use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const STORE_FILE: &str = "operations.json";
const STORE_VERSION: u32 = 1;
const MAX_EVENTS: usize = 1_000;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

type EventSink = Arc<dyn Fn(&TimelineEvent) + Send + Sync>;

#[derive(Clone)]
pub struct OperationsService {
    inner: Arc<OperationsInner>,
}

struct OperationsInner {
    data_dir: PathBuf,
    gate: Mutex<()>,
    workers: Mutex<HashMap<String, Arc<AtomicBool>>>,
    event_sink: EventSink,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureRuntime {
    pub available: bool,
    pub tshark: Option<PathBuf>,
    pub wireshark: Option<PathBuf>,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureInterface {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureRequest {
    pub interface_id: String,
    pub duration_seconds: u64,
    pub packet_limit: u64,
    pub scope_confirmed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureResult {
    pub path: PathBuf,
    pub bytes: u64,
    pub duration_seconds: u64,
    pub packet_limit: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    pub ip: String,
    pub mac: Option<String>,
    pub state: String,
    pub interface: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InventorySnapshot {
    pub collected_at: u64,
    pub source: String,
    pub devices: Vec<DeviceRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorConfig {
    pub id: String,
    pub target: String,
    pub interval_seconds: u64,
    pub latency_alert_ms: u64,
    pub loss_alert_percent: u8,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartMonitorRequest {
    pub target: String,
    pub interval_seconds: u64,
    pub latency_alert_ms: u64,
    pub loss_alert_percent: u8,
    pub scope_confirmed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    pub id: String,
    pub created_at: u64,
    pub kind: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub target: Option<String>,
    pub metrics: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OperationsStore {
    version: u32,
    monitors: Vec<MonitorConfig>,
    events: Vec<TimelineEvent>,
}

impl Default for OperationsStore {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            monitors: Vec::new(),
            events: Vec::new(),
        }
    }
}

impl OperationsService {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self::with_event_sink(data_dir, |_| {})
    }

    pub fn with_event_sink(
        data_dir: impl Into<PathBuf>,
        event_sink: impl Fn(&TimelineEvent) + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(OperationsInner {
                data_dir: data_dir.into(),
                gate: Mutex::new(()),
                workers: Mutex::new(HashMap::new()),
                event_sink: Arc::new(event_sink),
            }),
        }
    }

    pub fn data_dir(&self) -> &Path {
        &self.inner.data_dir
    }

    pub fn capture_packets(&self, request: CaptureRequest) -> Result<CaptureResult, String> {
        validate_capture_request(&request)?;
        let runtime = capture_runtime_status();
        let tshark = runtime
            .tshark
            .filter(|_| runtime.available)
            .ok_or_else(|| {
                runtime
                    .error
                    .unwrap_or_else(|| "TShark is unavailable".into())
            })?;
        let capture_dir = self.capture_dir();
        fs::create_dir_all(&capture_dir).map_err(|error| error.to_string())?;
        let path = capture_dir.join(format!("capture-{}.pcapng", unique_id()));
        let status = Command::new(tshark)
            .args([
                "-i",
                &request.interface_id,
                "-a",
                &format!("duration:{}", request.duration_seconds),
                "-c",
                &request.packet_limit.to_string(),
                "-w",
            ])
            .arg(&path)
            .status()
            .map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(format!("TShark capture exited with {status}"));
        }
        let bytes = fs::metadata(&path).map(|value| value.len()).unwrap_or(0);
        self.append_event(TimelineEvent {
            id: unique_id(),
            created_at: now_secs(),
            kind: "capture".into(),
            severity: "info".into(),
            title: "Packet capture completed".into(),
            detail: path.display().to_string(),
            target: None,
            metrics: json!({
                "bytes": bytes,
                "durationSeconds": request.duration_seconds,
                "packetLimit": request.packet_limit
            }),
        })?;
        Ok(CaptureResult {
            path,
            bytes,
            duration_seconds: request.duration_seconds,
            packet_limit: request.packet_limit,
        })
    }

    pub fn open_capture_handoff(&self, path: PathBuf) -> Result<(), String> {
        let canonical = path.canonicalize().map_err(|error| error.to_string())?;
        let canonical_root = self
            .capture_dir()
            .canonicalize()
            .unwrap_or_else(|_| self.capture_dir());
        if !canonical.starts_with(&canonical_root)
            || canonical.extension().and_then(|value| value.to_str()) != Some("pcapng")
        {
            return Err("capture handoff is limited to SonarNwork pcapng files".into());
        }
        if let Some(wireshark) = find_program(
            "SONARNWORK_WIRESHARK_PATH",
            "wireshark",
            &wireshark_candidates(),
        ) {
            Command::new(wireshark)
                .arg(canonical)
                .spawn()
                .map_err(|error| error.to_string())?;
            return Ok(());
        }
        #[cfg(target_os = "windows")]
        {
            Command::new("explorer.exe")
                .arg("/select,")
                .arg(canonical)
                .spawn()
                .map_err(|error| error.to_string())?;
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        Err("Wireshark was not found; use the returned capture path for handoff".into())
    }

    pub fn collect_device_inventory(&self) -> Result<InventorySnapshot, String> {
        let (source, output) = if cfg!(target_os = "windows") {
            ("arp -a", Command::new("arp").arg("-a").output())
        } else {
            (
                "ip neigh show",
                Command::new("ip").args(["neigh", "show"]).output(),
            )
        };
        let output = output.map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let devices = if cfg!(target_os = "windows") {
            parse_windows_arp(&text)
        } else {
            parse_ip_neigh(&text)
        };
        let snapshot = InventorySnapshot {
            collected_at: now_secs(),
            source: source.into(),
            devices,
        };
        self.append_event(TimelineEvent {
            id: unique_id(),
            created_at: snapshot.collected_at,
            kind: "inventory".into(),
            severity: "info".into(),
            title: "Device inventory refreshed".into(),
            detail: format!("{} neighbor entries", snapshot.devices.len()),
            target: None,
            metrics: json!({ "deviceCount": snapshot.devices.len(), "source": source }),
        })?;
        Ok(snapshot)
    }

    pub fn start_monitor(&self, request: StartMonitorRequest) -> Result<MonitorConfig, String> {
        validate_monitor_request(&request)?;
        let config = MonitorConfig {
            id: unique_id(),
            target: request.target.trim().into(),
            interval_seconds: request.interval_seconds,
            latency_alert_ms: request.latency_alert_ms,
            loss_alert_percent: request.loss_alert_percent,
            enabled: true,
        };
        {
            let _guard = self.lock_store()?;
            let mut store = load_store(&self.store_path())?;
            store.monitors.push(config.clone());
            write_store(&self.store_path(), &store)?;
        }
        self.spawn_monitor(config.clone())?;
        Ok(config)
    }

    pub fn stop_monitor(&self, monitor_id: &str) -> Result<(), String> {
        if let Some(flag) = self
            .inner
            .workers
            .lock()
            .map_err(|_| "monitor registry is poisoned")?
            .remove(monitor_id)
        {
            flag.store(true, Ordering::Relaxed);
        }
        let _guard = self.lock_store()?;
        let mut store = load_store(&self.store_path())?;
        let monitor = store
            .monitors
            .iter_mut()
            .find(|item| item.id == monitor_id)
            .ok_or_else(|| "monitor was not found".to_string())?;
        monitor.enabled = false;
        write_store(&self.store_path(), &store)
    }

    pub fn list_monitors(&self) -> Result<Vec<MonitorConfig>, String> {
        let _guard = self.lock_store()?;
        Ok(load_store(&self.store_path())?.monitors)
    }

    pub fn list_timeline(&self) -> Result<Vec<TimelineEvent>, String> {
        let _guard = self.lock_store()?;
        let mut events = load_store(&self.store_path())?.events;
        events.reverse();
        Ok(events)
    }

    pub fn clear_timeline(&self) -> Result<(), String> {
        let _guard = self.lock_store()?;
        let mut store = load_store(&self.store_path())?;
        store.events.clear();
        write_store(&self.store_path(), &store)
    }

    pub fn resume_monitors(&self) -> Result<(), String> {
        let configs = {
            let _guard = self.lock_store()?;
            load_store(&self.store_path())?
                .monitors
                .into_iter()
                .filter(|item| item.enabled)
                .collect::<Vec<_>>()
        };
        for config in configs {
            self.spawn_monitor(config)?;
        }
        Ok(())
    }

    fn lock_store(&self) -> Result<std::sync::MutexGuard<'_, ()>, String> {
        self.inner
            .gate
            .lock()
            .map_err(|_| "operations store is poisoned".into())
    }

    fn store_path(&self) -> PathBuf {
        self.inner.data_dir.join(STORE_FILE)
    }

    fn capture_dir(&self) -> PathBuf {
        self.inner.data_dir.join("captures")
    }

    fn spawn_monitor(&self, config: MonitorConfig) -> Result<(), String> {
        if self
            .inner
            .workers
            .lock()
            .map_err(|_| "monitor registry is poisoned")?
            .contains_key(&config.id)
        {
            return Ok(());
        }
        let stop = Arc::new(AtomicBool::new(false));
        self.inner
            .workers
            .lock()
            .map_err(|_| "monitor registry is poisoned")?
            .insert(config.id.clone(), Arc::clone(&stop));
        let service = self.clone();
        thread::spawn(move || service.monitor_loop(config, stop));
        Ok(())
    }

    fn monitor_loop(&self, config: MonitorConfig, stop: Arc<AtomicBool>) {
        let mut last_up = None;
        while !stop.load(Ordering::Relaxed) {
            let started = Instant::now();
            let output = ping_once(&config.target);
            let latency_ms = started.elapsed().as_millis() as u64;
            let up = output.as_ref().is_ok_and(|status| *status);
            let loss_percent = if up { 0 } else { 100 };
            let status_changed = last_up.is_some_and(|previous| previous != up);
            let alert = !up
                || latency_ms >= config.latency_alert_ms
                || loss_percent >= config.loss_alert_percent
                || status_changed;
            let event = TimelineEvent {
                id: unique_id(),
                created_at: now_secs(),
                kind: if alert { "alert" } else { "monitor" }.into(),
                severity: if alert { "warning" } else { "info" }.into(),
                title: if status_changed {
                    format!("{} changed status", config.target)
                } else if alert {
                    format!("{} crossed a monitor threshold", config.target)
                } else {
                    format!("{} is reachable", config.target)
                },
                detail: output
                    .err()
                    .unwrap_or_else(|| format!("latency {latency_ms} ms, loss {loss_percent}%")),
                target: Some(config.target.clone()),
                metrics: json!({
                    "reachable": up,
                    "latencyMs": latency_ms,
                    "lossPercent": loss_percent,
                    "statusChanged": status_changed,
                }),
            };
            let _ = self.append_event(event);
            last_up = Some(up);
            for _ in 0..config.interval_seconds {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    fn append_event(&self, event: TimelineEvent) -> Result<(), String> {
        {
            let _guard = self.lock_store()?;
            let mut store = load_store(&self.store_path())?;
            store.events.push(event.clone());
            if store.events.len() > MAX_EVENTS {
                store.events.drain(..store.events.len() - MAX_EVENTS);
            }
            write_store(&self.store_path(), &store)?;
        }
        (self.inner.event_sink)(&event);
        Ok(())
    }
}

pub fn capture_runtime_status() -> CaptureRuntime {
    let tshark = find_program("SONARNWORK_TSHARK_PATH", "tshark", &tshark_candidates());
    let wireshark = find_program(
        "SONARNWORK_WIRESHARK_PATH",
        "wireshark",
        &wireshark_candidates(),
    );
    let Some(tshark_path) = tshark.clone() else {
        return CaptureRuntime {
            available: false,
            tshark: None,
            wireshark,
            version: None,
            error: Some(
                "TShark was not found; install Wireshark or set SONARNWORK_TSHARK_PATH".into(),
            ),
        };
    };
    match Command::new(&tshark_path).arg("--version").output() {
        Ok(output) if output.status.success() => CaptureRuntime {
            available: true,
            tshark: Some(tshark_path),
            wireshark,
            version: first_line(&output.stdout).or_else(|| first_line(&output.stderr)),
            error: None,
        },
        Ok(output) => CaptureRuntime {
            available: false,
            tshark: Some(tshark_path),
            wireshark,
            version: None,
            error: Some(format!(
                "TShark version check exited with {}",
                output.status
            )),
        },
        Err(error) => CaptureRuntime {
            available: false,
            tshark: Some(tshark_path),
            wireshark,
            version: None,
            error: Some(error.to_string()),
        },
    }
}

pub fn list_capture_interfaces() -> Result<Vec<CaptureInterface>, String> {
    let runtime = capture_runtime_status();
    let tshark = runtime
        .tshark
        .filter(|_| runtime.available)
        .ok_or_else(|| {
            runtime
                .error
                .unwrap_or_else(|| "TShark is unavailable".into())
        })?;
    let output = Command::new(tshark)
        .arg("-D")
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(parse_capture_interfaces(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

pub fn default_app_data_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("SONARNWORK_DATA_DIR") {
        return PathBuf::from(path);
    }
    #[cfg(target_os = "windows")]
    if let Some(path) = std::env::var_os("APPDATA") {
        return PathBuf::from(path).join("dev.sonarnwork.app");
    }
    #[cfg(target_os = "macos")]
    if let Some(path) = std::env::var_os("HOME") {
        return PathBuf::from(path)
            .join("Library")
            .join("Application Support")
            .join("dev.sonarnwork.app");
    }
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(path).join("dev.sonarnwork.app");
    }
    if let Some(path) = std::env::var_os("HOME") {
        return PathBuf::from(path)
            .join(".local")
            .join("share")
            .join("dev.sonarnwork.app");
    }
    PathBuf::from(".sonarnwork")
}

fn validate_capture_request(request: &CaptureRequest) -> Result<(), String> {
    if !request.scope_confirmed {
        return Err("confirm that packet capture is authorized on this interface".into());
    }
    if request.interface_id.trim().is_empty()
        || request.interface_id.trim_start().starts_with('-')
        || request.interface_id.len() > 512
        || request.interface_id.chars().any(char::is_control)
        || request.interface_id.chars().any(char::is_whitespace)
    {
        return Err("invalid capture interface".into());
    }
    if !(1..=300).contains(&request.duration_seconds) {
        return Err("capture duration must be between 1 and 300 seconds".into());
    }
    if !(1..=100_000).contains(&request.packet_limit) {
        return Err("packet limit must be between 1 and 100000".into());
    }
    Ok(())
}

fn validate_monitor_request(request: &StartMonitorRequest) -> Result<(), String> {
    if !request.scope_confirmed {
        return Err("confirm that you own or are authorized to monitor this target".into());
    }
    validate_target(&request.target)?;
    if !(15..=86_400).contains(&request.interval_seconds) {
        return Err("monitor interval must be between 15 and 86400 seconds".into());
    }
    if request.latency_alert_ms == 0 || request.latency_alert_ms > 120_000 {
        return Err("latency threshold must be between 1 and 120000 ms".into());
    }
    if request.loss_alert_percent > 100 {
        return Err("loss threshold must be between 0 and 100 percent".into());
    }
    Ok(())
}

fn validate_target(target: &str) -> Result<(), String> {
    let target = target.trim();
    if target.is_empty()
        || target.starts_with('-')
        || target.len() > 253
        || target.chars().any(char::is_whitespace)
        || target.chars().any(char::is_control)
    {
        return Err("invalid monitor target".into());
    }
    if target.parse::<IpAddr>().is_ok()
        || target.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        return Ok(());
    }
    Err("monitor target must be an IP address or DNS name".into())
}

fn ping_once(target: &str) -> Result<bool, String> {
    let output = if cfg!(target_os = "windows") {
        Command::new("ping")
            .args(["-n", "1", "-w", "3000", target])
            .output()
    } else {
        Command::new("ping")
            .args(["-c", "1", "-W", "3", target])
            .output()
    }
    .map_err(|error| error.to_string())?;
    Ok(output.status.success())
}

fn parse_capture_interfaces(output: &str) -> Vec<CaptureInterface> {
    output
        .lines()
        .filter_map(|line| {
            let (_, rest) = line.trim().split_once('.')?;
            let label = rest.trim();
            let id = label
                .split_once(" (")
                .map_or(label, |(value, _)| value)
                .trim();
            (!id.is_empty()).then(|| CaptureInterface {
                id: id.into(),
                label: label.into(),
            })
        })
        .collect()
}

fn parse_windows_arp(output: &str) -> Vec<DeviceRecord> {
    let mut interface = None;
    let mut devices = Vec::new();
    for line in output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("Interface:") {
            interface = value.split_whitespace().next().map(str::to_string);
            continue;
        }
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() >= 3 && parts[0].parse::<IpAddr>().is_ok() {
            devices.push(DeviceRecord {
                ip: parts[0].into(),
                mac: Some(parts[1].into()),
                state: parts[2..].join(" "),
                interface: interface.clone(),
            });
        }
    }
    devices
}

fn parse_ip_neigh(output: &str) -> Vec<DeviceRecord> {
    output
        .lines()
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            let ip = parts.first()?.parse::<IpAddr>().ok()?.to_string();
            let interface = parts
                .windows(2)
                .find(|pair| pair[0] == "dev")
                .map(|pair| pair[1].to_string());
            let mac = parts
                .windows(2)
                .find(|pair| pair[0] == "lladdr")
                .map(|pair| pair[1].to_string());
            Some(DeviceRecord {
                ip,
                mac,
                state: parts.last().unwrap_or(&"unknown").to_string(),
                interface,
            })
        })
        .collect()
}

fn find_program(env_key: &str, name: &str, extra: &[PathBuf]) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(value) = std::env::var_os(env_key) {
        let value = PathBuf::from(value);
        candidates.push(value.clone());
        candidates.push(value.join(executable_name(name)));
    }
    candidates.extend_from_slice(extra);
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|dir| dir.join(executable_name(name))));
    }
    candidates.into_iter().find(|path| path.is_file())
}

fn executable_name(name: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{name}.exe")
    } else {
        name.into()
    }
}

fn tshark_candidates() -> Vec<PathBuf> {
    if cfg!(target_os = "windows") {
        vec![
            PathBuf::from(r"C:\Program Files\Wireshark\tshark.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
        ]
    } else {
        Vec::new()
    }
}

fn wireshark_candidates() -> Vec<PathBuf> {
    if cfg!(target_os = "windows") {
        vec![
            PathBuf::from(r"C:\Program Files\Wireshark\Wireshark.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Wireshark\Wireshark.exe"),
        ]
    } else {
        Vec::new()
    }
}

fn first_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

fn load_store(path: &Path) -> Result<OperationsStore, String> {
    if !path.is_file() {
        return Ok(OperationsStore::default());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid operations store: {error}"))
}

fn write_store(path: &Path, store: &OperationsStore) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let temporary = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(store).map_err(|error| error.to_string())?;
    fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    if path.exists() {
        fs::remove_file(path).map_err(|error| error.to_string())?;
    }
    fs::rename(temporary, path).map_err(|error| error.to_string())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unique_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}-{sequence:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tshark_interfaces_without_shell_tokens() {
        let parsed = parse_capture_interfaces(
            "1. \\Device\\NPF_{ABC} (Ethernet)\n2. rpcap://remote/interface (Remote)",
        );
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, r"\Device\NPF_{ABC}");
    }

    #[test]
    fn validates_bounded_capture_contract() {
        let mut request = CaptureRequest {
            interface_id: "1".into(),
            duration_seconds: 15,
            packet_limit: 5_000,
            scope_confirmed: true,
        };
        assert!(validate_capture_request(&request).is_ok());
        request.interface_id = "-i".into();
        assert!(validate_capture_request(&request).is_err());
    }

    #[test]
    fn monitor_target_rejects_argument_injection() {
        assert!(validate_target("example.com").is_ok());
        assert!(validate_target("--help").is_err());
        assert!(validate_target("example.com extra").is_err());
    }
}
