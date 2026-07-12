use std::{
    collections::HashSet,
    fs,
    io::{self, Cursor},
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, OnceLock},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ToolError>;

const MAX_NUCLEI_ARCHIVE_BYTES: u64 = 350 * 1024 * 1024;
static MANAGED_INSTALL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("managed tool not found: {0}")]
    NotFound(String),

    #[error("managed tool operation is not implemented yet: {0}")]
    NotImplemented(&'static str),

    #[error("managed tool descriptor is invalid: {0}")]
    InvalidDescriptor(String),

    #[error("managed tool operation failed: {0}")]
    Operation(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedToolDescriptor {
    pub id: String,
    pub display_name: String,
    pub source: ToolSource,
    pub install_strategy: InstallStrategy,
    pub risk: ToolRisk,
    pub category: ToolCategory,
    pub capabilities: Vec<ToolCapability>,
    pub target_kinds: Vec<ToolTargetKind>,
    pub interactions: Vec<ToolInteraction>,
    pub scope_requirement: ToolScopeRequirement,
    pub default_enabled: bool,
    pub notes: String,
    pub update: ToolUpdateInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSource {
    ProjectDiscovery,
    Trippy,
    NextTrace,
    Globalping,
    SonarNwork,
    NmapOrg,
    LocalSystem,
    Custom(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallStrategy {
    AutoDownload,
    DetectOnly,
    ApiOnly,
    SystemInstaller,
    ManagedDownload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolTargetKind {
    Host,
    IpAddress,
    Url,
    Domain,
    NetworkRange,
    CurrentPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolInteraction {
    Preview,
    RunInApp,
    OpenInCli,
    Stop,
    StructuredOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolScopeRequirement {
    None,
    ActiveTarget,
    IntrusiveTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolRisk {
    Passive,
    SafeRemoteVantage,
    ActiveScanner,
    IntrusiveScanner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    PathDiagnostics,
    Dns,
    Web,
    PortDiscovery,
    VulnScanning,
    RemoteVantage,
    LocalInspection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCapability {
    Ping,
    Trace,
    Mtr,
    DnsLookup,
    HttpProbe,
    TlsProbe,
    PortScan,
    SubdomainDiscovery,
    TemplateScan,
    RemoteMeasurement,
    LocalListenerInventory,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolUpdateInfo {
    pub source_label: String,
    pub source_url: String,
    pub latest_url: String,
    pub update_supported: bool,
    pub update_note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolUpdatePlan {
    pub tool_id: String,
    pub display_name: String,
    pub source_label: String,
    pub source_url: String,
    pub latest_url: String,
    pub update_supported: bool,
    pub update_note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolState {
    pub descriptor: ManagedToolDescriptor,
    pub installed_path: Option<PathBuf>,
    pub installed_version: Option<String>,
    pub latest_version: Option<String>,
    pub healthy: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolRuntimeStatus {
    pub tool_id: String,
    pub available: bool,
    pub executable: Option<PathBuf>,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolLifecyclePlan {
    pub tool_id: String,
    pub install_strategy: InstallStrategy,
    pub installed: bool,
    pub install_supported: bool,
    pub update_supported: bool,
    pub managed: bool,
    pub action_url: Option<String>,
    pub note: String,
}

#[async_trait]
pub trait ManagedTool: Send + Sync {
    fn descriptor(&self) -> ManagedToolDescriptor;
    async fn detect(&self) -> Result<ToolState>;
    async fn install(&self) -> Result<ToolState>;
    async fn update(&self) -> Result<ToolState>;
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ToolCatalog {
    pub tools: Vec<ManagedToolDescriptor>,
}

impl ToolCatalog {
    pub fn runtime_status(&self, tool_id: &str) -> Result<ToolRuntimeStatus> {
        if !self.tools.iter().any(|tool| tool.id == tool_id) {
            return Err(ToolError::NotFound(tool_id.to_string()));
        }

        let candidates: Vec<PathBuf> = match tool_id {
            "nmap" => scanner_runtime_candidates("nmap"),
            "nuclei" => scanner_runtime_candidates("nuclei"),
            _ => {
                return Ok(ToolRuntimeStatus {
                    tool_id: tool_id.to_string(),
                    available: false,
                    executable: None,
                    version: None,
                    error: Some("runtime detection is not implemented for this tool".into()),
                });
            }
        };

        let version_args: &[&str] = if tool_id == "nmap" {
            &["--version"]
        } else {
            &["-version"]
        };
        let mut errors = Vec::new();

        for candidate in candidates {
            if candidate.is_absolute() && !candidate.is_file() {
                continue;
            }

            match Command::new(&candidate).args(version_args).output() {
                Ok(output) => {
                    let combined = format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    let version = combined
                        .lines()
                        .map(str::trim)
                        .find(|line| !line.is_empty())
                        .map(str::to_string);
                    if output.status.success() {
                        return Ok(ToolRuntimeStatus {
                            tool_id: tool_id.to_string(),
                            available: true,
                            executable: Some(candidate),
                            version,
                            error: None,
                        });
                    }
                    errors.push(format!(
                        "{} version command exited with {}",
                        candidate.display(),
                        output.status
                    ));
                }
                Err(err) => errors.push(err.to_string()),
            }
        }

        Ok(ToolRuntimeStatus {
            tool_id: tool_id.to_string(),
            available: false,
            executable: None,
            version: None,
            error: Some(if errors.is_empty() {
                format!("{tool_id} was not found")
            } else {
                errors.join("; ")
            }),
        })
    }

    pub fn phase_zero_defaults() -> Self {
        let catalog = Self {
            tools: vec![
                descriptor(
                    "trippy",
                    "Trippy",
                    ToolSource::Trippy,
                    InstallStrategy::AutoDownload,
                    ToolRisk::ActiveScanner,
                    ToolCategory::PathDiagnostics,
                    &[ToolCapability::Trace, ToolCapability::Mtr],
                    true,
                    "Advanced trace/MTR view for packet loss, latency, and hop behavior.",
                    github_update(
                        "fujiapple852/trippy",
                        true,
                        "Auto-download can use the latest GitHub release when the managed tool runtime is enabled.",
                    ),
                ),
                descriptor(
                    "nexttrace",
                    "NextTrace",
                    ToolSource::NextTrace,
                    InstallStrategy::AutoDownload,
                    ToolRisk::ActiveScanner,
                    ToolCategory::PathDiagnostics,
                    &[ToolCapability::Trace],
                    true,
                    "Trace enrichment with ASN and geographic context when available.",
                    github_update(
                        "nxtrace/NTrace-core",
                        true,
                        "Auto-download can use the latest GitHub release when the managed tool runtime is enabled.",
                    ),
                ),
                descriptor(
                    "globalping",
                    "Globalping API",
                    ToolSource::Globalping,
                    InstallStrategy::ApiOnly,
                    ToolRisk::SafeRemoteVantage,
                    ToolCategory::RemoteVantage,
                    &[
                        ToolCapability::Ping,
                        ToolCapability::Trace,
                        ToolCapability::DnsLookup,
                        ToolCapability::HttpProbe,
                        ToolCapability::RemoteMeasurement,
                    ],
                    false,
                    "Remote public probes for ping, trace, DNS, MTR, and HTTP; not used for public port checks.",
                    ToolUpdateInfo {
                        source_label: "Globalping API".into(),
                        source_url: "https://www.jsdelivr.com/globalping".into(),
                        latest_url: "https://www.jsdelivr.com/globalping".into(),
                        update_supported: false,
                        update_note: "API-only provider; there is no local binary to update.".into(),
                    },
                ),
                descriptor(
                    "sonarnwork-remote-scan",
                    "SonarNwork remote scan",
                    ToolSource::SonarNwork,
                    InstallStrategy::ApiOnly,
                    ToolRisk::ActiveScanner,
                    ToolCategory::RemoteVantage,
                    &[ToolCapability::RemoteMeasurement, ToolCapability::PortScan],
                    false,
                    "Token handoff for explicitly scoped public service checks.",
                    ToolUpdateInfo {
                        source_label: "SonarNwork remote-scan".into(),
                        source_url: "sonarnwork://remote-scan".into(),
                        latest_url: "sonarnwork://remote-scan".into(),
                        update_supported: false,
                        update_note: "API-only provider; updates happen on the remote service side.".into(),
                    },
                ),
                descriptor(
                    "httpx",
                    "httpx",
                    ToolSource::ProjectDiscovery,
                    InstallStrategy::AutoDownload,
                    ToolRisk::ActiveScanner,
                    ToolCategory::Web,
                    &[ToolCapability::HttpProbe, ToolCapability::TlsProbe],
                    false,
                    "Managed web probing behind explicit target scope.",
                    github_update(
                        "projectdiscovery/httpx",
                        true,
                        "Auto-download can use the latest ProjectDiscovery GitHub release.",
                    ),
                ),
                descriptor(
                    "dnsx",
                    "dnsx",
                    ToolSource::ProjectDiscovery,
                    InstallStrategy::AutoDownload,
                    ToolRisk::Passive,
                    ToolCategory::Dns,
                    &[ToolCapability::DnsLookup],
                    false,
                    "Bulk DNS resolution for scoped lists.",
                    github_update(
                        "projectdiscovery/dnsx",
                        true,
                        "Auto-download can use the latest ProjectDiscovery GitHub release.",
                    ),
                ),
                descriptor(
                    "subfinder",
                    "subfinder",
                    ToolSource::ProjectDiscovery,
                    InstallStrategy::AutoDownload,
                    ToolRisk::Passive,
                    ToolCategory::Dns,
                    &[ToolCapability::SubdomainDiscovery],
                    false,
                    "Passive subdomain discovery for domains the user is allowed to assess.",
                    github_update(
                        "projectdiscovery/subfinder",
                        true,
                        "Auto-download can use the latest ProjectDiscovery GitHub release.",
                    ),
                ),
                descriptor(
                    "naabu",
                    "naabu",
                    ToolSource::ProjectDiscovery,
                    InstallStrategy::AutoDownload,
                    ToolRisk::ActiveScanner,
                    ToolCategory::PortDiscovery,
                    &[ToolCapability::PortScan],
                    false,
                    "Fast active port discovery, only behind explicit scan scope.",
                    github_update(
                        "projectdiscovery/naabu",
                        true,
                        "Auto-download can use the latest ProjectDiscovery GitHub release.",
                    ),
                ),
                descriptor(
                    "nuclei",
                    "nuclei",
                    ToolSource::ProjectDiscovery,
                    InstallStrategy::ManagedDownload,
                    ToolRisk::IntrusiveScanner,
                    ToolCategory::VulnScanning,
                    &[ToolCapability::TemplateScan],
                    false,
                    "Template scanning is never beginner-default and requires explicit scope.",
                    github_update(
                        "projectdiscovery/nuclei",
                        true,
                        "Update from ProjectDiscovery GitHub releases; running templates still requires explicit scope.",
                    ),
                ),
                descriptor(
                    "nmap",
                    "nmap",
                    ToolSource::NmapOrg,
                    InstallStrategy::SystemInstaller,
                    ToolRisk::ActiveScanner,
                    ToolCategory::PortDiscovery,
                    &[ToolCapability::PortScan],
                    false,
                    "SonarNwork scanner package; the app manages detection and launch, while the official Nmap installer may request Npcap or system permission.",
                    ToolUpdateInfo {
                        source_label: "Nmap.org".into(),
                        source_url: "https://nmap.org/download.html".into(),
                        latest_url: "https://nmap.org/download.html".into(),
                        update_supported: true,
                        update_note: "Install or update from SonarNwork using the official Nmap installer, then refresh package detection.".into(),
                    },
                ),
            ],
        };
        debug_assert!(catalog.validate().is_ok());
        catalog
    }

    pub fn validate(&self) -> Result<()> {
        let mut ids = HashSet::new();
        for tool in &self.tools {
            if tool.id.trim().is_empty() || tool.capabilities.is_empty() {
                return Err(ToolError::InvalidDescriptor(tool.id.clone()));
            }
            if !ids.insert(tool.id.as_str()) {
                return Err(ToolError::InvalidDescriptor(format!(
                    "duplicate tool id: {}",
                    tool.id
                )));
            }
            if matches!(tool.risk, ToolRisk::IntrusiveScanner)
                && tool.scope_requirement != ToolScopeRequirement::IntrusiveTarget
            {
                return Err(ToolError::InvalidDescriptor(format!(
                    "{} must require intrusive target scope",
                    tool.id
                )));
            }
            if tool.interactions.contains(&ToolInteraction::RunInApp)
                && !tool.interactions.contains(&ToolInteraction::Preview)
            {
                return Err(ToolError::InvalidDescriptor(format!(
                    "{} cannot run without command preview support",
                    tool.id
                )));
            }
        }
        Ok(())
    }

    pub fn lifecycle_plan(&self, tool_id: &str) -> Result<ToolLifecyclePlan> {
        let descriptor = self
            .tools
            .iter()
            .find(|tool| tool.id == tool_id)
            .ok_or_else(|| ToolError::NotFound(tool_id.to_string()))?;
        let installed = self.runtime_status(tool_id)?.available;
        let (install_supported, managed, action_url, note) = match descriptor.install_strategy {
            InstallStrategy::SystemInstaller => (
                true,
                true,
                Some(descriptor.update.source_url.clone()),
                "SonarNwork manages this scanner package through the official installer; Nmap may require Npcap or system permission."
                    .into(),
            ),
            InstallStrategy::ManagedDownload => (
                cfg!(target_os = "windows"),
                true,
                None,
                "Install or update explicitly into per-user SonarNwork application data.".into(),
            ),
            _ => (false, false, None, descriptor.notes.clone()),
        };
        Ok(ToolLifecyclePlan {
            tool_id: tool_id.into(),
            install_strategy: descriptor.install_strategy.clone(),
            installed,
            install_supported,
            update_supported: descriptor.update.update_supported,
            managed,
            action_url,
            note,
        })
    }

    pub fn install_managed(&self, tool_id: &str) -> Result<ToolRuntimeStatus> {
        let descriptor = self
            .tools
            .iter()
            .find(|tool| tool.id == tool_id)
            .ok_or_else(|| ToolError::NotFound(tool_id.to_string()))?;
        if !matches!(
            descriptor.install_strategy,
            InstallStrategy::ManagedDownload
        ) {
            return Err(ToolError::Operation(format!(
                "{tool_id} uses a managed installer handoff, not direct binary download"
            )));
        }
        if tool_id != "nuclei" || !cfg!(target_os = "windows") {
            return Err(ToolError::Operation(format!(
                "managed installation for {tool_id} is not supported on this platform"
            )));
        }
        install_latest_nuclei()?;
        self.runtime_status(tool_id)
    }

    pub fn update_plan(&self, tool_id: &str) -> Result<ToolUpdatePlan> {
        let descriptor = self
            .tools
            .iter()
            .find(|tool| tool.id == tool_id)
            .ok_or_else(|| ToolError::NotFound(tool_id.to_string()))?;

        Ok(ToolUpdatePlan {
            tool_id: descriptor.id.clone(),
            display_name: descriptor.display_name.clone(),
            source_label: descriptor.update.source_label.clone(),
            source_url: descriptor.update.source_url.clone(),
            latest_url: descriptor.update.latest_url.clone(),
            update_supported: descriptor.update.update_supported,
            update_note: descriptor.update.update_note.clone(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn descriptor(
    id: &str,
    display_name: &str,
    source: ToolSource,
    install_strategy: InstallStrategy,
    risk: ToolRisk,
    category: ToolCategory,
    capabilities: &[ToolCapability],
    default_enabled: bool,
    notes: &str,
    update: ToolUpdateInfo,
) -> ManagedToolDescriptor {
    let (target_kinds, interactions, scope_requirement) = match id {
        "nmap" => (
            vec![
                ToolTargetKind::Host,
                ToolTargetKind::IpAddress,
                ToolTargetKind::NetworkRange,
            ],
            scanner_interactions(),
            ToolScopeRequirement::ActiveTarget,
        ),
        "nuclei" => (
            vec![ToolTargetKind::Url],
            scanner_interactions(),
            ToolScopeRequirement::IntrusiveTarget,
        ),
        _ => (Vec::new(), Vec::new(), ToolScopeRequirement::None),
    };
    ManagedToolDescriptor {
        id: id.into(),
        display_name: display_name.into(),
        source,
        install_strategy,
        risk,
        category,
        capabilities: capabilities.to_vec(),
        target_kinds,
        interactions,
        scope_requirement,
        default_enabled,
        notes: notes.into(),
        update,
    }
}

fn scanner_interactions() -> Vec<ToolInteraction> {
    vec![
        ToolInteraction::Preview,
        ToolInteraction::RunInApp,
        ToolInteraction::OpenInCli,
        ToolInteraction::Stop,
        ToolInteraction::StructuredOutput,
    ]
}

fn managed_tool_root() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|path| path.join("SonarNwork").join("tools"))
}

fn managed_tool_executable(tool_id: &str) -> Option<PathBuf> {
    managed_tool_root().map(|root| root.join(tool_id).join(format!("{tool_id}.exe")))
}

fn scanner_runtime_candidates(tool_id: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    push_tool_env_candidates(&mut paths, tool_id);
    if cfg!(target_os = "windows") {
        push_managed_and_common_windows_candidates(&mut paths, tool_id);
        match tool_id {
            "nmap" => {
                push_unique(&mut paths, PathBuf::from(r"C:\Program Files\Nmap\nmap.exe"));
                push_unique(
                    &mut paths,
                    PathBuf::from(r"C:\Program Files (x86)\Nmap\nmap.exe"),
                );
            }
            "nuclei" => {
                push_unique(
                    &mut paths,
                    PathBuf::from(r"C:\ProgramData\chocolatey\bin\nuclei.exe"),
                );
                if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
                    push_unique(
                        &mut paths,
                        home.join("scoop").join("shims").join("nuclei.exe"),
                    );
                }
            }
            _ => {}
        }
        push_unique(&mut paths, PathBuf::from(format!("{tool_id}.exe")));
    } else {
        push_unique(&mut paths, PathBuf::from(tool_id));
    }
    paths
}

fn push_tool_env_candidates(paths: &mut Vec<PathBuf>, tool_id: &str) {
    let upper = tool_id.to_ascii_uppercase();
    for key in [
        format!("SONARNWORK_{}_PATH", upper),
        format!("{}_PATH", upper),
    ] {
        if let Some(path) = std::env::var_os(key) {
            let path = PathBuf::from(path);
            push_unique(paths, path.clone());
            if cfg!(target_os = "windows") {
                push_unique(paths, path.join(format!("{tool_id}.exe")));
            } else {
                push_unique(paths, path.join(tool_id));
            }
        }
    }
}

fn push_managed_and_common_windows_candidates(paths: &mut Vec<PathBuf>, tool_id: &str) {
    if let Some(path) = managed_tool_executable(tool_id) {
        push_unique(paths, path);
    }
    let common_tool_dir = PathBuf::from(format!(r"C:\tools\{tool_id}"));
    push_windows_tool_dir_candidates(paths, tool_id, &common_tool_dir);
    push_unique(paths, PathBuf::from(format!(r"C:\tools\{tool_id}.exe")));
    push_unique(paths, common_tool_dir);
}

fn push_windows_tool_dir_candidates(paths: &mut Vec<PathBuf>, tool_id: &str, root: &Path) {
    let executable = format!("{tool_id}.exe");
    push_unique(paths, root.join(&executable));
    push_unique(paths, root.join("bin").join(&executable));
    push_unique(paths, root.join("current").join(&executable));
    push_unique(paths, root.join("latest").join(&executable));

    let Ok(entries) = fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            push_unique(paths, path.join(&executable));
            push_unique(paths, path.join("bin").join(&executable));
        }
    }
}

fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

#[derive(Deserialize)]
struct GithubRelease {
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

fn install_latest_nuclei() -> Result<()> {
    let _guard = MANAGED_INSTALL_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| ToolError::Operation("managed installer lock is poisoned".into()))?;
    let client = reqwest::blocking::Client::builder()
        .user_agent("SonarNwork/0.1")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|err| ToolError::Operation(err.to_string()))?;
    let release: GithubRelease = client
        .get("https://api.github.com/repos/projectdiscovery/nuclei/releases/latest")
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|err| ToolError::Operation(err.to_string()))?
        .json()
        .map_err(|err| ToolError::Operation(err.to_string()))?;
    let asset = release
        .assets
        .into_iter()
        .find(|asset| asset.name.ends_with("_windows_amd64.zip"))
        .ok_or_else(|| {
            ToolError::Operation("official Windows amd64 Nuclei asset was not found".into())
        })?;
    if !asset
        .browser_download_url
        .starts_with("https://github.com/projectdiscovery/nuclei/releases/download/")
    {
        return Err(ToolError::Operation(
            "release asset URL is not allow-listed".into(),
        ));
    }
    let bytes = client
        .get(asset.browser_download_url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|err| ToolError::Operation(err.to_string()))?
        .bytes()
        .map_err(|err| ToolError::Operation(err.to_string()))?;
    let destination = managed_tool_executable("nuclei")
        .ok_or_else(|| ToolError::Operation("LOCALAPPDATA is unavailable".into()))?;
    let parent = destination
        .parent()
        .ok_or_else(|| ToolError::Operation("invalid managed tool directory".into()))?;
    fs::create_dir_all(parent).map_err(|err| ToolError::Operation(err.to_string()))?;
    let staged = parent.join("nuclei.exe.pending");
    if let Err(err) = extract_single_executable(&bytes, &staged) {
        let _ = fs::remove_file(&staged);
        return Err(err);
    }
    let version = Command::new(&staged)
        .arg("-version")
        .output()
        .map_err(|err| ToolError::Operation(err.to_string()))?;
    if !version.status.success() {
        let _ = fs::remove_file(&staged);
        return Err(ToolError::Operation(
            "downloaded Nuclei failed its version check".into(),
        ));
    }
    let backup = parent.join("nuclei.exe.previous");
    let had_previous = destination.exists();
    if had_previous {
        let _ = fs::remove_file(&backup);
        fs::rename(&destination, &backup).map_err(|err| ToolError::Operation(err.to_string()))?;
    }
    if let Err(err) = fs::rename(&staged, &destination) {
        if had_previous {
            let _ = fs::rename(&backup, &destination);
        }
        let _ = fs::remove_file(&staged);
        return Err(ToolError::Operation(err.to_string()));
    }
    let _ = fs::remove_file(backup);
    Ok(())
}

fn extract_single_executable(bytes: &[u8], destination: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|err| ToolError::Operation(err.to_string()))?;
    let mut entry = archive
        .by_name("nuclei.exe")
        .map_err(|_| ToolError::Operation("Nuclei archive does not contain nuclei.exe".into()))?;
    if entry.size() == 0 || entry.size() > MAX_NUCLEI_ARCHIVE_BYTES {
        return Err(ToolError::Operation(
            "Nuclei executable size is invalid".into(),
        ));
    }
    let mut file =
        fs::File::create(destination).map_err(|err| ToolError::Operation(err.to_string()))?;
    io::copy(&mut entry, &mut file).map_err(|err| ToolError::Operation(err.to_string()))?;
    Ok(())
}

fn github_update(repo: &str, update_supported: bool, update_note: &str) -> ToolUpdateInfo {
    ToolUpdateInfo {
        source_label: format!("GitHub: {repo}"),
        source_url: format!("https://github.com/{repo}"),
        latest_url: format!("https://github.com/{repo}/releases/latest"),
        update_supported,
        update_note: update_note.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;

    #[test]
    fn nmap_uses_managed_installer_without_being_bundled() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let nmap = catalog.tools.iter().find(|tool| tool.id == "nmap").unwrap();

        assert!(matches!(
            nmap.install_strategy,
            InstallStrategy::SystemInstaller
        ));
        assert!(!nmap.default_enabled);
        assert!(nmap.update.update_supported);
        assert!(nmap.notes.contains("SonarNwork scanner package"));
        assert_eq!(nmap.scope_requirement, ToolScopeRequirement::ActiveTarget);
        assert!(nmap.interactions.contains(&ToolInteraction::OpenInCli));
    }

    #[test]
    fn nuclei_updates_from_projectdiscovery_github() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let nuclei = catalog
            .tools
            .iter()
            .find(|tool| tool.id == "nuclei")
            .unwrap();

        assert!(nuclei.update.update_supported);
        assert!(matches!(
            nuclei.install_strategy,
            InstallStrategy::ManagedDownload
        ));
        assert_eq!(nuclei.target_kinds, [ToolTargetKind::Url]);
        assert_eq!(
            nuclei.scope_requirement,
            ToolScopeRequirement::IntrusiveTarget
        );
        assert_eq!(
            nuclei.update.latest_url,
            "https://github.com/projectdiscovery/nuclei/releases/latest"
        );
    }

    #[test]
    fn update_plan_returns_tool_policy() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let plan = catalog.update_plan("nuclei").unwrap();

        assert_eq!(plan.tool_id, "nuclei");
        assert!(plan.update_supported);
        assert!(plan.source_label.contains("projectdiscovery/nuclei"));
    }

    #[test]
    fn intrusive_tools_are_not_default_enabled() {
        let catalog = ToolCatalog::phase_zero_defaults();

        assert!(catalog
            .tools
            .iter()
            .filter(|tool| matches!(tool.risk, ToolRisk::IntrusiveScanner))
            .all(|tool| !tool.default_enabled));
    }

    #[test]
    fn globalping_is_not_a_public_port_checker() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let globalping = catalog
            .tools
            .iter()
            .find(|tool| tool.id == "globalping")
            .unwrap();

        assert!(matches!(globalping.risk, ToolRisk::SafeRemoteVantage));
        assert!(!globalping.capabilities.contains(&ToolCapability::PortScan));
    }

    #[test]
    fn runtime_status_rejects_unknown_tool() {
        let catalog = ToolCatalog::phase_zero_defaults();
        assert!(matches!(
            catalog.runtime_status("not-a-tool"),
            Err(ToolError::NotFound(_))
        ));
    }

    #[test]
    fn metadata_only_tool_reports_detection_as_unimplemented() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let status = catalog.runtime_status("globalping").unwrap();

        assert!(!status.available);
        assert!(status.executable.is_none());
        assert!(status.error.unwrap().contains("not implemented"));
    }

    #[test]
    fn nuclei_detection_checks_common_windows_tool_dirs() {
        let candidates = scanner_runtime_candidates("nuclei");

        if cfg!(target_os = "windows") {
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from(r"C:\tools\nuclei\nuclei.exe")));
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from(r"C:\tools\nuclei\bin\nuclei.exe")));
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from(r"C:\tools\nuclei\current\nuclei.exe")));
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from(r"C:\tools\nuclei.exe")));
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from(r"C:\tools\nuclei")));
        } else {
            assert_eq!(candidates, [PathBuf::from("nuclei")]);
        }
    }

    #[test]
    fn windows_tool_dir_candidates_include_shallow_extracted_subdirs() {
        let root =
            std::env::temp_dir().join(format!("sonarnwork-tool-detect-{}", std::process::id()));
        let extracted = root.join("nuclei_3.8.0_windows_amd64");
        fs::create_dir_all(&extracted).unwrap();

        let mut candidates = Vec::new();
        push_windows_tool_dir_candidates(&mut candidates, "nuclei", &root);

        assert!(candidates.iter().any(|path| {
            path == &extracted.join("nuclei.exe")
                || path == &extracted.join("bin").join("nuclei.exe")
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_contract_is_valid() {
        ToolCatalog::phase_zero_defaults().validate().unwrap();
    }

    #[test]
    fn scanner_contracts_do_not_overlap_business_meaning() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let nmap = catalog.tools.iter().find(|tool| tool.id == "nmap").unwrap();
        let nuclei = catalog
            .tools
            .iter()
            .find(|tool| tool.id == "nuclei")
            .unwrap();

        assert!(nmap.capabilities.contains(&ToolCapability::PortScan));
        assert!(!nmap.capabilities.contains(&ToolCapability::TemplateScan));
        assert!(nuclei.capabilities.contains(&ToolCapability::TemplateScan));
        assert!(!nuclei.capabilities.contains(&ToolCapability::PortScan));
    }

    #[test]
    fn lifecycle_plan_presents_scanners_as_app_managed_packages() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let nmap = catalog.lifecycle_plan("nmap").unwrap();
        let nuclei = catalog.lifecycle_plan("nuclei").unwrap();

        assert!(nmap.managed);
        assert!(nmap
            .action_url
            .as_deref()
            .unwrap()
            .starts_with("https://nmap.org/"));
        assert!(nmap.note.contains("SonarNwork manages"));
        assert!(nuclei.managed);
        assert!(nuclei.action_url.is_none());
    }

    #[test]
    fn managed_nuclei_path_is_user_data_not_repository_tools() {
        if let Some(path) = managed_tool_executable("nuclei") {
            assert!(path.ends_with(Path::new("SonarNwork/tools/nuclei/nuclei.exe")));
            assert!(!path.to_string_lossy().contains(".tools"));
            assert!(!path.to_string_lossy().contains("CARGO_MANIFEST_DIR"));
        }
    }

    #[test]
    fn catalog_validation_rejects_duplicate_ids() {
        let mut catalog = ToolCatalog::phase_zero_defaults();
        catalog.tools.push(catalog.tools[0].clone());

        assert!(matches!(
            catalog.validate(),
            Err(ToolError::InvalidDescriptor(_))
        ));
    }

    #[test]
    fn managed_install_rejects_installer_handoff() {
        let error = ToolCatalog::phase_zero_defaults()
            .install_managed("nmap")
            .unwrap_err();

        assert!(error.to_string().contains("installer handoff"));
    }

    #[test]
    fn nuclei_archive_requires_exact_nonempty_executable() {
        let temp = std::env::temp_dir().join("sonarnwork-nuclei-archive-test.exe");
        assert!(extract_single_executable(b"not a zip", &temp).is_err());

        let mut empty_archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        empty_archive
            .start_file("nuclei.exe", zip::write::SimpleFileOptions::default())
            .unwrap();
        let empty_bytes = empty_archive.finish().unwrap().into_inner();
        assert!(extract_single_executable(&empty_bytes, &temp).is_err());

        let mut valid_archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        valid_archive
            .start_file("nuclei.exe", zip::write::SimpleFileOptions::default())
            .unwrap();
        valid_archive.write_all(b"MZ-test").unwrap();
        let valid_bytes = valid_archive.finish().unwrap().into_inner();
        extract_single_executable(&valid_bytes, &temp).unwrap();
        assert_eq!(fs::read(&temp).unwrap(), b"MZ-test");
        let _ = fs::remove_file(temp);
    }
}
