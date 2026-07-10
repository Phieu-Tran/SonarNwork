use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use serde::Serialize;
use sonar_core::{
    ActionClass, AppCore, AppInfo, CommandInvocation, Entity, PivotGraph, ProbeDescriptor,
    ProbeOutput, ProbeTarget, RemoteMeasurementKind, RemoteVantagePlan, RemoteVantageProvider,
    ResultInterpretation, WorkflowDescriptor,
};
use sonar_tools::{ToolCatalog, ToolUpdatePlan};
use tauri::Emitter;

#[derive(Default)]
struct LiveProcesses {
    processes: Arc<Mutex<HashMap<String, Arc<Mutex<Child>>>>>,
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppCore::default().app_info()
}

#[tauri::command]
fn parse_entity(input: String) -> Result<Entity, String> {
    AppCore::default()
        .parse_entity(&input)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn all_probes() -> Vec<ProbeDescriptor> {
    AppCore::default().all_probes()
}

#[tauri::command]
fn workflows() -> Vec<WorkflowDescriptor> {
    AppCore::default().workflows()
}

#[tauri::command]
fn tools_catalog() -> ToolCatalog {
    ToolCatalog::phase_zero_defaults()
}

#[tauri::command]
fn tool_update_plan(tool_id: String) -> Result<ToolUpdatePlan, String> {
    ToolCatalog::phase_zero_defaults()
        .update_plan(&tool_id)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn remote_vantage_plan(
    provider: RemoteVantageProvider,
    measurement: RemoteMeasurementKind,
    target: ProbeTarget,
) -> RemoteVantagePlan {
    AppCore::default().remote_vantage_plan(provider, measurement, target)
}

#[tauri::command]
fn available_probes(input: String) -> Result<Vec<ProbeDescriptor>, String> {
    let core = AppCore::default();
    let entity = core.parse_entity(&input).map_err(|err| err.to_string())?;

    Ok(core.available_probes(&entity))
}

#[tauri::command]
fn available_probes_for_target(target: ProbeTarget) -> Result<Vec<ProbeDescriptor>, String> {
    AppCore::default()
        .available_probes_for_target(&target)
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn run_probe(probe_id: String, target: ProbeTarget) -> Result<ProbeRunView, String> {
    let core = AppCore::default();
    let (descriptor, output, graph) = core
        .run_probe_target(&probe_id, &target)
        .await
        .map_err(|err| err.to_string())?;
    let interpretation = core.interpret_result(&descriptor, &output);

    Ok(ProbeRunView {
        descriptor,
        output,
        graph,
        interpretation,
    })
}

#[tauri::command]
fn probe_command(probe_id: String, target: ProbeTarget) -> Result<CommandPreview, String> {
    let core = AppCore::default();
    let invocation = core
        .command_invocation_for_target(&probe_id, &target)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("probe `{probe_id}` does not expose a terminal command"))?;

    Ok(CommandPreview::from_invocation(invocation))
}

#[tauri::command]
fn open_probe_terminal(
    probe_id: String,
    target: ProbeTarget,
    shell: Option<String>,
    command_override: Option<String>,
) -> Result<(), String> {
    let core = AppCore::default();
    let fallback = core
        .command_invocation_for_target(&probe_id, &target)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("probe `{probe_id}` does not expose a terminal command"))?;
    let invocation = invocation_with_override(&core, &target, fallback, command_override)?;

    open_terminal(invocation, shell.unwrap_or_else(|| "powershell".into()))
}

#[tauri::command]
async fn run_probe_live(
    app: tauri::AppHandle,
    live_processes: tauri::State<'_, LiveProcesses>,
    run_id: String,
    probe_id: String,
    target: ProbeTarget,
    command_override: Option<String>,
) -> Result<ProbeLiveSummary, String> {
    let core = AppCore::default();
    let fallback = core
        .command_invocation_for_target(&probe_id, &target)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("probe `{probe_id}` does not expose a live command"))?;
    let invocation = invocation_with_override(&core, &target, fallback, command_override)?;
    let processes = Arc::clone(&live_processes.processes);

    tauri::async_runtime::spawn_blocking(move || {
        run_live_command(app, run_id, invocation, processes)
    })
    .await
    .map_err(|err| err.to_string())?
}

#[tauri::command]
fn cancel_probe_live(
    live_processes: tauri::State<'_, LiveProcesses>,
    run_id: String,
) -> Result<bool, String> {
    let child = live_processes
        .processes
        .lock()
        .map_err(|_| "live process registry is poisoned".to_string())?
        .get(&run_id)
        .cloned();

    let Some(child) = child else {
        return Ok(false);
    };

    let mut child = child
        .lock()
        .map_err(|_| "live process handle is poisoned".to_string())?;

    if child.try_wait().map_err(|err| err.to_string())?.is_some() {
        return Ok(false);
    }

    child.kill().map_err(|err| err.to_string())?;
    Ok(true)
}

#[derive(Serialize)]
struct ProbeRunView {
    descriptor: ProbeDescriptor,
    output: ProbeOutput,
    graph: PivotGraph,
    interpretation: ResultInterpretation,
}

#[derive(Serialize)]
struct CommandPreview {
    program: String,
    args: Vec<String>,
    display: String,
    powershell: String,
    cmd: String,
}

impl CommandPreview {
    fn from_invocation(invocation: CommandInvocation) -> Self {
        Self {
            display: invocation.display(),
            powershell: powershell_line(&invocation),
            cmd: cmd_line(&invocation),
            program: invocation.program,
            args: invocation.args,
        }
    }
}

#[derive(Clone, Serialize)]
struct ProbeLiveEvent {
    run_id: String,
    kind: &'static str,
    line: Option<String>,
    command: Option<String>,
    exit_code: Option<i32>,
    done: bool,
}

#[derive(Serialize)]
struct ProbeLiveSummary {
    command: String,
    exit_code: Option<i32>,
    stdout: Vec<String>,
    stderr: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkSummary {
    egress_ip: Option<String>,
    dns_servers: Vec<String>,
    observed_dns: Vec<String>,
    error: Option<String>,
}

#[tauri::command]
fn network_summary() -> NetworkSummary {
    network_summary_inner().unwrap_or_else(|err| NetworkSummary {
        egress_ip: None,
        dns_servers: Vec::new(),
        observed_dns: Vec::new(),
        error: Some(err),
    })
}

#[cfg(target_os = "windows")]
fn network_summary_inner() -> Result<NetworkSummary, String> {
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Continue'
$errors = @()
$egress = $null

try {
  $egress = (Invoke-RestMethod -UseBasicParsing -Uri 'https://api.ipify.org' -TimeoutSec 4).ToString().Trim()
} catch {
  $errors += $_.Exception.Message
}

$dns = @()
try {
  $dns = Get-DnsClientServerAddress |
    Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 } |
    Sort-Object InterfaceAlias, AddressFamily |
    ForEach-Object {
      "$($_.InterfaceAlias) [$($_.AddressFamily)]: $($_.ServerAddresses -join ', ')"
    }
} catch {
  $errors += $_.Exception.Message
}

$observed = @()
try {
  $checks = @(
    @{ Name = 'whoami.cloudflare'; Server = '1.1.1.1'; Type = 'TXT' },
    @{ Name = 'o-o.myaddr.l.google.com'; Server = 'ns1.google.com'; Type = 'TXT' }
  )
  foreach ($check in $checks) {
    try {
      $answers = Resolve-DnsName -Name $check.Name -Type $check.Type -Server $check.Server -ErrorAction Stop
      $answers | ForEach-Object {
        if ($_.Strings) {
          $observed += "$($check.Name) via $($check.Server): $($_.Strings -join ' ')"
        } elseif ($_.IPAddress) {
          $observed += "$($check.Name) via $($check.Server): $($_.IPAddress)"
        }
      }
    } catch {
      $errors += "$($check.Name) via $($check.Server): $($_.Exception.Message)"
    }
  }
} catch {
  $errors += $_.Exception.Message
}

$errorText = if ($errors.Count -gt 0) { $errors -join '; ' } else { $null }
[pscustomobject]@{
  egressIp = $egress
  dnsServers = @($dns)
  observedDns = @($observed)
  error = $errorText
} | ConvertTo-Json -Compress
"#;

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            SCRIPT,
        ])
        .output()
        .map_err(|err| err.to_string())?;

    if !output.status.success() {
        return Err(command_error("network summary", &output.stderr));
    }

    parse_network_summary(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(target_os = "windows"))]
fn network_summary_inner() -> Result<NetworkSummary, String> {
    let mut errors = Vec::new();
    let egress_ip = match Command::new("curl")
        .args(["-fsS", "--max-time", "4", "https://api.ipify.org"])
        .output()
    {
        Ok(output) if output.status.success() => {
            non_empty(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
        Ok(output) => {
            errors.push(command_error("egress IP", &output.stderr));
            None
        }
        Err(err) => {
            errors.push(err.to_string());
            None
        }
    };

    let dns_servers = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(contents) => contents
            .lines()
            .filter_map(|line| line.trim().strip_prefix("nameserver "))
            .map(str::trim)
            .filter(|server| !server.is_empty())
            .map(|server| format!("resolv.conf: {server}"))
            .collect(),
        Err(err) => {
            errors.push(err.to_string());
            Vec::new()
        }
    };

    let observed_dns = match Command::new("sh")
        .args([
            "-c",
            "command -v dig >/dev/null 2>&1 && { dig +short TXT whoami.cloudflare @1.1.1.1; dig +short TXT o-o.myaddr.l.google.com @ns1.google.com; }",
        ])
        .output()
    {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    };

    Ok(NetworkSummary {
        egress_ip,
        dns_servers,
        observed_dns,
        error: errors_to_option(errors),
    })
}

fn run_live_command(
    app: tauri::AppHandle,
    run_id: String,
    invocation: CommandInvocation,
    live_processes: Arc<Mutex<HashMap<String, Arc<Mutex<Child>>>>>,
) -> Result<ProbeLiveSummary, String> {
    emit_live(
        &app,
        ProbeLiveEvent {
            run_id: run_id.clone(),
            kind: "start",
            line: None,
            command: Some(invocation.display()),
            exit_code: None,
            done: false,
        },
    );

    let mut child = Command::new(&invocation.program)
        .args(&invocation.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("{}: {err}", invocation.display()))?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child = Arc::new(Mutex::new(child));

    live_processes
        .lock()
        .map_err(|_| "live process registry is poisoned".to_string())?
        .insert(run_id.clone(), Arc::clone(&child));

    let (tx, rx) = mpsc::channel::<(&'static str, String)>();

    if let Some(stdout) = stdout {
        let tx = tx.clone();
        thread::spawn(move || read_stream("stdout", stdout, tx));
    }

    if let Some(stderr) = stderr {
        let tx = tx.clone();
        thread::spawn(move || read_stream("stderr", stderr, tx));
    }

    drop(tx);

    let mut stdout_lines = Vec::new();
    let mut stderr_lines = Vec::new();

    for (kind, line) in rx {
        if kind == "stderr" {
            stderr_lines.push(line.clone());
        } else {
            stdout_lines.push(line.clone());
        }

        emit_live(
            &app,
            ProbeLiveEvent {
                run_id: run_id.clone(),
                kind,
                line: Some(line),
                command: None,
                exit_code: None,
                done: false,
            },
        );
    }

    let status = child
        .lock()
        .map_err(|_| "live process handle is poisoned".to_string())?
        .wait()
        .map_err(|err| err.to_string())?;
    let exit_code = status.code();

    if let Ok(mut processes) = live_processes.lock() {
        processes.remove(&run_id);
    }

    emit_live(
        &app,
        ProbeLiveEvent {
            run_id,
            kind: "exit",
            line: None,
            command: None,
            exit_code,
            done: true,
        },
    );

    Ok(ProbeLiveSummary {
        command: invocation.display(),
        exit_code,
        stdout: stdout_lines,
        stderr: stderr_lines,
    })
}

fn read_stream<R: std::io::Read + Send + 'static>(
    kind: &'static str,
    stream: R,
    tx: mpsc::Sender<(&'static str, String)>,
) {
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();

    loop {
        buffer.clear();
        match reader.read_until(b'\n', &mut buffer) {
            Ok(0) => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&buffer)
                    .trim_end_matches(['\r', '\n'])
                    .to_string();
                let _ = tx.send((kind, line));
            }
            Err(err) => {
                let _ = tx.send(("stderr", format!("stream read failed: {err}")));
                break;
            }
        }
    }
}

fn emit_live(app: &tauri::AppHandle, event: ProbeLiveEvent) {
    let _ = app.emit("probe-live-output", event);
}

fn invocation_with_override(
    core: &AppCore,
    target: &ProbeTarget,
    fallback: CommandInvocation,
    command_override: Option<String>,
) -> Result<CommandInvocation, String> {
    let Some(command_line) = command_override else {
        return Ok(fallback);
    };

    let command_line = command_line.trim();
    if command_line.is_empty() {
        return Ok(fallback);
    }

    core.ensure_allowed_for_target(target, ActionClass::ExternalTool)
        .map_err(|err| err.to_string())?;

    parse_command_line(command_line)
}

fn parse_command_line(command_line: &str) -> Result<CommandInvocation, String> {
    let parts = split_command_line(command_line)?;
    let (program, args) = parts
        .split_first()
        .ok_or_else(|| "command is empty".to_string())?;

    Ok(CommandInvocation {
        program: program.clone(),
        args: args.to_vec(),
    })
}

fn split_command_line(command_line: &str) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = command_line.chars().peekable();
    let mut quote: Option<char> = None;

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                } else {
                    current.push(ch);
                }
            }
            '\'' | '"' if quote == Some(ch) => {
                quote = None;
            }
            '\'' | '"' if quote.is_none() => {
                quote = Some(ch);
            }
            ch if ch.is_whitespace() && quote.is_none() => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }

    if let Some(open_quote) = quote {
        return Err(format!("unterminated {open_quote} quote in command"));
    }

    if !current.is_empty() {
        parts.push(current);
    }

    Ok(parts)
}

fn open_terminal(invocation: CommandInvocation, shell: String) -> Result<(), String> {
    if cfg!(target_os = "windows") {
        let normalized = shell.trim().to_ascii_lowercase();
        if normalized == "cmd" {
            Command::new("cmd")
                .args([
                    "/C",
                    "start",
                    "SonarNwork",
                    "cmd",
                    "/K",
                    &cmd_line(&invocation),
                ])
                .spawn()
                .map_err(|err| err.to_string())?;
        } else {
            Command::new("cmd")
                .args([
                    "/C",
                    "start",
                    "SonarNwork",
                    "powershell",
                    "-NoExit",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    &powershell_line(&invocation),
                ])
                .spawn()
                .map_err(|err| err.to_string())?;
        }

        return Ok(());
    }

    Err("opening a terminal is currently implemented for Windows".into())
}

fn powershell_line(invocation: &CommandInvocation) -> String {
    let mut parts = vec![format!("& {}", quote_powershell(&invocation.program))];
    parts.extend(invocation.args.iter().map(|arg| quote_powershell(arg)));
    parts.join(" ")
}

fn cmd_line(invocation: &CommandInvocation) -> String {
    std::iter::once(invocation.program.as_str())
        .chain(invocation.args.iter().map(String::as_str))
        .map(quote_cmd)
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_powershell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn quote_cmd(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

fn parse_network_summary(output: &str) -> Result<NetworkSummary, String> {
    let value: serde_json::Value =
        serde_json::from_str(output.trim()).map_err(|err| err.to_string())?;

    let egress_ip = value
        .get("egressIp")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .and_then(|value| non_empty(value.to_string()));

    let dns_servers = match value.get("dnsServers") {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|server| !server.is_empty())
            .map(str::to_string)
            .collect(),
        Some(serde_json::Value::String(server)) => {
            non_empty(server.trim().to_string()).into_iter().collect()
        }
        _ => Vec::new(),
    };

    let observed_dns = match value.get("observedDns") {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|server| !server.is_empty())
            .map(str::to_string)
            .collect(),
        Some(serde_json::Value::String(server)) => {
            non_empty(server.trim().to_string()).into_iter().collect()
        }
        _ => Vec::new(),
    };

    let error = value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .and_then(|value| non_empty(value.to_string()));

    Ok(NetworkSummary {
        egress_ip,
        dns_servers,
        observed_dns,
        error,
    })
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(not(target_os = "windows"))]
fn errors_to_option(errors: Vec<String>) -> Option<String> {
    let joined = errors
        .into_iter()
        .map(|error| error.trim().to_string())
        .filter(|error| !error.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    non_empty(joined)
}

fn command_error(label: &str, stderr: &[u8]) -> String {
    let detail = String::from_utf8_lossy(stderr).trim().to_string();
    if detail.is_empty() {
        format!("{label} command failed")
    } else {
        detail
    }
}

#[cfg(test)]
mod tests {
    use sonar_core::{AppCore, CommandInvocation, ProbeTarget};

    use super::{invocation_with_override, parse_command_line};

    #[test]
    fn parses_simple_editable_command() {
        let invocation = parse_command_line("ping -n 4 -w 1000 192.168.1.1").unwrap();

        assert_eq!(invocation.program, "ping");
        assert_eq!(invocation.args, ["-n", "4", "-w", "1000", "192.168.1.1"]);
    }

    #[test]
    fn parses_quoted_editable_command() {
        let invocation =
            parse_command_line("powershell -Command \"Write-Output hello world\"").unwrap();

        assert_eq!(invocation.program, "powershell");
        assert_eq!(invocation.args[0], "-Command");
        assert_eq!(invocation.args[1], "Write-Output hello world");
    }

    #[test]
    fn custom_command_requires_external_tool_scope() {
        let core = AppCore::default();
        let fallback = CommandInvocation {
            program: "echo".into(),
            args: vec!["ok".into()],
        };

        let error = invocation_with_override(
            &core,
            &ProbeTarget::CurrentInternetPath,
            fallback,
            Some("echo changed".into()),
        )
        .unwrap_err();

        assert!(error.contains("scope denied"));
    }
}

pub fn run() {
    tauri::Builder::default()
        .manage(LiveProcesses::default())
        .invoke_handler(tauri::generate_handler![
            app_info,
            parse_entity,
            all_probes,
            workflows,
            tools_catalog,
            tool_update_plan,
            remote_vantage_plan,
            available_probes,
            available_probes_for_target,
            run_probe,
            probe_command,
            open_probe_terminal,
            run_probe_live,
            cancel_probe_live,
            network_summary
        ])
        .run(tauri::generate_context!())
        .expect("error while running SonarNwork app");
}
