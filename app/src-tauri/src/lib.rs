mod history;
mod live;
mod operations;

use std::path::PathBuf;
use std::process::Command;

use serde::Serialize;
use sonar_core::{
    summarize_scanner_output, ActionClass, AppCore, AppInfo, CommandInvocation, Entity,
    ExternalScannerKind, ExternalScannerMode, ExternalScannerPorts, ExternalScannerProfile,
    InteractionCatalog, PivotGraph, ProbeDescriptor, ProbeOutput, ProbeTarget,
    RemoteMeasurementKind, RemoteVantagePlan, RemoteVantageProvider, ResultInterpretation,
    WorkflowDescriptor,
};
use sonar_tools::{
    remote::{
        GlobalpingMeasurementRequest, GlobalpingMeasurementResult, RemotePortCheckRequest,
        RemotePortCheckResult, RemoteProviderClient,
    },
    InstallStrategy, ToolCatalog, ToolLifecyclePlan, ToolRuntimeStatus, ToolUpdatePlan,
};

use history::{
    compare_probe_runs, delete_probe_run, get_probe_run, list_probe_runs, save_probe_run,
    HistoryState,
};
use live::{run_live_command, LiveProcesses, ProbeLiveSummary};
use operations::{
    capture_packets, capture_runtime_status, clear_timeline, collect_device_inventory,
    list_capture_interfaces, list_monitors, list_timeline, open_capture_handoff, resume_monitors,
    start_monitor, stop_monitor, OperationsState,
};

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
fn interaction_catalog() -> InteractionCatalog {
    ToolCatalog::phase_zero_defaults().interaction_catalog()
}

#[tauri::command]
fn tool_update_plan(tool_id: String) -> Result<ToolUpdatePlan, String> {
    ToolCatalog::phase_zero_defaults()
        .update_plan(&tool_id)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn tool_runtime_status(tool_id: String) -> Result<ToolRuntimeStatus, String> {
    ToolCatalog::phase_zero_defaults()
        .runtime_status(&tool_id)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn tool_lifecycle_plan(tool_id: String) -> Result<ToolLifecyclePlan, String> {
    ToolCatalog::phase_zero_defaults()
        .lifecycle_plan(&tool_id)
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn install_tool(tool_id: String) -> Result<ToolRuntimeStatus, String> {
    let catalog = ToolCatalog::phase_zero_defaults();
    let plan = catalog
        .lifecycle_plan(&tool_id)
        .map_err(|err| err.to_string())?;
    match plan.install_strategy {
        InstallStrategy::SystemInstaller => {
            let url = plan
                .action_url
                .ok_or_else(|| format!("{tool_id} installer URL is unavailable"))?;
            open_url(&url)?;
            catalog
                .runtime_status(&tool_id)
                .map_err(|err| err.to_string())
        }
        InstallStrategy::ManagedDownload => tauri::async_runtime::spawn_blocking(move || {
            catalog
                .install_managed(&tool_id)
                .map_err(|err| err.to_string())
        })
        .await
        .map_err(|err| err.to_string())?,
        _ => Err(format!(
            "{tool_id} does not support installation from the app"
        )),
    }
}

#[tauri::command]
async fn update_tool(tool_id: String) -> Result<ToolRuntimeStatus, String> {
    install_tool(tool_id).await
}

fn scanner_kind(tool_id: &str) -> Result<ExternalScannerKind, String> {
    ExternalScannerKind::from_tool_id(tool_id)
        .ok_or_else(|| format!("tool `{tool_id}` does not expose a scanner runner"))
}

fn scanner_invocation(
    tool_id: &str,
    target: &ProbeTarget,
    scope_confirmed: bool,
    scan_profile: Option<String>,
    scan_ports: Option<String>,
) -> Result<(ExternalScannerKind, CommandInvocation), String> {
    if !scope_confirmed {
        return Err("confirm that you own or are authorized to scan this target".into());
    }

    let kind = scanner_kind(tool_id)?;
    let runtime = ToolCatalog::phase_zero_defaults()
        .runtime_status(tool_id)
        .map_err(|err| err.to_string())?;
    if !runtime.available {
        return Err(runtime
            .error
            .unwrap_or_else(|| format!("{tool_id} is not installed")));
    }
    let executable = runtime
        .executable
        .ok_or_else(|| format!("{tool_id} executable path is unavailable"))?;
    let target_arg = scanner_cli_target(target)?;
    let profile = ExternalScannerProfile::new(kind, target_arg)
        .map_err(|err| err.to_string())?
        .with_mode(scanner_mode(kind, scan_profile.as_deref())?)
        .with_ports(scanner_ports(kind, scan_ports.as_deref())?)
        .map_err(|err| err.to_string())?;
    Ok((kind, profile.invocation(&executable)))
}

fn scanner_cli_invocation(
    tool_id: &str,
    target: &ProbeTarget,
    scope_confirmed: bool,
    scan_profile: Option<String>,
    scan_ports: Option<String>,
) -> Result<CommandInvocation, String> {
    if !scope_confirmed {
        return Err("confirm that you own or are authorized to scan this target".into());
    }

    let kind = scanner_kind(tool_id)?;
    let target_arg = scanner_cli_target(target)?;
    let mode = scanner_mode(kind, scan_profile.as_deref())?;
    let ports = scanner_ports(kind, scan_ports.as_deref())?;
    ExternalScannerProfile::new(kind, target_arg.clone())
        .map_err(|err| err.to_string())?
        .with_mode(mode)
        .with_ports(ports.clone())
        .map_err(|err| err.to_string())?;

    let mut args = vec![
        "scanner".into(),
        "run".into(),
        kind.tool_id().into(),
        target_arg,
    ];
    args.extend(["--profile".into(), scanner_profile_id(kind, mode).into()]);
    if matches!(kind, ExternalScannerKind::Nmap | ExternalScannerKind::Naabu) {
        args.extend(["--ports".into(), scanner_ports_id(&ports)]);
    }
    args.push("--yes".into());

    Ok(CommandInvocation {
        program: "sonarnwork".into(),
        args,
    })
}

fn scanner_mode(
    kind: ExternalScannerKind,
    value: Option<&str>,
) -> Result<ExternalScannerMode, String> {
    let mode = match value.unwrap_or_default() {
        "" | "default" => match kind {
            ExternalScannerKind::Nmap => ExternalScannerMode::NmapVersion,
            ExternalScannerKind::Nuclei => ExternalScannerMode::NucleiSafe,
            ExternalScannerKind::Httpx
            | ExternalScannerKind::Naabu
            | ExternalScannerKind::Subfinder
            | ExternalScannerKind::Dnsx
            | ExternalScannerKind::Trippy
            | ExternalScannerKind::Nexttrace => ExternalScannerMode::Default,
        },
        "fast" => ExternalScannerMode::Default,
        "version" | "nmap_version" => ExternalScannerMode::NmapVersion,
        "deep" | "nmap_service_deep" => ExternalScannerMode::NmapServiceDeep,
        "udp_quick" | "nmap_udp_quick" => ExternalScannerMode::NmapUdpQuick,
        "safe" | "nuclei_safe" => ExternalScannerMode::NucleiSafe,
        "http_exposure" | "nuclei_http_exposure" => ExternalScannerMode::NucleiHttpExposure,
        "known_vulns" | "nuclei_known_vulns" => ExternalScannerMode::NucleiKnownVulns,
        "full" | "nuclei_full" => ExternalScannerMode::NucleiFull,
        "nmap_top_ports" => ExternalScannerMode::NmapTopPorts,
        other => return Err(format!("unknown scanner profile `{other}`")),
    };
    if !scanner_mode_matches_kind(kind, mode) {
        return Err(format!(
            "scanner profile `{}` does not apply to {}",
            scanner_profile_id(kind, mode),
            kind.tool_id()
        ));
    }
    Ok(mode)
}

fn scanner_mode_matches_kind(kind: ExternalScannerKind, mode: ExternalScannerMode) -> bool {
    matches!(mode, ExternalScannerMode::Default)
        || matches!(
            (kind, mode),
            (
                ExternalScannerKind::Nmap,
                ExternalScannerMode::NmapTopPorts
                    | ExternalScannerMode::NmapVersion
                    | ExternalScannerMode::NmapServiceDeep
                    | ExternalScannerMode::NmapUdpQuick
            ) | (
                ExternalScannerKind::Nuclei,
                ExternalScannerMode::NucleiSafe
                    | ExternalScannerMode::NucleiHttpExposure
                    | ExternalScannerMode::NucleiKnownVulns
                    | ExternalScannerMode::NucleiFull
            )
        )
}

fn scanner_profile_id(kind: ExternalScannerKind, mode: ExternalScannerMode) -> &'static str {
    match (kind, mode) {
        (
            ExternalScannerKind::Nmap,
            ExternalScannerMode::Default | ExternalScannerMode::NmapTopPorts,
        ) => "fast",
        (ExternalScannerKind::Nmap, ExternalScannerMode::NmapVersion) => "version",
        (ExternalScannerKind::Nmap, ExternalScannerMode::NmapServiceDeep) => "deep",
        (ExternalScannerKind::Nmap, ExternalScannerMode::NmapUdpQuick) => "udp_quick",
        (ExternalScannerKind::Nuclei, ExternalScannerMode::NucleiSafe) => "safe",
        (ExternalScannerKind::Nuclei, ExternalScannerMode::NucleiHttpExposure) => "http_exposure",
        (ExternalScannerKind::Nuclei, ExternalScannerMode::NucleiKnownVulns) => "known_vulns",
        (ExternalScannerKind::Nuclei, ExternalScannerMode::NucleiFull) => "full",
        _ => "default",
    }
}

fn scanner_ports(
    kind: ExternalScannerKind,
    value: Option<&str>,
) -> Result<ExternalScannerPorts, String> {
    if !matches!(kind, ExternalScannerKind::Nmap | ExternalScannerKind::Naabu) {
        if value.is_some_and(|value| !value.trim().is_empty()) {
            return Err("ports only apply to nmap and naabu".into());
        }
        return Ok(ExternalScannerPorts::Default);
    }

    let ports = match value.unwrap_or("top").trim() {
        "" | "default" => ExternalScannerPorts::Default,
        "top" => ExternalScannerPorts::Top,
        "all" | "-" | "-p-" => ExternalScannerPorts::All,
        custom => ExternalScannerPorts::Custom(custom.into()),
    };
    Ok(ports)
}

fn scanner_ports_id(ports: &ExternalScannerPorts) -> String {
    match ports {
        ExternalScannerPorts::Default | ExternalScannerPorts::Top => "top".into(),
        ExternalScannerPorts::All => "all".into(),
        ExternalScannerPorts::Custom(value) => value.clone(),
    }
}

fn scanner_cli_target(target: &ProbeTarget) -> Result<String, String> {
    match target {
        ProbeTarget::Input(input) => {
            let target = input.trim();
            if target.is_empty()
                || target.starts_with('-')
                || target.chars().any(char::is_control)
                || target.chars().any(char::is_whitespace)
            {
                return Err(format!("invalid scanner target: {target}"));
            }
            Ok(target.into())
        }
        ProbeTarget::LocalMachine | ProbeTarget::CurrentInternetPath => {
            Err("scanner CLI requires an explicit target".into())
        }
    }
}

fn probe_cli_invocation(probe_id: &str, target: &ProbeTarget) -> Result<CommandInvocation, String> {
    if probe_id == "public.egress_check" && matches!(target, ProbeTarget::CurrentInternetPath) {
        return Ok(CommandInvocation {
            program: "sonarnwork".into(),
            args: vec!["myip".into()],
        });
    }

    let core = AppCore::for_explicit_target(target).unwrap_or_else(|_| AppCore::default());
    let fallback = core
        .command_invocation_for_target(probe_id, target)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("probe `{probe_id}` does not expose a terminal command"))?;

    let Ok(target_arg) = scanner_cli_target(target) else {
        return Ok(fallback);
    };

    Ok(CommandInvocation {
        program: "sonarnwork".into(),
        args: vec!["probe".into(), "run".into(), probe_id.into(), target_arg],
    })
}

#[tauri::command]
fn scanner_command(
    tool_id: String,
    target: ProbeTarget,
    scope_confirmed: bool,
    scan_profile: Option<String>,
    scan_ports: Option<String>,
) -> Result<CommandPreview, String> {
    let invocation =
        scanner_cli_invocation(&tool_id, &target, scope_confirmed, scan_profile, scan_ports)?;
    Ok(CommandPreview::from_invocation(invocation))
}

#[tauri::command]
fn open_scanner_terminal(
    tool_id: String,
    target: ProbeTarget,
    scope_confirmed: bool,
    scan_profile: Option<String>,
    scan_ports: Option<String>,
) -> Result<(), String> {
    let invocation =
        scanner_cli_invocation(&tool_id, &target, scope_confirmed, scan_profile, scan_ports)?;
    open_terminal(invocation)
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
async fn run_globalping_measurement(
    request: GlobalpingMeasurementRequest,
) -> Result<GlobalpingMeasurementResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        RemoteProviderClient::new()?.run_globalping(request)
    })
    .await
    .map_err(|err| err.to_string())?
    .map_err(|err| err.to_string())
}

#[tauri::command]
async fn run_remote_port_check(
    request: RemotePortCheckRequest,
) -> Result<RemotePortCheckResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        RemoteProviderClient::new()?.run_remote_port_check(request)
    })
    .await
    .map_err(|err| err.to_string())?
    .map_err(|err| err.to_string())
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
    let core = app_core_for_target(&target)?;
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
    let invocation = probe_cli_invocation(&probe_id, &target)?;

    Ok(CommandPreview::from_invocation(invocation))
}

#[tauri::command]
fn open_probe_terminal(
    probe_id: String,
    target: ProbeTarget,
    command_override: Option<String>,
) -> Result<(), String> {
    let core = AppCore::for_explicit_target(&target).unwrap_or_else(|_| AppCore::default());
    let fallback = probe_cli_invocation(&probe_id, &target)?;
    let invocation = invocation_with_override(&core, &target, fallback, command_override)?;

    open_terminal(invocation)
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
    let core = app_core_for_target(&target)?;
    let fallback = core
        .command_invocation_for_target(&probe_id, &target)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("probe `{probe_id}` does not expose a live command"))?;
    let invocation = invocation_with_override(&core, &target, fallback, command_override)?;
    let processes = live_processes.registry();

    tauri::async_runtime::spawn_blocking(move || {
        run_live_command(app, run_id, invocation, processes)
    })
    .await
    .map_err(|err| err.to_string())?
}

fn app_core_for_target(target: &ProbeTarget) -> Result<AppCore, String> {
    match target {
        ProbeTarget::Input(_) => {
            AppCore::for_explicit_target(target).map_err(|err| err.to_string())
        }
        ProbeTarget::LocalMachine | ProbeTarget::CurrentInternetPath => Ok(AppCore::default()),
    }
}

#[tauri::command]
// Tauri exposes command parameters by name; keeping them flat preserves the stable IPC contract.
#[allow(clippy::too_many_arguments)]
async fn run_scanner_live(
    app: tauri::AppHandle,
    live_processes: tauri::State<'_, LiveProcesses>,
    run_id: String,
    tool_id: String,
    target: ProbeTarget,
    scope_confirmed: bool,
    scan_profile: Option<String>,
    scan_ports: Option<String>,
) -> Result<ScannerRunView, String> {
    let (kind, invocation) =
        scanner_invocation(&tool_id, &target, scope_confirmed, scan_profile, scan_ports)?;
    let processes = live_processes.registry();
    let summary = tauri::async_runtime::spawn_blocking(move || {
        run_live_command(app, run_id, invocation, processes)
    })
    .await
    .map_err(|err| err.to_string())??;
    let output =
        summarize_scanner_output(kind, summary.exit_code, &summary.stdout, &summary.stderr);
    Ok(ScannerRunView { summary, output })
}

#[tauri::command]
fn cancel_probe_live(
    live_processes: tauri::State<'_, LiveProcesses>,
    run_id: String,
) -> Result<bool, String> {
    live_processes.cancel(&run_id)
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
}

impl CommandPreview {
    fn from_invocation(invocation: CommandInvocation) -> Self {
        Self {
            display: invocation.display(),
            program: invocation.program,
            args: invocation.args,
        }
    }
}

#[derive(Serialize)]
struct ScannerRunView {
    summary: ProbeLiveSummary,
    output: ProbeOutput,
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

    let invocation = parse_command_line(command_line)?;
    validate_command_override(&fallback, &invocation)?;
    Ok(invocation)
}

fn validate_command_override(
    fallback: &CommandInvocation,
    invocation: &CommandInvocation,
) -> Result<(), String> {
    if !same_executable(&fallback.program, &invocation.program) {
        return Err(format!(
            "command override executable must remain `{}`",
            fallback.program
        ));
    }

    if fallback.args.len() != invocation.args.len() {
        return Err("command override cannot add or remove arguments".into());
    }

    for (expected, candidate) in fallback.args.iter().zip(&invocation.args) {
        if expected == candidate {
            continue;
        }

        let numeric_option_changed =
            expected.parse::<u64>().is_ok() && candidate.parse::<u64>().is_ok();
        if !numeric_option_changed {
            return Err(
                "command override may only change numeric option values; executable, flags, and target are fixed"
                    .into(),
            );
        }
    }

    Ok(())
}

fn same_executable(expected: &str, candidate: &str) -> bool {
    if cfg!(windows) {
        expected.eq_ignore_ascii_case(candidate)
    } else {
        expected == candidate
    }
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

fn open_terminal(invocation: CommandInvocation) -> Result<(), String> {
    if cfg!(target_os = "windows") {
        let invocation = terminal_invocation(invocation)?;
        let command_line = terminal_command_line(&invocation);
        Command::new("cmd")
            .args([
                "/C",
                "start",
                "",
                "powershell.exe",
                "-NoExit",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &command_line,
            ])
            .spawn()
            .map_err(|err| err.to_string())?;

        return Ok(());
    }

    Err("opening a terminal is currently implemented for Windows".into())
}

fn terminal_invocation(mut invocation: CommandInvocation) -> Result<CommandInvocation, String> {
    if !invocation.program.eq_ignore_ascii_case("sonarnwork") {
        return Ok(invocation);
    }

    if let Some(program) = resolve_sonarnwork_cli() {
        invocation.program = program.to_string_lossy().to_string();
        return Ok(invocation);
    }

    if let Some(manifest) = resolve_workspace_manifest() {
        return Ok(cargo_sonarnwork_invocation(manifest, invocation.args));
    }

    Err(
        "Không tìm thấy SonarNwork CLI. Hãy build `sonarnwork.exe` hoặc đặt biến SONARNWORK_CLI trước khi mở CLI."
            .into(),
    )
}

fn cargo_sonarnwork_invocation(manifest: PathBuf, cli_args: Vec<String>) -> CommandInvocation {
    let mut args = vec![
        "run".into(),
        "--quiet".into(),
        "--manifest-path".into(),
        manifest.to_string_lossy().to_string(),
        "-p".into(),
        "sonar-cli".into(),
        "--bin".into(),
        "sonarnwork".into(),
        "--".into(),
    ];
    args.extend(cli_args);

    CommandInvocation {
        program: "cargo".into(),
        args,
    }
}

fn terminal_command_line(invocation: &CommandInvocation) -> String {
    if is_sonarnwork_program(&invocation.program) {
        let autorun = shell_input_line(&invocation.args);
        if autorun.is_empty() {
            return format!("& {}", quote_powershell(&invocation.program));
        }

        return format!(
            "$env:SONARNWORK_SHELL_AUTORUN = {}; & {}; Remove-Item Env:SONARNWORK_SHELL_AUTORUN -ErrorAction SilentlyContinue",
            quote_powershell(&autorun),
            quote_powershell(&invocation.program)
        );
    }

    if is_cargo_sonarnwork_invocation(invocation) {
        let Some(separator) = invocation.args.iter().rposition(|arg| arg == "--") else {
            return powershell_line(invocation);
        };
        let autorun = shell_input_line(&invocation.args[separator + 1..]);
        let mut launcher = invocation.clone();
        launcher.args.truncate(separator + 1);
        let launch_line = powershell_line(&launcher);

        if autorun.is_empty() {
            return launch_line;
        }

        return format!(
            "$env:SONARNWORK_SHELL_AUTORUN = {}; {}; Remove-Item Env:SONARNWORK_SHELL_AUTORUN -ErrorAction SilentlyContinue",
            quote_powershell(&autorun),
            launch_line
        );
    }

    powershell_line(invocation)
}

fn is_cargo_sonarnwork_invocation(invocation: &CommandInvocation) -> bool {
    let is_cargo = PathBuf::from(&invocation.program)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem.eq_ignore_ascii_case("cargo"));

    is_cargo
        && invocation
            .args
            .windows(2)
            .any(|pair| pair == ["--bin", "sonarnwork"])
}

fn is_sonarnwork_program(program: &str) -> bool {
    program.eq_ignore_ascii_case("sonarnwork")
        || PathBuf::from(program)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| stem.eq_ignore_ascii_case("sonarnwork"))
}

fn shell_input_line(args: &[String]) -> String {
    args.iter()
        .map(|arg| quote_shell_token(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_shell_token(value: &str) -> String {
    if !value.is_empty()
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\'' | '\\'))
    {
        return value.into();
    }

    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn resolve_sonarnwork_cli() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    let mut roots = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))];

    if let Ok(path) = std::env::var("SONARNWORK_CLI") {
        candidates.push(PathBuf::from(path));
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            candidates.push(exe_dir.join("sonarnwork.exe"));
            candidates.push(exe_dir.join("sonarnwork"));
            roots.push(exe_dir.to_path_buf());
        }
    }
    if let Ok(current_dir) = std::env::current_dir() {
        roots.push(current_dir);
    }

    for root in roots {
        for path in root.ancestors() {
            candidates.push(path.join("sonarnwork.exe"));
            candidates.push(path.join("sonarnwork"));
            candidates.push(path.join("target").join("debug").join("sonarnwork.exe"));
            candidates.push(path.join("target").join("release").join("sonarnwork.exe"));
        }
    }

    candidates.into_iter().find(|path| path.is_file())
}

fn resolve_workspace_manifest() -> Option<PathBuf> {
    let mut roots = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))];

    if let Ok(current_dir) = std::env::current_dir() {
        roots.push(current_dir);
    }
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(exe_dir) = current_exe.parent() {
            roots.push(exe_dir.to_path_buf());
        }
    }

    roots.into_iter().find_map(|root| {
        root.ancestors().find_map(|ancestor| {
            let manifest = ancestor.join("Cargo.toml");
            let cli_manifest = ancestor.join("crates").join("sonar-cli").join("Cargo.toml");
            (manifest.is_file() && cli_manifest.is_file()).then_some(manifest)
        })
    })
}

fn open_url(url: &str) -> Result<(), String> {
    if !installer_url_allowed(url) {
        return Err("installer URL is not on the official allow-list".into());
    }
    if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
            .map_err(|err| err.to_string())?;
        return Ok(());
    }
    Err("opening installer links is currently implemented for Windows".into())
}

fn installer_url_allowed(url: &str) -> bool {
    matches!(url, "https://nmap.org/download.html")
}

fn powershell_line(invocation: &CommandInvocation) -> String {
    let mut parts = vec![format!("& {}", quote_powershell(&invocation.program))];
    parts.extend(invocation.args.iter().map(|arg| quote_powershell(arg)));
    parts.join(" ")
}

fn quote_powershell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
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

pub fn run() {
    tauri::Builder::default()
        .manage(LiveProcesses::default())
        .manage(HistoryState::default())
        .manage(OperationsState::default())
        .setup(|app| {
            if let Err(error) = resume_monitors(app.handle().clone()) {
                eprintln!("could not resume background monitors: {error}");
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            parse_entity,
            all_probes,
            workflows,
            tools_catalog,
            interaction_catalog,
            tool_update_plan,
            tool_runtime_status,
            tool_lifecycle_plan,
            install_tool,
            update_tool,
            remote_vantage_plan,
            run_globalping_measurement,
            run_remote_port_check,
            capture_runtime_status,
            list_capture_interfaces,
            capture_packets,
            open_capture_handoff,
            collect_device_inventory,
            start_monitor,
            stop_monitor,
            list_monitors,
            list_timeline,
            clear_timeline,
            available_probes,
            available_probes_for_target,
            run_probe,
            probe_command,
            open_probe_terminal,
            run_probe_live,
            scanner_command,
            open_scanner_terminal,
            run_scanner_live,
            cancel_probe_live,
            network_summary,
            save_probe_run,
            list_probe_runs,
            get_probe_run,
            delete_probe_run,
            compare_probe_runs
        ])
        .run(tauri::generate_context!())
        .expect("error while running SonarNwork app");
}

#[cfg(test)]
mod tests {
    use sonar_core::{AppCore, CommandInvocation, ProbeTarget};

    use super::{
        app_core_for_target, cargo_sonarnwork_invocation, installer_url_allowed,
        interaction_catalog, invocation_with_override, parse_command_line, probe_cli_invocation,
        scanner_cli_invocation, scanner_invocation, scanner_kind, terminal_command_line,
        terminal_invocation,
    };

    #[test]
    fn interaction_catalog_serializes_all_desktop_operation_families() {
        let catalog = interaction_catalog();
        catalog.validate().unwrap();
        for id in [
            "ping",
            "scanner.nmap",
            "scanner.nuclei",
            "globalping",
            "capture",
            "inventory",
            "monitor",
            "timeline",
            "history",
        ] {
            assert!(catalog.namespace(id).is_some(), "missing namespace {id}");
        }

        let value = serde_json::to_value(catalog).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert!(value["namespaces"]
            .as_array()
            .is_some_and(|items| !items.is_empty()));
    }

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

    #[test]
    fn custom_command_cannot_replace_the_scoped_executable() {
        let target = ProbeTarget::Input("1.1.1.1".into());
        let core = AppCore::for_explicit_target(&target).unwrap();
        let fallback = CommandInvocation {
            program: "ping".into(),
            args: vec!["-n".into(), "4".into(), "1.1.1.1".into()],
        };

        let error = invocation_with_override(
            &core,
            &target,
            fallback,
            Some("powershell -n 4 1.1.1.1".into()),
        )
        .unwrap_err();

        assert!(error.contains("executable must remain"));
    }

    #[test]
    fn custom_command_cannot_replace_the_scoped_target() {
        let target = ProbeTarget::Input("1.1.1.1".into());
        let core = AppCore::for_explicit_target(&target).unwrap();
        let fallback = CommandInvocation {
            program: "ping".into(),
            args: vec!["-n".into(), "4".into(), "1.1.1.1".into()],
        };

        let error =
            invocation_with_override(&core, &target, fallback, Some("ping -n 4 8.8.8.8".into()))
                .unwrap_err();

        assert!(error.contains("target are fixed"));
    }

    #[test]
    fn custom_command_can_tune_a_numeric_option() {
        let target = ProbeTarget::Input("1.1.1.1".into());
        let core = AppCore::for_explicit_target(&target).unwrap();
        let fallback = CommandInvocation {
            program: "ping".into(),
            args: vec!["-n".into(), "4".into(), "1.1.1.1".into()],
        };

        let invocation =
            invocation_with_override(&core, &target, fallback, Some("ping -n 2 1.1.1.1".into()))
                .unwrap();

        assert_eq!(invocation.args, ["-n", "2", "1.1.1.1"]);
    }

    #[test]
    fn terminal_invocation_keeps_non_cli_programs() {
        let invocation = CommandInvocation {
            program: "ping".into(),
            args: vec!["127.0.0.1".into()],
        };

        let resolved = terminal_invocation(invocation).unwrap();

        assert_eq!(resolved.program, "ping");
        assert_eq!(resolved.args, ["127.0.0.1"]);
    }

    #[test]
    fn terminal_invocation_never_leaves_an_unresolved_cli_name() {
        let invocation = CommandInvocation {
            program: "sonarnwork".into(),
            args: vec!["myip".into()],
        };

        let resolved = terminal_invocation(invocation).unwrap();

        assert_ne!(resolved.program, "sonarnwork");
        assert!(
            resolved.program.eq_ignore_ascii_case("cargo")
                || super::is_sonarnwork_program(&resolved.program)
        );
    }

    #[test]
    fn terminal_cargo_fallback_runs_the_requested_cli_command() {
        let resolved = cargo_sonarnwork_invocation(
            "C:\\src\\SonarNwork\\Cargo.toml".into(),
            vec!["myip".into()],
        );

        assert_eq!(resolved.program, "cargo");
        assert_eq!(
            resolved.args,
            [
                "run",
                "--quiet",
                "--manifest-path",
                "C:\\src\\SonarNwork\\Cargo.toml",
                "-p",
                "sonar-cli",
                "--bin",
                "sonarnwork",
                "--",
                "myip",
            ]
        );

        let line = terminal_command_line(&resolved);
        assert!(line.contains("SONARNWORK_SHELL_AUTORUN"));
        assert!(line.contains("cargo"));
        assert_eq!(line.matches("myip").count(), 1);
    }

    #[test]
    fn terminal_command_line_opens_sonarnwork_shell_with_autorun() {
        let executable = format!("sonarnwork{}", std::env::consts::EXE_SUFFIX);
        let invocation = CommandInvocation {
            program: std::path::PathBuf::from("Apps")
                .join("SonarNwork")
                .join(&executable)
                .to_string_lossy()
                .into_owned(),
            args: vec!["probe".into(), "list".into()],
        };

        let line = terminal_command_line(&invocation);

        assert!(line.contains("SONARNWORK_SHELL_AUTORUN"));
        assert!(line.contains("probe list"));
        assert!(line.contains(&executable));
    }

    #[test]
    fn probe_cli_preview_uses_sonarnwork_for_explicit_target() {
        let invocation =
            probe_cli_invocation("connectivity.ping", &ProbeTarget::Input("1.1.1.1".into()))
                .unwrap();

        assert_eq!(invocation.program, "sonarnwork");
        assert_eq!(
            invocation.args,
            ["probe", "run", "connectivity.ping", "1.1.1.1"]
        );
    }

    #[test]
    fn probe_cli_preview_uses_myip_for_current_internet_path() {
        let invocation =
            probe_cli_invocation("public.egress_check", &ProbeTarget::CurrentInternetPath).unwrap();

        assert_eq!(invocation.program, "sonarnwork");
        assert_eq!(invocation.args, ["myip"]);
    }

    #[test]
    fn gui_core_allows_explicit_domain_probe_target() {
        let target = ProbeTarget::Input("youtube.com".into());
        let core = app_core_for_target(&target).unwrap();

        let invocation = core
            .command_invocation_for_target("connectivity.ping", &target)
            .unwrap();

        assert!(invocation.is_some());
    }

    #[test]
    fn scanner_preview_requires_explicit_scope_before_runtime_detection() {
        let error = scanner_invocation(
            "nmap",
            &ProbeTarget::Input("127.0.0.1".into()),
            false,
            None,
            None,
        )
        .unwrap_err();

        assert!(error.contains("authorized"));
    }

    #[test]
    fn scanner_cli_preview_uses_sonarnwork_without_runtime_detection() {
        let invocation = scanner_cli_invocation(
            "nmap",
            &ProbeTarget::Input("103.29.26.0/24".into()),
            true,
            Some("version".into()),
            Some("all".into()),
        )
        .unwrap();

        assert_eq!(invocation.program, "sonarnwork");
        assert_eq!(
            invocation.args,
            [
                "scanner",
                "run",
                "nmap",
                "103.29.26.0/24",
                "--profile",
                "version",
                "--ports",
                "all",
                "--yes"
            ]
        );
    }

    #[test]
    fn scanner_cli_preview_requires_explicit_scope() {
        let error = scanner_cli_invocation(
            "nuclei",
            &ProbeTarget::Input("https://example.com".into()),
            false,
            None,
            None,
        )
        .unwrap_err();

        assert!(error.contains("authorized"));
    }

    #[test]
    fn non_scanner_tool_cannot_use_scanner_runner() {
        assert!(scanner_kind("globalping").is_err());
    }

    #[test]
    fn installer_handoff_is_restricted_to_official_nmap_url() {
        assert!(installer_url_allowed("https://nmap.org/download.html"));
        assert!(!installer_url_allowed("http://nmap.org/download.html"));
        assert!(!installer_url_allowed("https://example.com/nmap.exe"));
    }
}
