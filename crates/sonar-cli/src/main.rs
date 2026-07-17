use anyhow::Context;
use clap::{error::ErrorKind, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::{json, Value};
use sonar_core::{
    command_target, summarize_scanner_output, ActionClass, AppCore, DnsLookupProfile, Entity,
    EntityKind, ExternalScannerKind, ExternalScannerMode, ExternalScannerPorts,
    ExternalScannerProfile, PingProfile, PivotGraph, PortCheckProfile, ProbeDescriptor,
    ProbeOutput, ProbeStatus, ProbeTarget, TraceProfile, TraceProtocol,
};
use sonar_tools::{
    history::HistoryService,
    operations::{
        capture_runtime_status, default_app_data_dir, list_capture_interfaces, CaptureRequest,
        OperationsService, StartMonitorRequest,
    },
    remote::{
        GlobalpingMeasurementKind, GlobalpingMeasurementRequest, RemotePortCheckRequest,
        RemoteProviderClient,
    },
    InstallStrategy, ToolCatalog,
};
use std::fmt::Display;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, ExitCode};

mod tui;
mod update;

#[derive(Debug, Parser)]
#[command(name = "sonar")]
#[command(version)]
#[command(about = "SonarNwork CLI shell backed by sonar-core")]
#[command(
    after_help = "Examples:\n  sonar\n  sonar check example.com\n  sonar ping 1.1.1.1 --count 4 --timeout 1000\n  sonar trace 1.1.1.1 --tcp --port 443\n  sonar scanner run nmap 103.29.26.0/24 --profile version --ports all\n  sonar update --check\n  sonar open ui"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a beginner-friendly quick check for a target.
    Check {
        target: String,
        #[command(flatten)]
        output: OutputOptions,
    },
    /// Ping a target from this machine.
    Ping {
        target: String,
        #[arg(long, default_value_t = 4)]
        count: u16,
        #[arg(long, default_value_t = 1000)]
        timeout: u64,
        #[arg(long)]
        size: Option<u16>,
        #[command(flatten)]
        output: OutputOptions,
    },
    /// Trace the route from this machine to a target.
    Trace {
        target: String,
        #[arg(long)]
        tcp: bool,
        #[arg(long)]
        udp: bool,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, default_value_t = 30)]
        max_hops: u8,
        #[command(flatten)]
        output: OutputOptions,
    },
    /// Resolve DNS records through the local resolver or a selected server.
    Dns {
        domain: String,
        #[arg(long, default_value = "A")]
        record: String,
        #[arg(long)]
        server: Option<String>,
        #[command(flatten)]
        output: OutputOptions,
    },
    /// Check host:port reachability from this machine.
    Port {
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value_t = 3000)]
        timeout: u64,
        #[command(flatten)]
        output: OutputOptions,
    },
    /// Show this machine's public egress IP and DNS path.
    Myip {
        #[command(flatten)]
        output: OutputOptions,
    },
    /// Show beginner workflows and safe first commands.
    Guide,
    Info {
        #[arg(long)]
        json: bool,
    },
    /// Check for or install the latest published SonarNwork version.
    Update {
        /// Check for a newer release without installing it.
        #[arg(long)]
        check: bool,
        /// Confirm the update without an interactive prompt.
        #[arg(long)]
        yes: bool,
    },
    Entity {
        #[command(subcommand)]
        command: EntityCommand,
    },
    Probe {
        #[command(subcommand)]
        command: ProbeCommand,
    },
    Scope {
        #[command(subcommand)]
        command: ScopeCommand,
    },
    Scanner {
        #[command(subcommand)]
        command: ScannerCommand,
    },
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },
    /// Run a measurement from an external network vantage point.
    Remote {
        #[command(subcommand)]
        command: RemoteCommand,
    },
    /// Inspect or start a bounded packet capture.
    Capture {
        #[command(subcommand)]
        command: CaptureCommand,
    },
    /// Collect the local neighbor/device inventory.
    Inventory {
        #[arg(long)]
        json: bool,
    },
    /// Manage persisted reachability monitors.
    Monitor {
        #[command(subcommand)]
        command: MonitorCommand,
    },
    /// View or clear the shared operations timeline.
    Timeline {
        #[command(subcommand)]
        command: TimelineCommand,
    },
    /// Browse, compare, or explicitly delete saved structured runs.
    History {
        #[command(subcommand)]
        command: HistoryCommand,
    },
    /// Open another SonarNwork user interface.
    Open {
        #[command(subcommand)]
        command: OpenCommand,
    },
}

#[derive(Debug, Subcommand)]
enum EntityCommand {
    Parse {
        target: String,
        #[arg(long)]
        json: bool,
    },
    Probes {
        target: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ProbeCommand {
    List {
        #[arg(long)]
        json: bool,
    },
    Run {
        probe_id: String,
        target: String,
        #[command(flatten)]
        output: OutputOptions,
    },
}

#[derive(Debug, Subcommand)]
enum ScopeCommand {
    Check {
        target: String,
        #[arg(long, value_enum, default_value_t = ActionArg::ActiveProbe)]
        action: ActionArg,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ScannerCommand {
    Run {
        #[arg(value_enum)]
        tool: ScannerToolArg,
        target: String,
        #[arg(long, value_enum)]
        profile: Option<ScannerProfileArg>,
        #[arg(long)]
        ports: Option<String>,
        #[command(flatten)]
        output: OutputOptions,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScannerToolArg {
    Nmap,
    Nuclei,
    Httpx,
    Naabu,
    Subfinder,
    Dnsx,
    Trippy,
    Nexttrace,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[value(rename_all = "snake_case")]
enum ScannerProfileArg {
    Default,
    Fast,
    Version,
    Deep,
    UdpQuick,
    Safe,
    HttpExposure,
    KnownVulns,
    Full,
}

impl From<ScannerToolArg> for ExternalScannerKind {
    fn from(value: ScannerToolArg) -> Self {
        match value {
            ScannerToolArg::Nmap => Self::Nmap,
            ScannerToolArg::Nuclei => Self::Nuclei,
            ScannerToolArg::Httpx => Self::Httpx,
            ScannerToolArg::Naabu => Self::Naabu,
            ScannerToolArg::Subfinder => Self::Subfinder,
            ScannerToolArg::Dnsx => Self::Dnsx,
            ScannerToolArg::Trippy => Self::Trippy,
            ScannerToolArg::Nexttrace => Self::Nexttrace,
        }
    }
}

impl From<ScannerProfileArg> for ExternalScannerMode {
    fn from(value: ScannerProfileArg) -> Self {
        match value {
            ScannerProfileArg::Default | ScannerProfileArg::Fast => Self::Default,
            ScannerProfileArg::Version => Self::NmapVersion,
            ScannerProfileArg::Deep => Self::NmapServiceDeep,
            ScannerProfileArg::UdpQuick => Self::NmapUdpQuick,
            ScannerProfileArg::Safe => Self::NucleiSafe,
            ScannerProfileArg::HttpExposure => Self::NucleiHttpExposure,
            ScannerProfileArg::KnownVulns => Self::NucleiKnownVulns,
            ScannerProfileArg::Full => Self::NucleiFull,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ToolsCommand {
    Catalog {
        #[arg(long)]
        json: bool,
    },
    Status {
        tool_id: String,
        #[arg(long)]
        json: bool,
    },
    Lifecycle {
        tool_id: String,
        #[arg(long)]
        json: bool,
    },
    Install {
        tool_id: String,
        /// Confirm this explicit installation or installer handoff.
        #[arg(long)]
        yes: bool,
    },
    Update {
        tool_id: String,
        /// Confirm this explicit update or installer handoff.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RemoteCommand {
    Globalping {
        #[arg(value_enum)]
        measurement: RemoteMeasurementArg,
        target: String,
        #[arg(long, default_value = "")]
        location: String,
        #[arg(long, default_value_t = 3)]
        limit: u8,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Port {
        target: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value_t = 3)]
        nodes: u8,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RemoteMeasurementArg {
    Ping,
    Traceroute,
    Mtr,
    Dns,
    Http,
}

impl From<RemoteMeasurementArg> for GlobalpingMeasurementKind {
    fn from(value: RemoteMeasurementArg) -> Self {
        match value {
            RemoteMeasurementArg::Ping => Self::Ping,
            RemoteMeasurementArg::Traceroute => Self::Traceroute,
            RemoteMeasurementArg::Mtr => Self::Mtr,
            RemoteMeasurementArg::Dns => Self::Dns,
            RemoteMeasurementArg::Http => Self::Http,
        }
    }
}

#[derive(Debug, Subcommand)]
enum CaptureCommand {
    Status {
        #[arg(long)]
        json: bool,
    },
    Interfaces {
        #[arg(long)]
        json: bool,
    },
    Run {
        #[arg(long)]
        interface: String,
        #[arg(long, default_value_t = 15)]
        duration: u64,
        #[arg(long, default_value_t = 5_000)]
        packets: u64,
        #[arg(long)]
        json: bool,
    },
    Open {
        path: std::path::PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum MonitorCommand {
    Start {
        target: String,
        #[arg(long, default_value_t = 60)]
        interval: u64,
        #[arg(long, default_value_t = 250)]
        latency: u64,
        #[arg(long, default_value_t = 20)]
        loss: u8,
        #[arg(long)]
        json: bool,
    },
    Stop {
        monitor_id: String,
    },
    List {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TimelineCommand {
    List {
        #[arg(long)]
        json: bool,
    },
    Clear {
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum HistoryCommand {
    List {
        #[arg(long)]
        query: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Get {
        id: String,
        #[arg(long)]
        json: bool,
    },
    Compare {
        left_id: String,
        right_id: String,
        #[arg(long)]
        json: bool,
    },
    Delete {
        id: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum OpenCommand {
    /// Launch the SonarNwork desktop app.
    Ui,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ActionArg {
    LocalInspection,
    PassiveLookup,
    ActiveProbe,
    IntrusiveScan,
    ExternalTool,
}

#[derive(Clone, Copy, Debug, Default, Args)]
struct OutputOptions {
    /// Print full structured JSON.
    #[arg(long, conflicts_with_all = ["raw", "summary"])]
    json: bool,
    /// Print the raw command payload/output.
    #[arg(long, conflicts_with_all = ["json", "summary"])]
    raw: bool,
    /// Print the filtered human summary. This is the default.
    #[arg(long, conflicts_with_all = ["json", "raw"])]
    summary: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputMode {
    Summary,
    Raw,
    Json,
}

const EXIT_UNHEALTHY: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_DEPENDENCY_UNAVAILABLE: u8 = 3;
const EXIT_CONFIRMATION_REQUIRED: u8 = 4;
const EXIT_OPERATION_FAILED: u8 = 5;

const CLI_BANNER: &str = r#"  ____   ___  _   _    _    ____  _   ___        _____  ____  _  __
 / ___| / _ \| \ | |  / \  |  _ \| \ | \ \      / / _ \|  _ \| |/ /
 \___ \| | | |  \| | / _ \ | |_) |  \| |\ \ /\ / / | | | |_) | ' /
  ___) | |_| | |\  |/ ___ \|  _ <| |\  | \ V  V /| |_| |  _ <| . \
 |____/ \___/|_| \_/_/   \_\_| \_\_| \_|  \_/\_/  \___/|_| \_\_|\_\"#;

#[derive(Debug)]
struct CliExitError {
    code: u8,
    message: String,
}

impl CliExitError {
    fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl Display for CliExitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CliExitError {}

#[derive(Clone, Copy)]
enum Tone {
    Brand,
    Heading,
    Label,
    Success,
    Warning,
    Error,
    Muted,
    Command,
}

impl Tone {
    fn ansi(self) -> &'static str {
        match self {
            Self::Brand => "\x1b[1;36m",
            Self::Heading => "\x1b[1;97m",
            Self::Label => "\x1b[36m",
            Self::Success => "\x1b[1;32m",
            Self::Warning => "\x1b[1;33m",
            Self::Error => "\x1b[1;31m",
            Self::Muted => "\x1b[2;37m",
            Self::Command => "\x1b[33m",
        }
    }
}

fn colors_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }

    match std::env::var("SONARNWORK_COLOR") {
        Ok(value) if value.eq_ignore_ascii_case("always") => true,
        Ok(value) if value.eq_ignore_ascii_case("never") => false,
        _ => io::stdout().is_terminal(),
    }
}

fn paint(value: impl Display, tone: Tone) -> String {
    if colors_enabled() {
        format!("{}{value}\x1b[0m", tone.ansi())
    } else {
        value.to_string()
    }
}

fn output_tone(output: &ProbeOutput) -> Tone {
    let failed = output
        .raw
        .as_ref()
        .and_then(|raw| raw.get("exit_code"))
        .and_then(Value::as_i64)
        .is_some_and(|code| code != 0);

    if failed {
        Tone::Error
    } else if output.warnings.is_empty() {
        Tone::Success
    } else {
        Tone::Warning
    }
}

impl OutputOptions {
    fn mode(self) -> OutputMode {
        if self.json {
            OutputMode::Json
        } else if self.raw {
            OutputMode::Raw
        } else {
            OutputMode::Summary
        }
    }
}

impl From<ActionArg> for ActionClass {
    fn from(value: ActionArg) -> Self {
        match value {
            ActionArg::LocalInspection => Self::LocalInspection,
            ActionArg::PassiveLookup => Self::PassiveLookup,
            ActionArg::ActiveProbe => Self::ActiveProbe,
            ActionArg::IntrusiveScan => Self::IntrusiveScan,
            ActionArg::ExternalTool => Self::ExternalTool,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match try_main().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(exit_code_for_error(&error))
        }
    }
}

async fn try_main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        if tui_enabled() {
            return tui::run();
        }
        return run_shell().await;
    };

    let core = AppCore::active_network_scan();
    run_command(command, &core).await
}

fn tui_enabled() -> bool {
    io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && std::env::var_os("SONARNWORK_SHELL_AUTORUN").is_none()
        && std::env::var("SONARNWORK_TUI").map_or(true, |value| value != "0")
}

fn exit_code_for_error(error: &anyhow::Error) -> u8 {
    if let Some(explicit) = error.downcast_ref::<CliExitError>() {
        return explicit.code;
    }

    let message = format!("{error:#}").to_ascii_lowercase();
    if [
        "not installed",
        "executable path is unavailable",
        "tool unavailable",
        "program not found",
        "no such file or directory",
        "cannot find the file specified",
        "os error 2",
    ]
    .iter()
    .any(|marker| message.contains(marker))
    {
        EXIT_DEPENDENCY_UNAVAILABLE
    } else if ["scope denied", "requires --yes", "confirm this explicit"]
        .iter()
        .any(|marker| message.contains(marker))
    {
        EXIT_CONFIRMATION_REQUIRED
    } else if [
        "invalid target",
        "invalid value",
        "unknown probe",
        "unsupported",
        "does not apply",
    ]
    .iter()
    .any(|marker| message.contains(marker))
    {
        EXIT_USAGE
    } else {
        EXIT_OPERATION_FAILED
    }
}

fn cli_operation<T>(result: Result<T, String>) -> anyhow::Result<T> {
    result.map_err(anyhow::Error::msg)
}

fn open_desktop_ui() -> anyhow::Result<()> {
    let executable = resolve_desktop_executable()?;
    ProcessCommand::new(&executable)
        .spawn()
        .with_context(|| format!("open SonarNwork desktop at {}", executable.display()))?;
    println!(
        "{} {}",
        paint("desktop opened:", Tone::Success),
        executable.display()
    );
    Ok(())
}

fn resolve_desktop_executable() -> anyhow::Result<PathBuf> {
    desktop_executable_candidates()
        .into_iter()
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "desktop program not found; keep sonarnwork-app next to sonar or set SONARNWORK_DESKTOP_PATH"
            )
        })
}

fn desktop_executable_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(explicit) = std::env::var_os("SONARNWORK_DESKTOP_PATH") {
        push_desktop_candidates(&mut candidates, PathBuf::from(explicit));
    }
    if let Ok(current) = std::env::current_exe() {
        if let Some(directory) = current.parent() {
            push_desktop_candidates(&mut candidates, directory.to_path_buf());
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            push_desktop_candidates(&mut candidates, directory);
        }
    }
    #[cfg(target_os = "windows")]
    {
        for key in ["LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(root) = std::env::var_os(key) {
                let root = PathBuf::from(root);
                push_desktop_candidates(&mut candidates, root.join("SonarNwork"));
                push_desktop_candidates(&mut candidates, root.join("Programs").join("SonarNwork"));
            }
        }
    }
    #[cfg(debug_assertions)]
    {
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        push_desktop_candidates(&mut candidates, workspace.join("target/debug"));
        push_desktop_candidates(&mut candidates, workspace.join("target/release"));
    }
    candidates
}

fn push_desktop_candidates(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    let is_known_executable = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            desktop_executable_names()
                .iter()
                .any(|candidate| name.eq_ignore_ascii_case(candidate))
        });
    if path.is_file() || (!path.is_dir() && is_known_executable) {
        candidates.push(path);
        return;
    }
    for executable in desktop_executable_names() {
        candidates.push(path.join(executable));
    }
}

#[cfg(target_os = "windows")]
fn desktop_executable_names() -> &'static [&'static str] {
    &["sonarnwork-app.exe", "SonarNwork.exe"]
}

#[cfg(not(target_os = "windows"))]
fn desktop_executable_names() -> &'static [&'static str] {
    &["sonarnwork-app", "SonarNwork"]
}

async fn run_command(command: Command, core: &AppCore) -> anyhow::Result<()> {
    match command {
        Command::Check {
            target,
            output: output_options,
        } => {
            let entity = core.parse_entity(&target)?;
            let probes = core.available_probes(&entity);
            let probe_id = beginner_probe_id(&entity, &probes)
                .context("no beginner-safe probe is available for this target")?;
            let (descriptor, output_value, graph) = core.run_probe(probe_id, &entity).await?;
            let view = ProbeRunView {
                descriptor: descriptor.clone(),
                output: output_value.clone(),
                graph,
            };
            if matches!(output_options.mode(), OutputMode::Summary) {
                print_beginner_check(&target, &entity, &descriptor, &output_value);
                ensure_probe_healthy(&output_value)?;
            } else {
                print_probe_run(&view, output_options)?;
            }
        }
        Command::Ping {
            target,
            count,
            timeout,
            size,
            output,
        } => {
            let entity = core.parse_entity(&target)?;
            let profile = PingProfile {
                target: command_target(&entity),
                count,
                timeout_ms: timeout,
                packet_size: size,
            };
            let invocation = core.ping_invocation(&profile);
            let (descriptor, output_value, graph) =
                core.run_command_invocation("connectivity.ping", invocation)?;
            print_probe_run(
                &ProbeRunView {
                    descriptor,
                    output: output_value,
                    graph,
                },
                output,
            )?;
        }
        Command::Trace {
            target,
            tcp,
            udp,
            port,
            max_hops,
            output,
        } => {
            anyhow::ensure!(!(tcp && udp), "choose either --tcp or --udp, not both");
            let entity = core.parse_entity(&target)?;
            let protocol = if tcp {
                TraceProtocol::Tcp
            } else if udp {
                TraceProtocol::Udp
            } else {
                TraceProtocol::Icmp
            };
            let profile = TraceProfile {
                target: command_target(&entity),
                protocol,
                port,
                max_hops,
            };
            let invocation = core.trace_invocation(&profile);
            let (descriptor, output_value, graph) =
                core.run_command_invocation("connectivity.traceroute", invocation)?;
            print_probe_run(
                &ProbeRunView {
                    descriptor,
                    output: output_value,
                    graph,
                },
                output,
            )?;
        }
        Command::Dns {
            domain,
            record,
            server,
            output,
        } => {
            let entity = core.parse_entity(&domain)?;
            let profile = DnsLookupProfile {
                target: command_target(&entity),
                record,
                server,
            };
            let invocation = core.dns_lookup_invocation(&profile);
            let (descriptor, output_value, graph) =
                core.run_command_invocation("dns.lookup", invocation)?;
            print_probe_run(
                &ProbeRunView {
                    descriptor,
                    output: output_value,
                    graph,
                },
                output,
            )?;
        }
        Command::Port {
            host,
            port,
            timeout,
            output,
        } => {
            let profile = PortCheckProfile {
                host,
                port,
                timeout_ms: timeout,
            };
            let (descriptor, output_value, graph) = core.run_port_profile(&profile)?;
            print_probe_run(
                &ProbeRunView {
                    descriptor,
                    output: output_value,
                    graph,
                },
                output,
            )?;
        }
        Command::Myip { output } => {
            let (descriptor, output_value, graph) = core
                .run_probe_target("public.egress_check", &ProbeTarget::CurrentInternetPath)
                .await?;
            print_probe_run(
                &ProbeRunView {
                    descriptor,
                    output: output_value,
                    graph,
                },
                output,
            )?;
        }
        Command::Guide => {
            print_guide();
        }
        Command::Info { json } => {
            let info = core.app_info();
            if json {
                print_json(&info)?;
            } else {
                println!(
                    "{} {}",
                    paint(info.name, Tone::Brand),
                    paint(info.version, Tone::Muted)
                );
                println!("{}", paint(info.contract, Tone::Muted));
            }
        }
        Command::Update { check, yes } => {
            tokio::task::spawn_blocking(move || update::run(check, yes))
                .await
                .context("wait for the SonarNwork updater")??;
        }
        Command::Entity { command } => match command {
            EntityCommand::Parse { target, json } => {
                let entity = core.parse_entity(&target)?;
                if json {
                    print_json(&entity)?;
                } else {
                    println!(
                        "{} {} {}",
                        paint(target, Tone::Command),
                        paint("->", Tone::Muted),
                        paint(entity.id(), Tone::Success)
                    );
                }
            }
            EntityCommand::Probes { target, json } => {
                let entity = core.parse_entity(&target)?;
                let probes = core.available_probes(&entity);
                if json {
                    print_json(&probes)?;
                } else {
                    println!("Applicable probes for {}:", entity.id());
                    for probe in probes {
                        println!("- {} ({:?})", probe.id, probe.risk);
                    }
                }
            }
        },
        Command::Probe { command } => match command {
            ProbeCommand::List { json } => {
                let probes = core.all_probes();
                if json {
                    print_json(&probes)?;
                } else {
                    print_probe_list(&probes);
                }
            }
            ProbeCommand::Run {
                probe_id,
                target,
                output,
            } => {
                let entity = core.parse_entity(&target)?;
                let (descriptor, output_value, graph) = core.run_probe(&probe_id, &entity).await?;
                print_probe_run(
                    &ProbeRunView {
                        descriptor,
                        output: output_value,
                        graph,
                    },
                    output,
                )?;
            }
        },
        Command::Scope { command } => match command {
            ScopeCommand::Check {
                target,
                action,
                json,
            } => {
                let scope_core = AppCore::default();
                let entity = scope_core.parse_entity(&target)?;
                let decision = scope_core.scope_decision(&entity, action.into());
                if json {
                    print_json(&decision)?;
                } else {
                    println!("{:?}", decision);
                }
            }
        },
        Command::Scanner { command } => match command {
            ScannerCommand::Run {
                tool,
                target,
                profile,
                ports,
                output,
            } => {
                run_scanner_command(tool.into(), profile, ports, target, output)?;
            }
        },
        Command::Tools { command } => match command {
            ToolsCommand::Catalog { json } => {
                let catalog = ToolCatalog::phase_zero_defaults();
                if json {
                    print_json(&catalog)?;
                } else {
                    for tool in catalog.tools {
                        println!(
                            "- {}: {:?}, {:?}",
                            tool.id, tool.source, tool.install_strategy
                        );
                    }
                }
            }
            ToolsCommand::Status { tool_id, json } => {
                let status = ToolCatalog::phase_zero_defaults().runtime_status(&tool_id)?;
                if json {
                    print_json(&status)?;
                } else if status.available {
                    println!(
                        "{} {}",
                        paint("installed:", Tone::Success),
                        status.version.as_deref().unwrap_or("version unavailable")
                    );
                    if let Some(executable) = status.executable {
                        println!(
                            "{} {}",
                            paint("path     :", Tone::Label),
                            executable.display()
                        );
                    }
                } else {
                    println!("{} {tool_id}", paint("unavailable:", Tone::Warning));
                    if let Some(error) = status.error {
                        println!("{error}");
                    }
                }
            }
            ToolsCommand::Lifecycle { tool_id, json } => {
                let plan = ToolCatalog::phase_zero_defaults().lifecycle_plan(&tool_id)?;
                if json {
                    print_json(&plan)?;
                } else {
                    println!("{} {tool_id}", paint("tool     :", Tone::Label));
                    println!(
                        "{} {:?}",
                        paint("strategy :", Tone::Label),
                        plan.install_strategy
                    );
                    println!("{} {}", paint("installed:", Tone::Label), plan.installed);
                    println!("{} {}", paint("note     :", Tone::Label), plan.note);
                }
            }
            ToolsCommand::Install { tool_id, yes } => {
                run_tool_lifecycle_action(&tool_id, yes)?;
            }
            ToolsCommand::Update { tool_id, yes } => {
                run_tool_lifecycle_action(&tool_id, yes)?;
            }
        },
        Command::Remote { command } => {
            let client = RemoteProviderClient::new()?;
            match command {
                RemoteCommand::Globalping {
                    measurement,
                    target,
                    location,
                    limit,
                    token,
                    json,
                } => {
                    let result = client.run_globalping(GlobalpingMeasurementRequest {
                        kind: measurement.into(),
                        target,
                        location,
                        limit,
                        token: token.or_else(|| std::env::var("GLOBALPING_TOKEN").ok()),
                    })?;
                    if json {
                        print_json(&result)?;
                    } else {
                        println!("{} {}", paint("status:", Tone::Label), result.status);
                        println!("{} {}", paint("target:", Tone::Label), result.target);
                        println!("{} {}", paint("report:", Tone::Label), result.share_url);
                        for node in result.nodes {
                            println!("- {}: {}", node.location, node.summary);
                        }
                    }
                }
                RemoteCommand::Port {
                    target,
                    port,
                    nodes,
                    json,
                } => {
                    let result = client.run_remote_port_check(RemotePortCheckRequest {
                        target,
                        port,
                        max_nodes: nodes,
                    })?;
                    if json {
                        print_json(&result)?;
                    } else {
                        println!("{} {}", paint("status:", Tone::Label), result.status);
                        println!(
                            "{} {}:{}",
                            paint("target:", Tone::Label),
                            result.target,
                            result.port
                        );
                        println!("{} {}", paint("report:", Tone::Label), result.report_url);
                        for node in result.nodes {
                            println!("- {}: {}", node.location, node.status);
                        }
                    }
                }
            }
        }
        Command::Capture { command } => {
            let service = OperationsService::new(default_app_data_dir());
            match command {
                CaptureCommand::Status { json } => {
                    let status = capture_runtime_status();
                    if json {
                        print_json(&status)?;
                    } else if status.available {
                        println!(
                            "{} {}",
                            paint("ready:", Tone::Success),
                            status.version.as_deref().unwrap_or("TShark")
                        );
                    } else {
                        println!("{}", paint("TShark unavailable", Tone::Warning));
                        if let Some(error) = status.error {
                            println!("{error}");
                        }
                    }
                }
                CaptureCommand::Interfaces { json } => {
                    let interfaces = cli_operation(list_capture_interfaces())?;
                    if json {
                        print_json(&interfaces)?;
                    } else {
                        for interface in interfaces {
                            println!("- {}: {}", interface.id, interface.label);
                        }
                    }
                }
                CaptureCommand::Run {
                    interface,
                    duration,
                    packets,
                    json,
                } => {
                    let result = cli_operation(service.capture_packets(CaptureRequest {
                        interface_id: interface,
                        duration_seconds: duration,
                        packet_limit: packets,
                    }))?;
                    if json {
                        print_json(&result)?;
                    } else {
                        println!(
                            "{} {}",
                            paint("capture:", Tone::Success),
                            result.path.display()
                        );
                        println!("{} {}", paint("bytes  :", Tone::Label), result.bytes);
                    }
                }
                CaptureCommand::Open { path } => {
                    cli_operation(service.open_capture_handoff(path))?;
                }
            }
        }
        Command::Inventory { json } => {
            let snapshot = cli_operation(
                OperationsService::new(default_app_data_dir()).collect_device_inventory(),
            )?;
            if json {
                print_json(&snapshot)?;
            } else {
                println!(
                    "{} {} ({})",
                    paint("devices:", Tone::Label),
                    snapshot.devices.len(),
                    snapshot.source
                );
                for device in snapshot.devices {
                    println!(
                        "- {}  {}  {}",
                        device.ip,
                        device.mac.as_deref().unwrap_or("-"),
                        device.state
                    );
                }
            }
        }
        Command::Monitor { command } => {
            let service = OperationsService::new(default_app_data_dir());
            match command {
                MonitorCommand::Start {
                    target,
                    interval,
                    latency,
                    loss,
                    json,
                } => {
                    let config = cli_operation(service.start_monitor(StartMonitorRequest {
                        target,
                        interval_seconds: interval,
                        latency_alert_ms: latency,
                        loss_alert_percent: loss,
                    }))?;
                    if json {
                        print_json(&config)?;
                    } else {
                        println!("{} {}", paint("monitor:", Tone::Success), config.id);
                        println!("{} {}", paint("target :", Tone::Label), config.target);
                        println!(
                            "registered in the shared store; the desktop or an active TUI session resumes sampling"
                        );
                    }
                }
                MonitorCommand::Stop { monitor_id } => {
                    cli_operation(service.stop_monitor(&monitor_id))?;
                }
                MonitorCommand::List { json } => {
                    let monitors = cli_operation(service.list_monitors())?;
                    if json {
                        print_json(&monitors)?;
                    } else {
                        for monitor in monitors {
                            println!(
                                "- {} {} every {}s ({})",
                                monitor.id,
                                monitor.target,
                                monitor.interval_seconds,
                                if monitor.enabled {
                                    "enabled"
                                } else {
                                    "stopped"
                                }
                            );
                        }
                    }
                }
            }
        }
        Command::Timeline { command } => {
            let service = OperationsService::new(default_app_data_dir());
            match command {
                TimelineCommand::List { json } => {
                    let events = cli_operation(service.list_timeline())?;
                    if json {
                        print_json(&events)?;
                    } else {
                        for event in events {
                            println!("- [{}] {}: {}", event.severity, event.title, event.detail);
                        }
                    }
                }
                TimelineCommand::Clear { yes } => {
                    anyhow::ensure!(yes, "clearing the timeline requires --yes");
                    cli_operation(service.clear_timeline())?;
                    println!("{}", paint("timeline cleared", Tone::Success));
                }
            }
        }
        Command::History { command } => {
            let history = HistoryService::new(default_app_data_dir());
            match command {
                HistoryCommand::List { query, json } => {
                    let runs = cli_operation(history.list(query.as_deref()))?;
                    if json {
                        print_json(&runs)?;
                    } else {
                        for run in runs {
                            println!(
                                "- {} [{}] {} {} — {}",
                                run.id, run.verdict, run.probe_id, run.target, run.summary
                            );
                        }
                    }
                }
                HistoryCommand::Get { id, json } => {
                    let run = cli_operation(history.get(&id))?;
                    if json {
                        print_json(&run)?;
                    } else {
                        println!("{} {}", paint("probe  :", Tone::Label), run.probe_name);
                        println!("{} {}", paint("target :", Tone::Label), run.target);
                        println!("{} {}", paint("verdict:", Tone::Label), run.verdict);
                        println!("{} {}", paint("summary:", Tone::Label), run.summary);
                        for fact in run.summary_rows {
                            println!("- {}: {}", fact.label, fact.value);
                        }
                    }
                }
                HistoryCommand::Compare {
                    left_id,
                    right_id,
                    json,
                } => {
                    let comparison = cli_operation(history.compare(&left_id, &right_id))?;
                    if json {
                        print_json(&comparison)?;
                    } else {
                        println!(
                            "{} {}",
                            paint("verdict changed:", Tone::Label),
                            comparison.verdict_changed
                        );
                        for change in comparison.fact_changes {
                            println!(
                                "- {}: {} -> {}",
                                change.label,
                                change.before.as_deref().unwrap_or("-"),
                                change.after.as_deref().unwrap_or("-")
                            );
                        }
                    }
                }
                HistoryCommand::Delete { id, yes } => {
                    anyhow::ensure!(yes, "deleting a saved run requires --yes");
                    cli_operation(history.delete(&id))?;
                    println!("{} {id}", paint("deleted:", Tone::Success));
                }
            }
        }
        Command::Open { command } => match command {
            OpenCommand::Ui => open_desktop_ui()?,
        },
    }

    Ok(())
}

fn run_tool_lifecycle_action(tool_id: &str, confirmed: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        confirmed,
        "confirm this explicit tool installation or update with --yes"
    );
    let catalog = ToolCatalog::phase_zero_defaults();
    let plan = catalog.lifecycle_plan(tool_id)?;
    match plan.install_strategy {
        InstallStrategy::SystemInstaller => {
            let url = plan
                .action_url
                .context("official installer URL is unavailable")?;
            anyhow::ensure!(
                url == "https://nmap.org/download.html",
                "installer URL is not on the official allow-list"
            );
            #[cfg(target_os = "windows")]
            {
                std::process::Command::new("cmd")
                    .args(["/C", "start", "", &url])
                    .spawn()
                    .context("open official installer")?;
                println!("Opened the official installer. Refresh tool status after it completes.");
                Ok(())
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = url;
                anyhow::bail!("installer handoff is currently implemented for Windows")
            }
        }
        InstallStrategy::ManagedDownload | InstallStrategy::AutoDownload => {
            let status = catalog.install_managed(tool_id)?;
            anyhow::ensure!(status.available, "{tool_id} installation was not detected");
            println!(
                "{} {}",
                paint("installed:", Tone::Success),
                status.version.as_deref().unwrap_or("version unavailable")
            );
            Ok(())
        }
        _ => anyhow::bail!("{tool_id} does not support installation from SonarNwork"),
    }
}

async fn run_shell() -> anyhow::Result<()> {
    let core = AppCore::active_network_scan();
    print_shell_banner(&core);

    if let Ok(command) = std::env::var("SONARNWORK_SHELL_AUTORUN") {
        let command = command.trim();
        if !command.is_empty() {
            println!(
                "{} {} {}",
                paint("sonar", Tone::Brand),
                paint(">", Tone::Muted),
                paint(command, Tone::Command)
            );
            run_shell_command(command, &core).await;
            println!();
        }
    }

    loop {
        print!(
            "{} {} ",
            paint("sonar", Tone::Brand),
            paint(">", Tone::Muted)
        );
        io::stdout().flush().context("flush shell prompt")?;

        let mut line = String::new();
        if io::stdin()
            .read_line(&mut line)
            .context("read shell input")?
            == 0
        {
            println!();
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match line.to_ascii_lowercase().as_str() {
            "exit" | "quit" => break,
            "clear" | "cls" => {
                print!("\x1b[2J\x1b[H");
                print_shell_banner(&core);
                continue;
            }
            "help" | "?" => {
                print_shell_help();
                continue;
            }
            _ => run_shell_command(line, &core).await,
        }

        println!();
    }

    Ok(())
}

async fn run_shell_command(line: &str, core: &AppCore) {
    match parse_shell_command(line) {
        Ok(Some(command)) => {
            if let Err(err) = run_command(command, core).await {
                eprintln!("{} {err:#}", paint("error:", Tone::Error));
            }
        }
        Ok(None) => {}
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            print!("{err}");
        }
        Err(err) => {
            eprint!("{err}");
        }
    }
}

fn parse_shell_command(line: &str) -> Result<Option<Command>, clap::Error> {
    let mut args = split_shell_line(line)
        .map_err(|message| Cli::command().error(ErrorKind::InvalidValue, message))?;
    if args.is_empty() {
        return Ok(None);
    }

    if !args.first().is_some_and(|arg| {
        arg.eq_ignore_ascii_case("sonar") || arg.eq_ignore_ascii_case("sonarnwork")
    }) {
        args.insert(0, "sonar".into());
    }

    Cli::try_parse_from(args).map(|cli| cli.command)
}

fn split_shell_line(line: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut quote: Option<char> = None;
    let mut token_started = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                let mut backslashes = 1;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    backslashes += 1;
                }

                let matching_quote = chars.peek().copied().filter(|next| {
                    matches!(next, '\'' | '"') && (quote.is_none() || quote == Some(*next))
                });
                if let Some(next_quote) = matching_quote {
                    current.extend(std::iter::repeat_n('\\', backslashes / 2));
                    chars.next();
                    if backslashes % 2 == 0 {
                        quote = if quote == Some(next_quote) {
                            None
                        } else {
                            Some(next_quote)
                        };
                    } else {
                        current.push(next_quote);
                    }
                } else {
                    current.extend(std::iter::repeat_n('\\', backslashes));
                }
                token_started = true;
            }
            '\'' | '"' if quote == Some(ch) => {
                quote = None;
                token_started = true;
            }
            '\'' | '"' if quote.is_none() => {
                quote = Some(ch);
                token_started = true;
            }
            ch if ch.is_whitespace() && quote.is_none() => {
                if token_started {
                    args.push(std::mem::take(&mut current));
                    token_started = false;
                }
            }
            _ => {
                current.push(ch);
                token_started = true;
            }
        }
    }

    if let Some(open_quote) = quote {
        return Err(format!("unterminated {open_quote} quote"));
    }

    if token_started {
        args.push(current);
    }

    Ok(args)
}

#[cfg(test)]
mod shell_input_tests {
    use super::split_shell_line;

    #[test]
    fn preserves_windows_paths() {
        assert_eq!(
            split_shell_line(r"capture open C:\Temp\trace.pcapng").unwrap(),
            ["capture", "open", r"C:\Temp\trace.pcapng"]
        );
        assert_eq!(
            split_shell_line(r#"capture open "C:\Program Files\SonarNwork\trace.pcapng""#).unwrap(),
            [
                "capture",
                "open",
                r"C:\Program Files\SonarNwork\trace.pcapng"
            ]
        );
        assert_eq!(
            split_shell_line(r#"capture open "\\server\captures\trace.pcapng""#).unwrap(),
            ["capture", "open", r"\\server\captures\trace.pcapng"]
        );
    }

    #[test]
    fn supports_quoted_arguments_and_rejects_unclosed_quotes() {
        assert_eq!(
            split_shell_line(r#"ping "host name" --count 2"#).unwrap(),
            ["ping", "host name", "--count", "2"]
        );
        assert_eq!(
            split_shell_line(r#"check "a\"b""#).unwrap(),
            ["check", "a\"b"]
        );
        assert_eq!(
            split_shell_line(r#"check "" tail"#).unwrap(),
            ["check", "", "tail"]
        );
        assert_eq!(
            split_shell_line(r#"capture open "C:\Temp Folder\\""#).unwrap(),
            ["capture", "open", "C:\\Temp Folder\\"]
        );
        assert!(split_shell_line(r#"ping "unfinished"#).is_err());
    }
}

fn print_shell_banner(core: &AppCore) {
    let info = core.app_info();

    println!("\n{}\n", paint(CLI_BANNER, Tone::Brand));
    println!(
        "{}  {}",
        paint("SonarNwork CLI Shell", Tone::Heading),
        paint(info.version, Tone::Muted)
    );
    println!("{}", paint(info.contract, Tone::Muted));
    println!();
    println!(
        "{} interactive operator console",
        paint("Mode   :", Tone::Label)
    );
    println!(
        "{} local checks, DNS, trace, ports, probes, and scanners",
        paint("Scope  :", Tone::Label)
    );
    println!(
        "{} type commands below without the program name",
        paint("Input  :", Tone::Label)
    );
    println!(
        "{} {}",
        paint("Try    :", Tone::Label),
        paint("help | probe list | myip | exit", Tone::Command)
    );
    println!();
}

fn print_shell_help() {
    println!("{}", paint("Interactive commands", Tone::Heading));
    println!("  help                         show this shell help");
    println!("  clear                        redraw the banner");
    println!("  exit                         close the shell");
    println!();
    println!(
        "{}",
        paint("Run SonarNwork commands directly", Tone::Heading)
    );
    println!("  check example.com");
    println!("  ping 1.1.1.1 --count 4 --timeout 1000");
    println!("  trace 1.1.1.1 --tcp --port 443");
    println!("  dns example.com --record A");
    println!("  probe list");
    println!("  probe run core.describe_entity 1.1.1.1");
    println!("  scanner run nmap 103.29.26.0/24 --profile version --ports all");
    println!("  myip");
    println!("  update --check");
    println!();
    println!("{}", paint("Command help still works", Tone::Heading));
    println!("  probe --help");
    println!("  scanner run --help");
}

#[derive(Serialize)]
struct ProbeRunView {
    descriptor: ProbeDescriptor,
    output: ProbeOutput,
    graph: PivotGraph,
}

#[derive(Serialize)]
struct ScannerRunView {
    tool_id: String,
    target: String,
    command: String,
    exit_code: Option<i32>,
    output: ProbeOutput,
}

fn run_scanner_command(
    kind: ExternalScannerKind,
    profile: Option<ScannerProfileArg>,
    ports: Option<String>,
    target: String,
    output_options: OutputOptions,
) -> anyhow::Result<()> {
    let tool_id = kind.tool_id();
    let mode = scanner_profile_for_tool(kind, profile)?;
    let port_spec = scanner_ports_for_tool(kind, ports)?;
    ensure_scanner_mode_matches_kind(kind, mode)?;
    let profile = ExternalScannerProfile::new(kind, target.clone())?
        .with_mode(mode)
        .with_ports(port_spec)?;
    let runtime = ToolCatalog::phase_zero_defaults().runtime_status(tool_id)?;
    anyhow::ensure!(
        runtime.available,
        "{}",
        runtime
            .error
            .unwrap_or_else(|| format!("{tool_id} is not installed"))
    );
    let executable = runtime
        .executable
        .with_context(|| format!("{tool_id} executable path is unavailable"))?;
    let invocation = profile.invocation(&executable);
    let command_display = invocation.display();
    let output = std::process::Command::new(&invocation.program)
        .args(&invocation.args)
        .output()
        .with_context(|| format!("run {command_display}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout_lines = stdout.lines().map(str::to_string).collect::<Vec<_>>();
    let stderr_lines = stderr.lines().map(str::to_string).collect::<Vec<_>>();
    let mut probe_output =
        summarize_scanner_output(kind, output.status.code(), &stdout_lines, &stderr_lines);
    probe_output.raw = Some(json!({
        "command": command_display.clone(),
        "exitCode": output.status.code(),
        "stdout": stdout,
        "stderr": stderr,
    }));

    let view = ScannerRunView {
        tool_id: tool_id.into(),
        target,
        command: command_display,
        exit_code: output.status.code(),
        output: probe_output,
    };
    print_scanner_run(&view, output_options)?;

    if !output.status.success() {
        return Err(CliExitError::new(
            EXIT_UNHEALTHY,
            format!("scanner exited with {}", output.status),
        )
        .into());
    }

    Ok(())
}

fn scanner_profile_for_tool(
    kind: ExternalScannerKind,
    profile: Option<ScannerProfileArg>,
) -> anyhow::Result<ExternalScannerMode> {
    let profile = profile.unwrap_or(match kind {
        ExternalScannerKind::Nmap => ScannerProfileArg::Version,
        ExternalScannerKind::Nuclei => ScannerProfileArg::Safe,
        ExternalScannerKind::Httpx
        | ExternalScannerKind::Naabu
        | ExternalScannerKind::Subfinder
        | ExternalScannerKind::Dnsx
        | ExternalScannerKind::Trippy
        | ExternalScannerKind::Nexttrace => ScannerProfileArg::Default,
    });
    let mode = profile.into();
    ensure_scanner_mode_matches_kind(kind, mode)?;
    Ok(mode)
}

fn scanner_ports_for_tool(
    kind: ExternalScannerKind,
    ports: Option<String>,
) -> anyhow::Result<ExternalScannerPorts> {
    match kind {
        ExternalScannerKind::Nmap | ExternalScannerKind::Naabu => {
            Ok(parse_scanner_ports(ports.as_deref().unwrap_or("top"))?)
        }
        ExternalScannerKind::Nuclei
        | ExternalScannerKind::Httpx
        | ExternalScannerKind::Subfinder
        | ExternalScannerKind::Dnsx
        | ExternalScannerKind::Trippy
        | ExternalScannerKind::Nexttrace => {
            anyhow::ensure!(ports.is_none(), "--ports only applies to nmap and naabu");
            Ok(ExternalScannerPorts::Default)
        }
    }
}

fn parse_scanner_ports(value: &str) -> anyhow::Result<ExternalScannerPorts> {
    match value.trim() {
        "" | "default" => Ok(ExternalScannerPorts::Default),
        "top" => Ok(ExternalScannerPorts::Top),
        "all" | "-" | "-p-" => Ok(ExternalScannerPorts::All),
        custom => Ok(ExternalScannerPorts::Custom(custom.to_string())),
    }
}

fn ensure_scanner_mode_matches_kind(
    kind: ExternalScannerKind,
    mode: ExternalScannerMode,
) -> anyhow::Result<()> {
    let valid = matches!(mode, ExternalScannerMode::Default)
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
        );
    anyhow::ensure!(valid, "scanner mode does not apply to {}", kind.tool_id());
    Ok(())
}

fn print_scanner_run(view: &ScannerRunView, options: OutputOptions) -> anyhow::Result<()> {
    match options.mode() {
        OutputMode::Json => print_json(view),
        OutputMode::Raw => print_raw_output(&view.output),
        OutputMode::Summary => {
            println!(
                "{}",
                view.output
                    .summary
                    .as_deref()
                    .unwrap_or("Scanner completed.")
            );
            print_summary_rows(&view.output);
            Ok(())
        }
    }
}

fn beginner_probe_id(entity: &Entity, probes: &[ProbeDescriptor]) -> Option<&'static str> {
    let preferred = match entity.kind() {
        EntityKind::Port => &[
            "connectivity.reachability",
            "web.http_probe",
            "web.tls_cert",
        ][..],
        EntityKind::Url => &["web.http_probe", "web.tls_cert", "connectivity.ping"][..],
        EntityKind::Domain | EntityKind::Host | EntityKind::Ip => {
            &["connectivity.ping", "dns.lookup", "web.http_probe"][..]
        }
        _ => &["core.describe_entity"][..],
    };

    preferred.iter().copied().find(|id| {
        probes
            .iter()
            .any(|probe| probe.id == *id && probe.status == ProbeStatus::Ready)
    })
}

fn print_beginner_check(
    target: &str,
    entity: &Entity,
    descriptor: &ProbeDescriptor,
    output: &ProbeOutput,
) {
    println!("{}", paint("SonarNwork quick check", Tone::Heading));
    println!("{} {target}", paint("Target :", Tone::Label));
    println!("{} {}", paint("Entity :", Tone::Label), entity.id());
    println!(
        "{} {} ({})",
        paint("Tool   :", Tone::Label),
        descriptor.name,
        descriptor.id
    );
    println!();
    println!(
        "{} {}",
        paint("Result :", Tone::Label),
        paint(
            output
                .summary
                .as_deref()
                .unwrap_or("Check completed. See details below."),
            output_tone(output)
        )
    );
    print_summary_rows(output);
    println!();
    println!("{}", paint("Next commands", Tone::Heading));
    for command in next_commands_for(target, entity) {
        println!("  {}", paint(command, Tone::Command));
    }
}

fn print_summary_rows(output: &ProbeOutput) {
    if output.summary_rows.is_empty() {
        return;
    }

    println!("{}", paint("Details", Tone::Heading));
    let label_width = output
        .summary_rows
        .iter()
        .map(|row| row.label.len())
        .max()
        .unwrap_or(0)
        .min(18);
    for row in &output.summary_rows {
        let label = format!("{:label_width$}", row.label);
        println!(
            "  {} {} {}",
            paint(label, Tone::Label),
            paint(":", Tone::Muted),
            row.value
        );
    }
}

fn print_probe_run(view: &ProbeRunView, options: OutputOptions) -> anyhow::Result<()> {
    match options.mode() {
        OutputMode::Json => print_json(view)?,
        OutputMode::Raw => print_raw_output(&view.output)?,
        OutputMode::Summary => {
            println!(
                "{}",
                paint(
                    view.output.summary.as_deref().unwrap_or("Probe completed."),
                    output_tone(&view.output)
                )
            );
            print_summary_rows(&view.output);
        }
    }

    ensure_probe_healthy(&view.output)
}

fn ensure_probe_healthy(output: &ProbeOutput) -> anyhow::Result<()> {
    let Some(exit_code) = output
        .raw
        .as_ref()
        .and_then(|raw| raw.get("exit_code"))
        .and_then(Value::as_i64)
    else {
        return Ok(());
    };

    if exit_code == 0 {
        Ok(())
    } else {
        Err(CliExitError::new(
            EXIT_UNHEALTHY,
            format!("probe completed unhealthy (raw command exit {exit_code})"),
        )
        .into())
    }
}

fn print_raw_output(output: &ProbeOutput) -> anyhow::Result<()> {
    let Some(raw) = output.raw.as_ref() else {
        println!("No raw output captured.");
        return Ok(());
    };

    if let Some(stdout) = raw.get("stdout").and_then(Value::as_str) {
        if !stdout.trim().is_empty() {
            println!("{stdout}");
        }
    }
    if let Some(stderr) = raw.get("stderr").and_then(Value::as_str) {
        if !stderr.trim().is_empty() {
            eprintln!("{stderr}");
        }
    }

    if raw.get("stdout").is_none() && raw.get("stderr").is_none() {
        print_json(raw)?;
    }

    Ok(())
}

fn next_commands_for(target: &str, entity: &Entity) -> Vec<String> {
    match entity.kind() {
        EntityKind::Ip => vec![
            format!("sonarnwork trace {target}"),
            format!("sonarnwork port {target} --port 443"),
            format!("sonarnwork probe run recon.whois_rdap {target}"),
        ],
        EntityKind::Domain | EntityKind::Host => vec![
            format!("sonarnwork dns {}", entity.stable_key()),
            format!("sonarnwork trace {}", entity.stable_key()),
            format!(
                "sonarnwork probe run web.http_probe {}",
                entity.stable_key()
            ),
        ],
        EntityKind::Port => {
            let port_command = match entity {
                Entity::Port(port) => format!("sonarnwork port {} --port {}", port.ip, port.port),
                _ => format!("sonarnwork port {target} --port 443"),
            };
            vec![
                port_command,
                format!("sonarnwork probe run web.http_probe {target}"),
                format!("sonarnwork probe run web.tls_cert {target}"),
            ]
        }
        EntityKind::Url => vec![
            format!("sonarnwork probe run web.tls_cert {target}"),
            format!("sonarnwork probe run recon.whois_rdap {target}"),
        ],
        _ => vec!["sonarnwork probe list".into()],
    }
}

fn print_probe_list(probes: &[ProbeDescriptor]) {
    println!("{}", paint("Available probes", Tone::Heading));
    for probe in probes {
        let status_tone = match probe.status {
            ProbeStatus::Ready => Tone::Success,
            ProbeStatus::Planned => Tone::Warning,
            ProbeStatus::Disabled => Tone::Muted,
        };
        let probe_id = format!("{:28}", probe.id);
        let category = format!("{:16}", format!("{:?}", probe.category));
        println!(
            "{} {} {} {:?} {}",
            paint("•", Tone::Brand),
            paint(probe_id, Tone::Command),
            paint(category, Tone::Muted),
            probe.risk,
            paint(format!("{:?}", probe.status), status_tone)
        );
        println!("  {}", paint(&probe.description, Tone::Muted));
    }
}

fn print_guide() {
    println!("{}", paint("SonarNwork beginner guide", Tone::Heading));
    println!();
    println!("{}", paint("Start here", Tone::Brand));
    println!("  sonarnwork check example.com");
    println!("  sonarnwork check https://example.com");
    println!("  sonarnwork check 1.1.1.1:443");
    println!();
    println!("{}", paint("Useful next steps", Tone::Brand));
    println!("  sonarnwork probe list");
    println!("  sonarnwork ping 1.1.1.1 --count 4 --timeout 1000");
    println!("  sonarnwork trace 1.1.1.1 --tcp --port 443");
    println!("  sonarnwork dns example.com --record A");
    println!("  sonarnwork port 127.0.0.1 --port 443");
    println!("  sonarnwork scanner run nmap 103.29.26.0/24 --profile version --ports all");
    println!("  sonarnwork myip");
    println!();
    println!("{}", paint("Output modes", Tone::Brand));
    println!("  --summary  filtered result for humans (default)");
    println!("  --raw      raw command output");
    println!("  --json     full structured output");
}

fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value).context("serialize JSON output")?;
    println!("{json}");
    Ok(())
}
