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
use sonar_tools::ToolCatalog;
use std::io::{self, Write};

#[derive(Debug, Parser)]
#[command(name = "sonarnwork")]
#[command(version)]
#[command(about = "SonarNwork CLI shell backed by sonar-core")]
#[command(
    after_help = "Examples:\n  sonarnwork check example.com\n  sonarnwork ping 1.1.1.1 --count 4 --timeout 1000\n  sonarnwork trace 1.1.1.1 --tcp --port 443\n  sonarnwork dns example.com --record A\n  sonarnwork scanner run nmap 103.29.26.0/24 --profile version --ports all --yes\n  sonarnwork myip"
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
        /// Confirm that you own or are authorized to scan this target.
        #[arg(long, alias = "i-am-authorized")]
        yes: bool,
        #[command(flatten)]
        output: OutputOptions,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScannerToolArg {
    Nmap,
    Nuclei,
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
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        return run_shell().await;
    };

    let core = AppCore::active_network_scan();
    run_command(command, &core).await
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
                println!("{} {}", info.name, info.version);
                println!("{}", info.contract);
            }
        }
        Command::Entity { command } => match command {
            EntityCommand::Parse { target, json } => {
                let entity = core.parse_entity(&target)?;
                if json {
                    print_json(&entity)?;
                } else {
                    println!("{} -> {}", target, entity.id());
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
                yes,
                output,
            } => {
                run_scanner_command(tool.into(), profile, ports, target, yes, output)?;
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
        },
    }

    Ok(())
}

async fn run_shell() -> anyhow::Result<()> {
    let core = AppCore::active_network_scan();
    print_shell_banner(&core);

    if let Ok(command) = std::env::var("SONARNWORK_SHELL_AUTORUN") {
        let command = command.trim();
        if !command.is_empty() {
            println!("sonarnwork > {command}");
            run_shell_command(command, &core).await;
            println!();
        }
    }

    loop {
        print!("sonarnwork > ");
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
                eprintln!("error: {err:#}");
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

    if !args
        .first()
        .is_some_and(|arg| arg.eq_ignore_ascii_case("sonarnwork"))
    {
        args.insert(0, "sonarnwork".into());
    }

    Cli::try_parse_from(args).map(|cli| cli.command)
}

fn split_shell_line(line: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars();
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
                    args.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }

    if let Some(open_quote) = quote {
        return Err(format!("unterminated {open_quote} quote"));
    }

    if !current.is_empty() {
        args.push(current);
    }

    Ok(args)
}

fn print_shell_banner(core: &AppCore) {
    let info = core.app_info();

    println!(
        r#"
  ____   ___  _   _    _    ____  _   ___        _____  ____  _  __
 / ___| / _ \| \ | |  / \  |  _ \| \ | \ \      / / _ \|  _ \| |/ /
 \___ \| | | |  \| | / _ \ | |_) |  \| |\ \ /\ / / | | | |_) | ' /
  ___) | |_| | |\  |/ ___ \|  _ <| |\  | \ V  V /| |_| |  _ <| . \
 |____/ \___/|_| \_/_/   \_\_| \_\_| \_|  \_/\_/  \___/|_| \_\_|\_\
"#
    );
    println!("SonarNwork CLI Shell  {}", info.version);
    println!("{}", info.contract);
    println!();
    println!("Mode   : interactive operator console");
    println!("Scope  : local checks, DNS, trace, ports, probes, and scanners");
    println!("Input  : type commands below without the program name");
    println!("Try    : help | probe list | myip | scanner run nmap 103.29.26.0/24 --profile version --ports all --yes | exit");
    println!();
}

fn print_shell_help() {
    println!("Interactive commands:");
    println!("  help                         show this shell help");
    println!("  clear                        redraw the banner");
    println!("  exit                         close the shell");
    println!();
    println!("Run SonarNwork commands directly:");
    println!("  check example.com");
    println!("  ping 1.1.1.1 --count 4 --timeout 1000");
    println!("  trace 1.1.1.1 --tcp --port 443");
    println!("  dns example.com --record A");
    println!("  probe list");
    println!("  probe run core.describe_entity 1.1.1.1");
    println!("  scanner run nmap 103.29.26.0/24 --profile version --ports all --yes");
    println!("  myip");
    println!();
    println!("Command help still works:");
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
    yes: bool,
    output_options: OutputOptions,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        yes,
        "confirm that you own or are authorized to scan this target with --yes"
    );

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
        anyhow::bail!("scanner exited with {}", output.status);
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
        ExternalScannerKind::Nmap => Ok(parse_scanner_ports(ports.as_deref().unwrap_or("top"))?),
        ExternalScannerKind::Nuclei => {
            anyhow::ensure!(ports.is_none(), "--ports only applies to nmap");
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
    println!("SonarNwork quick check");
    println!("Target : {target}");
    println!("Entity : {}", entity.id());
    println!("Tool   : {} ({})", descriptor.name, descriptor.id);
    println!();
    println!(
        "Result : {}",
        output
            .summary
            .as_deref()
            .unwrap_or("Check completed. See details below.")
    );
    print_summary_rows(output);
    println!();
    println!("Next commands:");
    for command in next_commands_for(target, entity) {
        println!("  {command}");
    }
}

fn print_summary_rows(output: &ProbeOutput) {
    if output.summary_rows.is_empty() {
        return;
    }

    println!("Details:");
    let label_width = output
        .summary_rows
        .iter()
        .map(|row| row.label.len())
        .max()
        .unwrap_or(0)
        .min(18);
    for row in &output.summary_rows {
        println!("  {:label_width$} : {}", row.label, row.value);
    }
}

fn print_probe_run(view: &ProbeRunView, options: OutputOptions) -> anyhow::Result<()> {
    match options.mode() {
        OutputMode::Json => print_json(view),
        OutputMode::Raw => print_raw_output(&view.output),
        OutputMode::Summary => {
            println!(
                "{}",
                view.output.summary.as_deref().unwrap_or("Probe completed.")
            );
            print_summary_rows(&view.output);
            Ok(())
        }
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
    println!("Available probes:");
    for probe in probes {
        println!(
            "- {:28} {:16} {:?} {:?}",
            probe.id,
            format!("{:?}", probe.category),
            probe.risk,
            probe.status
        );
        println!("  {}", probe.description);
    }
}

fn print_guide() {
    println!("SonarNwork beginner guide");
    println!();
    println!("Start here:");
    println!("  sonarnwork check example.com");
    println!("  sonarnwork check https://example.com");
    println!("  sonarnwork check 1.1.1.1:443");
    println!();
    println!("Useful next steps:");
    println!("  sonarnwork probe list");
    println!("  sonarnwork ping 1.1.1.1 --count 4 --timeout 1000");
    println!("  sonarnwork trace 1.1.1.1 --tcp --port 443");
    println!("  sonarnwork dns example.com --record A");
    println!("  sonarnwork port 127.0.0.1 --port 443");
    println!("  sonarnwork scanner run nmap 103.29.26.0/24 --profile version --ports all --yes");
    println!("  sonarnwork myip");
    println!();
    println!("Output modes:");
    println!("  --summary  filtered result for humans (default)");
    println!("  --raw      raw command output");
    println!("  --json     full structured output");
}

fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value).context("serialize JSON output")?;
    println!("{json}");
    Ok(())
}
