use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::Value;
use sonar_core::{
    command_target, ActionClass, AppCore, DnsLookupProfile, Entity, EntityKind, PingProfile,
    PivotGraph, PortCheckProfile, ProbeDescriptor, ProbeOutput, ProbeStatus, ProbeTarget,
    TraceProfile, TraceProtocol,
};
use sonar_tools::ToolCatalog;

#[derive(Debug, Parser)]
#[command(name = "sonarnwork")]
#[command(version)]
#[command(about = "SonarNwork CLI shell backed by sonar-core")]
#[command(
    after_help = "Beginner examples:\n  sonarnwork check example.com\n  sonarnwork ping 1.1.1.1 --count 4 --timeout 1000\n  sonarnwork trace 1.1.1.1 --tcp --port 443\n  sonarnwork dns example.com --record A\n  sonarnwork myip"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
    let core = AppCore::active_network_scan();

    match cli.command {
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

#[derive(Serialize)]
struct ProbeRunView {
    descriptor: ProbeDescriptor,
    output: ProbeOutput,
    graph: PivotGraph,
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
