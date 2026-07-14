use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sonar_os::{FirewallState, L4Proto as OsL4Proto, OsNet, SystemOsNet};
use uuid::Uuid;

use crate::entity::{Entity, EntityId, EntityKind};
use crate::error::{Result, SonarError};
use crate::graph::{Confidence, PivotGraph, RelationKind};
use crate::scope::{ActionClass, ScopeGuard};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeDescriptor {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: ProbeCategory,
    pub status: ProbeStatus,
    pub risk: ProbeRisk,
    pub requirements: Vec<ProbeRequirement>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeCategory {
    Core,
    Connectivity,
    LocalNetwork,
    PublicExposure,
    Dns,
    Recon,
    WebTls,
    Intelligence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Ready,
    Planned,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeRisk {
    Passive,
    SafeActive,
    Intrusive,
    Dangerous,
}

impl ProbeRisk {
    pub fn action_class(self) -> ActionClass {
        match self {
            Self::Passive => ActionClass::PassiveLookup,
            Self::SafeActive => ActionClass::ActiveProbe,
            Self::Intrusive | Self::Dangerous => ActionClass::IntrusiveScan,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ProbeRequirement {
    Network,
    RawSocket,
    Admin,
    ExternalTool(String),
    ApiKey(String),
}

#[derive(Clone, Debug)]
pub struct ProbeCtx {
    pub run_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub scope: ScopeGuard,
}

impl ProbeCtx {
    pub fn new(scope: ScopeGuard) -> Self {
        Self {
            run_id: Uuid::new_v4(),
            started_at: Utc::now(),
            scope,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProbeOutput {
    pub summary: Option<String>,
    pub summary_rows: Vec<SummaryRow>,
    pub findings: Vec<Finding>,
    pub discovered: Vec<DiscoveredEntity>,
    pub edges: Vec<EdgeDraft>,
    pub artifacts: Vec<Artifact>,
    pub warnings: Vec<ProbeWarning>,
    pub raw: Option<Value>,
}

impl ProbeOutput {
    pub fn with_summary(summary: impl Into<String>) -> Self {
        Self {
            summary: Some(summary.into()),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryRow {
    pub label: String,
    pub value: String,
}

impl SummaryRow {
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub evidence: Option<Value>,
    pub entities: Vec<EntityId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredEntity {
    pub entity: Entity,
    pub relation: RelationKind,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EdgeDraft {
    pub from: Option<EntityId>,
    pub to: Entity,
    pub relation: RelationKind,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Artifact {
    pub kind: ArtifactKind,
    pub label: String,
    pub mime_type: Option<String>,
    pub content_ref: String,
    pub sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    RawOutput,
    Json,
    Xml,
    Text,
    Screenshot,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeWarning {
    pub code: String,
    pub message: String,
}

#[async_trait]
pub trait Probe: Send + Sync {
    fn descriptor(&self) -> ProbeDescriptor;
    fn applies_to(&self, entity: &Entity) -> bool;
    async fn run(&self, entity: &Entity, ctx: &ProbeCtx) -> Result<ProbeOutput>;
}

#[derive(Clone, Default)]
pub struct ProbeRegistry {
    probes: Vec<Arc<dyn Probe>>,
}

impl ProbeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<P>(&mut self, probe: P)
    where
        P: Probe + 'static,
    {
        self.probes.push(Arc::new(probe));
    }

    pub fn descriptors(&self) -> Vec<ProbeDescriptor> {
        self.probes.iter().map(|probe| probe.descriptor()).collect()
    }

    pub fn descriptors_for(&self, entity: &Entity) -> Vec<ProbeDescriptor> {
        self.probes
            .iter()
            .filter(|probe| probe.applies_to(entity))
            .map(|probe| probe.descriptor())
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Probe>> {
        self.probes
            .iter()
            .find(|probe| probe.descriptor().id == id)
            .cloned()
    }

    pub fn descriptor(&self, id: &str) -> Option<ProbeDescriptor> {
        self.get(id).map(|probe| probe.descriptor())
    }

    pub async fn run(
        &self,
        probe_id: &str,
        entity: &Entity,
        ctx: &ProbeCtx,
    ) -> Result<(ProbeDescriptor, ProbeOutput, PivotGraph)> {
        let probe = self
            .get(probe_id)
            .ok_or_else(|| SonarError::ProbeNotFound(probe_id.to_string()))?;
        let descriptor = probe.descriptor();

        if !probe.applies_to(entity) {
            return Err(SonarError::ProbeDoesNotApply {
                probe_id: descriptor.id,
                entity_id: entity.id().to_string(),
            });
        }

        if descriptor.status != ProbeStatus::Ready {
            return Err(SonarError::ProbeNotReady {
                probe_id: descriptor.id,
                status: format!("{:?}", descriptor.status).to_ascii_lowercase(),
            });
        }

        ctx.scope
            .ensure_allowed(entity, descriptor.risk.action_class())?;

        let output = probe.run(entity, ctx).await?;
        let mut graph = PivotGraph::new();
        graph.apply_probe_output(entity, &descriptor, ctx, &output);

        Ok((descriptor, output, graph))
    }
}

pub struct DescribeEntityProbe;

#[async_trait]
impl Probe for DescribeEntityProbe {
    fn descriptor(&self) -> ProbeDescriptor {
        ProbeDescriptor {
            id: "core.describe_entity".into(),
            name: "Describe entity".into(),
            description: "Returns the normalized entity identity without touching the network."
                .into(),
            category: ProbeCategory::Core,
            status: ProbeStatus::Ready,
            risk: ProbeRisk::Passive,
            requirements: vec![],
        }
    }

    fn applies_to(&self, _entity: &Entity) -> bool {
        true
    }

    async fn run(&self, entity: &Entity, _ctx: &ProbeCtx) -> Result<ProbeOutput> {
        Ok(ProbeOutput {
            summary: Some(format!(
                "{} normalized as {}",
                entity.kind().as_str(),
                entity.id()
            )),
            summary_rows: compact_summary_rows([
                ("Type", entity.kind().as_str().to_string()),
                ("Entity", entity.id().to_string()),
            ]),
            findings: vec![Finding {
                title: "Entity normalized".into(),
                severity: Severity::Info,
                description: "The target was parsed into a typed SonarNwork entity.".into(),
                evidence: Some(serde_json::to_value(entity).expect("entity serializes")),
                entities: vec![entity.id()],
            }],
            ..ProbeOutput::default()
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum OsCommandKind {
    Ping,
    Traceroute,
    FastTrace,
    Mtr,
    PathMtu,
    RouteCheck,
    LocalNetworkState,
    ListeningPorts,
    DnsLookup,
    DnsLeakCheck,
    PublicPortCheck,
    EgressDns,
    WhoisRdap,
    HttpProbe,
    TlsCert,
}

pub struct OsCommandProbe {
    descriptor: ProbeDescriptor,
    entity_kinds: Vec<EntityKind>,
    kind: OsCommandKind,
}

impl OsCommandProbe {
    // Keep probe registration declarative at the call site: these arguments map
    // one-to-one to ProbeDescriptor plus the command-specific routing fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &str,
        name: &str,
        description: &str,
        category: ProbeCategory,
        risk: ProbeRisk,
        requirements: Vec<ProbeRequirement>,
        entity_kinds: Vec<EntityKind>,
        kind: OsCommandKind,
    ) -> Self {
        Self::new_with_status(
            id,
            name,
            description,
            category,
            ProbeStatus::Ready,
            risk,
            requirements,
            entity_kinds,
            kind,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_status(
        id: &str,
        name: &str,
        description: &str,
        category: ProbeCategory,
        status: ProbeStatus,
        risk: ProbeRisk,
        requirements: Vec<ProbeRequirement>,
        entity_kinds: Vec<EntityKind>,
        kind: OsCommandKind,
    ) -> Self {
        Self {
            descriptor: ProbeDescriptor {
                id: id.into(),
                name: name.into(),
                description: description.into(),
                category,
                status,
                risk,
                requirements,
            },
            entity_kinds,
            kind,
        }
    }

    fn invocation(&self, entity: &Entity) -> CommandInvocation {
        command_invocation_for_kind(self.kind, entity)
    }
}

#[async_trait]
impl Probe for OsCommandProbe {
    fn descriptor(&self) -> ProbeDescriptor {
        self.descriptor.clone()
    }

    fn applies_to(&self, entity: &Entity) -> bool {
        self.entity_kinds.contains(&entity.kind())
    }

    async fn run(&self, entity: &Entity, _ctx: &ProbeCtx) -> Result<ProbeOutput> {
        let invocation = self.invocation(entity);
        run_os_command(&self.descriptor, invocation)
    }
}

pub struct ReachabilityProbe {
    entity_kinds: Vec<EntityKind>,
}

impl ReachabilityProbe {
    pub fn new(entity_kinds: Vec<EntityKind>) -> Self {
        Self { entity_kinds }
    }
}

#[async_trait]
impl Probe for ReachabilityProbe {
    fn descriptor(&self) -> ProbeDescriptor {
        ProbeDescriptor {
            id: "connectivity.reachability".into(),
            name: "Reachability".into(),
            description: "Check whether a host:port can actually be reached from this machine."
                .into(),
            category: ProbeCategory::Connectivity,
            status: ProbeStatus::Ready,
            risk: ProbeRisk::SafeActive,
            requirements: vec![ProbeRequirement::Network],
        }
    }

    fn applies_to(&self, entity: &Entity) -> bool {
        self.entity_kinds.contains(&entity.kind())
    }

    async fn run(&self, entity: &Entity, _ctx: &ProbeCtx) -> Result<ProbeOutput> {
        let (host, port) = reachability_target(entity);
        run_tcp_reachability(&host, port, Duration::from_secs(3), vec![entity.id()])
    }
}

pub struct LocalNetworkStateProbe;

#[async_trait]
impl Probe for LocalNetworkStateProbe {
    fn descriptor(&self) -> ProbeDescriptor {
        ProbeDescriptor {
            id: "local.network_state".into(),
            name: "Local network state".into(),
            description:
                "List interfaces, addresses, gateways, default routes, and configured resolvers."
                    .into(),
            category: ProbeCategory::LocalNetwork,
            status: ProbeStatus::Ready,
            risk: ProbeRisk::Passive,
            requirements: vec![],
        }
    }

    fn applies_to(&self, entity: &Entity) -> bool {
        entity.kind() == EntityKind::LocalMachine
    }

    async fn run(&self, _entity: &Entity, _ctx: &ProbeCtx) -> Result<ProbeOutput> {
        let os = SystemOsNet::current();
        let interfaces = os
            .interfaces()
            .map_err(|err| SonarError::CommandFailed(err.to_string()))?;
        let resolvers = os
            .configured_resolvers()
            .map_err(|err| SonarError::CommandFailed(err.to_string()))?;
        let firewall = os.firewall_state().unwrap_or(FirewallState::Unknown);
        let local_ips = interfaces
            .iter()
            .flat_map(|iface| iface.ips.iter().map(ToString::to_string))
            .collect::<Vec<_>>();
        let gateways = interfaces
            .iter()
            .filter_map(|iface| iface.gateway.map(|gateway| gateway.to_string()))
            .collect::<Vec<_>>();
        let resolver_rows = resolvers
            .iter()
            .map(|resolver| resolver.address.to_string())
            .collect::<Vec<_>>();

        Ok(ProbeOutput {
            summary: Some("Local network state collected from the operating system.".into()),
            summary_rows: compact_summary_rows([
                ("Interface", interfaces.len().to_string()),
                ("Local IPs", summarize_list(&local_ips, 3)),
                ("Gateway", summarize_list(&gateways, 2)),
                ("DNS servers", summarize_list(&resolver_rows, 3)),
                ("Firewall", format!("{firewall:?}")),
            ]),
            findings: vec![Finding {
                title: "Local network state collected".into(),
                severity: Severity::Info,
                description:
                    "Interfaces, configured resolvers, and local firewall state were read from the OS."
                        .into(),
                evidence: None,
                entities: Vec::new(),
            }],
            raw: Some(json!({
                "interfaces": interfaces,
                "resolvers": resolvers,
                "firewall": firewall,
            })),
            ..ProbeOutput::default()
        })
    }
}

pub struct ListeningPortsProbe;

#[async_trait]
impl Probe for ListeningPortsProbe {
    fn descriptor(&self) -> ProbeDescriptor {
        ProbeDescriptor {
            id: "local.listening_ports".into(),
            name: "Listening ports".into(),
            description:
                "Show local listening sockets, bind addresses, process owners, and exposure hints."
                    .into(),
            category: ProbeCategory::LocalNetwork,
            status: ProbeStatus::Ready,
            risk: ProbeRisk::Passive,
            requirements: vec![],
        }
    }

    fn applies_to(&self, entity: &Entity) -> bool {
        entity.kind() == EntityKind::LocalMachine
    }

    async fn run(&self, _entity: &Entity, _ctx: &ProbeCtx) -> Result<ProbeOutput> {
        let sockets = SystemOsNet::current()
            .listening_sockets()
            .map_err(|err| SonarError::CommandFailed(err.to_string()))?;
        let public_binds = sockets
            .iter()
            .filter(|socket| socket.local_addr.is_unspecified())
            .count();
        let samples = sockets
            .iter()
            .take(3)
            .map(|socket| {
                format!(
                    "{}:{} {}{}",
                    socket.local_addr,
                    socket.local_port,
                    match socket.proto {
                        OsL4Proto::Tcp => "tcp",
                        OsL4Proto::Udp => "udp",
                    },
                    socket
                        .owning_pid
                        .map(|pid| format!(" pid {pid}"))
                        .unwrap_or_default()
                )
            })
            .collect::<Vec<_>>();

        Ok(ProbeOutput {
            summary: Some("Local listening sockets collected from the operating system.".into()),
            summary_rows: compact_summary_rows([
                ("Listeners", sockets.len().to_string()),
                ("Public binds", public_binds.to_string()),
                ("Summary", summarize_list(&samples, 3)),
            ]),
            findings: vec![Finding {
                title: "Local listening ports collected".into(),
                severity: if public_binds > 0 {
                    Severity::Low
                } else {
                    Severity::Info
                },
                description: format!(
                    "{} local listening sockets found; {} bind to all interfaces.",
                    sockets.len(),
                    public_binds
                ),
                evidence: None,
                entities: Vec::new(),
            }],
            raw: Some(json!({ "sockets": sockets })),
            ..ProbeOutput::default()
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandInvocation {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandInvocation {
    fn new<const N: usize>(program: &str, args: [&str; N]) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(String::from).collect(),
        }
    }

    pub fn from_parts(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingProfile {
    pub target: String,
    pub count: u16,
    pub timeout_ms: u64,
    pub packet_size: Option<u16>,
}

impl PingProfile {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            count: 4,
            timeout_ms: 1000,
            packet_size: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceProtocol {
    Icmp,
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceProfile {
    pub target: String,
    pub protocol: TraceProtocol,
    pub port: Option<u16>,
    pub max_hops: u8,
}

impl TraceProfile {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            protocol: TraceProtocol::Icmp,
            port: None,
            max_hops: 30,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsLookupProfile {
    pub target: String,
    pub record: String,
    pub server: Option<String>,
}

impl DnsLookupProfile {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            record: "A".into(),
            server: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortCheckProfile {
    pub host: String,
    pub port: u16,
    pub timeout_ms: u64,
}

impl PortCheckProfile {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            timeout_ms: 3000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpProbeProfile {
    pub url: String,
    pub max_redirects: u8,
    pub timeout_secs: u64,
}

impl HttpProbeProfile {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            max_redirects: 5,
            timeout_secs: 15,
        }
    }
}

pub fn ping_invocation(profile: &PingProfile) -> CommandInvocation {
    if cfg!(target_os = "windows") {
        let mut args = vec![
            "-n".to_string(),
            profile.count.to_string(),
            "-w".to_string(),
            profile.timeout_ms.to_string(),
        ];
        if let Some(size) = profile.packet_size {
            args.push("-l".into());
            args.push(size.to_string());
        }
        args.push(profile.target.clone());
        CommandInvocation::from_parts("ping", args)
    } else {
        let mut args = vec!["-c".to_string(), profile.count.to_string()];
        if let Some(size) = profile.packet_size {
            args.push("-s".into());
            args.push(size.to_string());
        }
        args.push(profile.target.clone());
        CommandInvocation::from_parts("ping", args)
    }
}

pub fn trace_invocation(profile: &TraceProfile) -> CommandInvocation {
    if cfg!(target_os = "windows") {
        match profile.protocol {
            TraceProtocol::Tcp => CommandInvocation::from_parts(
                "powershell",
                [
                    "-NoProfile".to_string(),
                    "-ExecutionPolicy".into(),
                    "Bypass".into(),
                    "-Command".into(),
                    windows_tcp_trace_script(
                        &profile.target,
                        profile.port.unwrap_or(443),
                        profile.max_hops,
                    ),
                ],
            ),
            TraceProtocol::Icmp | TraceProtocol::Udp => CommandInvocation::from_parts(
                "tracert",
                [
                    "-d".to_string(),
                    "-h".into(),
                    profile.max_hops.to_string(),
                    profile.target.clone(),
                ],
            ),
        }
    } else {
        let mut args = vec!["-n".to_string(), "-m".into(), profile.max_hops.to_string()];
        match profile.protocol {
            TraceProtocol::Tcp => {
                args.push("-T".into());
                if let Some(port) = profile.port {
                    args.push("-p".into());
                    args.push(port.to_string());
                }
            }
            TraceProtocol::Udp => {
                if let Some(port) = profile.port {
                    args.push("-p".into());
                    args.push(port.to_string());
                }
            }
            TraceProtocol::Icmp => {}
        }
        args.push(profile.target.clone());
        CommandInvocation::from_parts("traceroute", args)
    }
}

pub fn dns_lookup_invocation(profile: &DnsLookupProfile) -> CommandInvocation {
    let mut args = vec![format!("-type={}", profile.record.to_ascii_uppercase())];
    args.push(profile.target.clone());
    if let Some(server) = profile
        .server
        .as_ref()
        .filter(|server| !server.trim().is_empty())
    {
        args.push(server.clone());
    }
    CommandInvocation::from_parts("nslookup", args)
}

pub fn run_command_invocation(
    descriptor: &ProbeDescriptor,
    invocation: CommandInvocation,
) -> Result<ProbeOutput> {
    run_os_command(descriptor, invocation)
}

pub fn run_port_check_profile(profile: &PortCheckProfile) -> Result<ProbeOutput> {
    run_tcp_reachability(
        &profile.host,
        profile.port,
        Duration::from_millis(profile.timeout_ms),
        Vec::new(),
    )
}

pub fn command_invocation_for_probe(probe_id: &str, entity: &Entity) -> Option<CommandInvocation> {
    let kind = match probe_id {
        "connectivity.ping" => OsCommandKind::Ping,
        "connectivity.traceroute" => OsCommandKind::Traceroute,
        "connectivity.fast_trace" => OsCommandKind::FastTrace,
        "connectivity.mtr" => OsCommandKind::Mtr,
        "connectivity.path_mtu" => OsCommandKind::PathMtu,
        "connectivity.route_check" => OsCommandKind::RouteCheck,
        "local.network_state" => OsCommandKind::LocalNetworkState,
        "local.listening_ports" => OsCommandKind::ListeningPorts,
        "dns.lookup" => OsCommandKind::DnsLookup,
        "dns.leak_check" => OsCommandKind::DnsLeakCheck,
        "public.port_check" => return None,
        "public.egress_check" => OsCommandKind::EgressDns,
        "recon.whois_rdap" => OsCommandKind::WhoisRdap,
        "web.http_probe" => OsCommandKind::HttpProbe,
        "web.tls_cert" => OsCommandKind::TlsCert,
        _ => return None,
    };

    Some(command_invocation_for_kind(kind, entity))
}

pub fn command_target(entity: &Entity) -> String {
    target_for_command(entity)
}

fn command_invocation_for_kind(kind: OsCommandKind, entity: &Entity) -> CommandInvocation {
    let target = target_for_command(entity);

    match kind {
        OsCommandKind::Ping => {
            if cfg!(target_os = "windows") {
                CommandInvocation::new("ping", ["-n", "4", "-w", "1000", &target])
            } else {
                CommandInvocation::new("ping", ["-c", "4", &target])
            }
        }
        OsCommandKind::Traceroute => {
            if cfg!(target_os = "windows") {
                CommandInvocation::new("tracert", ["-d", "-h", "30", &target])
            } else {
                CommandInvocation::new("traceroute", ["-n", "-m", "30", &target])
            }
        }
        OsCommandKind::FastTrace => {
            if cfg!(target_os = "windows") {
                CommandInvocation::new("tracert", ["-d", "-h", "15", &target])
            } else {
                CommandInvocation::new("traceroute", ["-n", "-m", "15", "-q", "1", &target])
            }
        }
        OsCommandKind::Mtr => {
            if cfg!(target_os = "windows") {
                CommandInvocation::new("pathping", ["-n", "-q", "10", "-w", "1000", &target])
            } else {
                CommandInvocation::new("mtr", ["-rwzc", "10", &target])
            }
        }
        OsCommandKind::PathMtu => {
            if cfg!(target_os = "windows") {
                CommandInvocation::new(
                    "powershell",
                    [
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        &windows_path_mtu_script(&target),
                    ],
                )
            } else {
                CommandInvocation::new("sh", ["-c", &unix_path_mtu_script(&target)])
            }
        }
        OsCommandKind::RouteCheck => {
            if cfg!(target_os = "windows") {
                CommandInvocation::new("route", ["PRINT"])
            } else {
                CommandInvocation::new("ip", ["route"])
            }
        }
        OsCommandKind::LocalNetworkState => {
            if cfg!(target_os = "windows") {
                CommandInvocation::new("ipconfig", ["/all"])
            } else {
                CommandInvocation::new("ip", ["addr"])
            }
        }
        OsCommandKind::ListeningPorts => {
            if cfg!(target_os = "windows") {
                CommandInvocation::new("netstat", ["-ano"])
            } else {
                CommandInvocation::new("ss", ["-tulpen"])
            }
        }
        OsCommandKind::DnsLookup => CommandInvocation::new("nslookup", [&target]),
        OsCommandKind::DnsLeakCheck => {
            if cfg!(target_os = "windows") {
                CommandInvocation::new(
                    "powershell",
                    [
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        &windows_dns_leak_script(),
                    ],
                )
            } else {
                CommandInvocation::new("sh", ["-c", &unix_dns_leak_script()])
            }
        }
        OsCommandKind::PublicPortCheck => {
            let (host, port) = port_check_target(entity);
            if cfg!(target_os = "windows") {
                CommandInvocation::new(
                    "powershell",
                    [
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        &windows_public_port_script(&host, port),
                    ],
                )
            } else {
                CommandInvocation::new("sh", ["-c", &unix_public_port_script(&host, port)])
            }
        }
        OsCommandKind::EgressDns => {
            if cfg!(target_os = "windows") {
                CommandInvocation::new(
                    "powershell",
                    [
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        &windows_egress_dns_script(),
                    ],
                )
            } else {
                CommandInvocation::new("sh", ["-c", &unix_egress_dns_script()])
            }
        }
        OsCommandKind::WhoisRdap => {
            let target = target_for_command(entity);
            let rdap_kind = rdap_kind(entity);
            if cfg!(target_os = "windows") {
                CommandInvocation::new(
                    "powershell",
                    [
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        &windows_rdap_script(&target, rdap_kind),
                    ],
                )
            } else {
                CommandInvocation::new("sh", ["-c", &unix_rdap_script(&target, rdap_kind)])
            }
        }
        OsCommandKind::HttpProbe => {
            let url = http_probe_url(entity);
            if cfg!(target_os = "windows") {
                CommandInvocation::new(
                    "powershell",
                    [
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        &windows_http_probe_script(&url),
                    ],
                )
            } else {
                CommandInvocation::new("sh", ["-c", &unix_http_probe_script(&url)])
            }
        }
        OsCommandKind::TlsCert => {
            let (host, port) = tls_target(entity);
            if cfg!(target_os = "windows") {
                CommandInvocation::new(
                    "powershell",
                    [
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        &windows_tls_cert_script(&host, port),
                    ],
                )
            } else {
                CommandInvocation::new("sh", ["-c", &unix_tls_cert_script(&host, port)])
            }
        }
    }
}

fn windows_dns_leak_script() -> String {
    r#"
$ErrorActionPreference = 'Continue'
Write-Output '== Configured DNS servers =='
try {
  Get-DnsClientServerAddress |
    Where-Object { $_.ServerAddresses.Count -gt 0 } |
    ForEach-Object {
      "$($_.InterfaceAlias) [$($_.AddressFamily)] -> $($_.ServerAddresses -join ', ')"
    }
} catch {
  Write-Output "DNS config error: $($_.Exception.Message)"
}

Write-Output ''
Write-Output '== Observed recursive DNS path =='
$checks = @(
  @{ Name = 'whoami.cloudflare'; Server = '1.1.1.1'; Type = 'TXT' },
  @{ Name = 'o-o.myaddr.l.google.com'; Server = 'ns1.google.com'; Type = 'TXT' }
)
foreach ($check in $checks) {
  try {
    $answers = Resolve-DnsName -Name $check.Name -Type $check.Type -Server $check.Server -ErrorAction Stop
    $answers | ForEach-Object {
      if ($_.Strings) {
        "$($check.Name) via $($check.Server) -> $($_.Strings -join ' ')"
      } elseif ($_.IPAddress) {
        "$($check.Name) via $($check.Server) -> $($_.IPAddress)"
      }
    }
  } catch {
    Write-Output "$($check.Name) via $($check.Server) -> ERROR: $($_.Exception.Message)"
  }
}
"#
    .trim()
    .to_string()
}

fn unix_dns_leak_script() -> String {
    r#"
echo '== Configured DNS servers =='
cat /etc/resolv.conf 2>/dev/null || true
echo ''
echo '== Observed recursive DNS path =='
if command -v dig >/dev/null 2>&1; then
  printf 'whoami.cloudflare @1.1.1.1 -> '
  dig +short TXT whoami.cloudflare @1.1.1.1
  printf 'o-o.myaddr.l.google.com @ns1.google.com -> '
  dig +short TXT o-o.myaddr.l.google.com @ns1.google.com
else
  echo 'dig not found'
fi
"#
    .trim()
    .to_string()
}

fn windows_public_port_script(host: &str, port: u16) -> String {
    format!(
        r#"
$ErrorActionPreference = 'Continue'
$TargetHost = {host}
$TargetPort = {port}
Write-Output "== Public port reachability =="
Write-Output "Target: $TargetHost`:$TargetPort"
try {{
  $result = Test-NetConnection -ComputerName $TargetHost -Port $TargetPort -InformationLevel Detailed
  "ResolvedAddresses: $($result.ResolvedAddresses -join ', ')"
  "RemoteAddress: $($result.RemoteAddress)"
  "RemotePort: $($result.RemotePort)"
  "TcpTestSucceeded: $($result.TcpTestSucceeded)"
  "InterfaceAlias: $($result.InterfaceAlias)"
  "SourceAddress: $($result.SourceAddress)"
  "PingSucceeded: $($result.PingSucceeded)"
}} catch {{
  Write-Output "Test-NetConnection error: $($_.Exception.Message)"
}}

Write-Output ''
Write-Output '== Local listeners on same port =='
try {{
  Get-NetTCPConnection -LocalPort $TargetPort -State Listen -ErrorAction Stop |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Format-Table -AutoSize | Out-String
}} catch {{
  Write-Output "No local listener found or access denied: $($_.Exception.Message)"
}}
"#,
        host = quote_powershell(host),
        port = port
    )
    .trim()
    .to_string()
}

fn unix_public_port_script(host: &str, port: u16) -> String {
    format!(
        r#"
host={host}
port={port}
echo '== Public port reachability =='
printf 'Target: %s:%s\n' "$host" "$port"
if command -v nc >/dev/null 2>&1; then
  nc -vz -w 5 "$host" "$port"
else
  timeout 5 sh -c "cat < /dev/null > /dev/tcp/$host/$port" && echo 'tcp connect succeeded' || echo 'tcp connect failed'
fi
echo ''
echo '== Route used =='
ip route get "$host" 2>/dev/null || true
"#,
        host = quote_shell(host),
        port = port
    )
    .trim()
    .to_string()
}

fn windows_tcp_trace_script(target: &str, port: u16, max_hops: u8) -> String {
    format!(
        r#"
$ErrorActionPreference = 'Continue'
$Target = {target}
$Port = {port}
$MaxHops = {max_hops}
Write-Output '== TCP trace =='
Write-Output "Target: $Target`:$Port"
Write-Output "MaxHops: $MaxHops"
try {{
  $result = Test-NetConnection -ComputerName $Target -Port $Port -TraceRoute -InformationLevel Detailed
  "RemoteAddress: $($result.RemoteAddress)"
  "RemotePort: $($result.RemotePort)"
  "TcpTestSucceeded: $($result.TcpTestSucceeded)"
  if ($result.TraceRoute) {{
    Write-Output ''
    Write-Output 'TraceRoute:'
    $i = 1
    $result.TraceRoute | Select-Object -First $MaxHops | ForEach-Object {{
      "$i  $_"
      $i += 1
    }}
  }}
}} catch {{
  Write-Output "TCP trace error: $($_.Exception.Message)"
}}
"#,
        target = quote_powershell(target),
        port = port,
        max_hops = max_hops
    )
    .trim()
    .to_string()
}

fn windows_path_mtu_script(target: &str) -> String {
    format!(
        r#"
$ErrorActionPreference = 'Continue'
$Target = {target}
Write-Output '== Path MTU probe =='
Write-Output "Target: $Target"
$sizes = @(1472, 1464, 1452, 1432, 1400, 1360, 1280, 1200, 1000, 576)
$best = $null
foreach ($size in $sizes) {{
  Write-Output "Try payload: $size"
  $output = ping -n 1 -f -l $size -w 1000 $Target 2>&1
  $output | ForEach-Object {{ $_ }}
  if (($LASTEXITCODE -eq 0) -and (($output -join "`n") -match 'Reply from')) {{
    $best = $size + 28
    break
  }}
}}
if ($best) {{
  Write-Output "Estimated MTU: $best"
}} else {{
  Write-Output 'Estimated MTU: unknown'
}}
"#,
        target = quote_powershell(target)
    )
    .trim()
    .to_string()
}

fn unix_path_mtu_script(target: &str) -> String {
    format!(
        r#"
target={target}
echo '== Path MTU probe =='
printf 'Target: %s\n' "$target"
for size in 1472 1464 1452 1432 1400 1360 1280 1200 1000 576; do
  printf 'Try payload: %s\n' "$size"
  if ping -c 1 -M do -s "$size" "$target"; then
    mtu=$((size + 28))
    printf 'Estimated MTU: %s\n' "$mtu"
    exit 0
  fi
done
echo 'Estimated MTU: unknown'
"#,
        target = quote_shell(target)
    )
    .trim()
    .to_string()
}

fn windows_egress_dns_script() -> String {
    r#"
$ErrorActionPreference = 'Continue'
Write-Output '== Public egress IP =='
$endpoints = @(
  'https://api.ipify.org',
  'https://ifconfig.me/ip',
  'https://checkip.amazonaws.com'
)
foreach ($endpoint in $endpoints) {
  try {
    $value = (Invoke-RestMethod -UseBasicParsing -Uri $endpoint -TimeoutSec 8).ToString().Trim()
    if ($value) { Write-Output "$endpoint -> $value" }
  } catch {
    Write-Output "$endpoint -> ERROR: $($_.Exception.Message)"
  }
}

Write-Output ''
Write-Output '== Configured DNS servers =='
try {
  Get-DnsClientServerAddress |
    Where-Object { $_.ServerAddresses.Count -gt 0 } |
    ForEach-Object {
      "$($_.InterfaceAlias) [$($_.AddressFamily)] -> $($_.ServerAddresses -join ', ')"
    }
} catch {
  Write-Output "DNS config error: $($_.Exception.Message)"
}

Write-Output ''
Write-Output '== DNS path checks =='
$checks = @(
  @{ Name = 'whoami.cloudflare'; Server = '1.1.1.1'; Type = 'TXT' },
  @{ Name = 'o-o.myaddr.l.google.com'; Server = 'ns1.google.com'; Type = 'TXT' }
)
foreach ($check in $checks) {
  try {
    $answers = Resolve-DnsName -Name $check.Name -Type $check.Type -Server $check.Server -ErrorAction Stop
    $answers | ForEach-Object {
      if ($_.Strings) {
        "$($check.Name) via $($check.Server) -> $($_.Strings -join ' ')"
      } elseif ($_.IPAddress) {
        "$($check.Name) via $($check.Server) -> $($_.IPAddress)"
      }
    }
  } catch {
    Write-Output "$($check.Name) via $($check.Server) -> ERROR: $($_.Exception.Message)"
  }
}
"#
    .trim()
    .to_string()
}

fn unix_egress_dns_script() -> String {
    r#"
echo '== Public egress IP =='
for endpoint in https://api.ipify.org https://ifconfig.me/ip https://checkip.amazonaws.com; do
  value="$(curl -fsS --max-time 8 "$endpoint" 2>&1)"
  printf '%s -> %s\n' "$endpoint" "$value"
done
echo ''
echo '== Configured DNS servers =='
cat /etc/resolv.conf 2>/dev/null || true
echo ''
echo '== DNS path checks =='
if command -v dig >/dev/null 2>&1; then
  dig +short TXT whoami.cloudflare @1.1.1.1
  dig +short TXT o-o.myaddr.l.google.com @ns1.google.com
else
  echo 'dig not found'
fi
"#
    .trim()
    .to_string()
}

fn windows_rdap_script(target: &str, kind: &str) -> String {
    format!(
        r#"
$ErrorActionPreference = 'Continue'
$Target = {target}
$Kind = {kind}
$Uri = "https://rdap.org/$Kind/$Target"
Write-Output '== RDAP lookup =='
Write-Output "URI: $Uri"
try {{
  $data = Invoke-RestMethod -UseBasicParsing -Uri $Uri -TimeoutSec 15
  if ($data.objectClassName) {{ "ObjectClass: $($data.objectClassName)" }}
  if ($data.handle) {{ "Handle: $($data.handle)" }}
  if ($data.name) {{ "Name: $($data.name)" }}
  if ($data.ldhName) {{ "LDH name: $($data.ldhName)" }}
  if ($data.country) {{ "Country: $($data.country)" }}
  if ($data.events) {{
    Write-Output ''
    Write-Output 'Events:'
    $data.events | ForEach-Object {{ "  $($_.eventAction): $($_.eventDate)" }}
  }}
  if ($data.nameservers) {{
    Write-Output ''
    Write-Output 'Nameservers:'
    $data.nameservers | ForEach-Object {{ "  $($_.ldhName)" }}
  }}
  if ($data.entities) {{
    Write-Output ''
    Write-Output 'Entities:'
    $data.entities | Select-Object -First 8 | ForEach-Object {{
      $roles = if ($_.roles) {{ $_.roles -join ', ' }} else {{ 'unknown' }}
      "  $($_.handle) [$roles]"
    }}
  }}
  Write-Output ''
  Write-Output 'Raw JSON:'
  $data | ConvertTo-Json -Depth 8
}} catch {{
  Write-Output "RDAP error: $($_.Exception.Message)"
}}
"#,
        target = quote_powershell(target),
        kind = quote_powershell(kind)
    )
    .trim()
    .to_string()
}

fn unix_rdap_script(target: &str, kind: &str) -> String {
    format!(
        r#"
target={target}
kind={kind}
uri="https://rdap.org/$kind/$target"
echo '== RDAP lookup =='
printf 'URI: %s\n' "$uri"
if command -v curl >/dev/null 2>&1; then
  curl -fsS --max-time 15 "$uri"
else
  echo 'curl not found'
fi
"#,
        target = quote_shell(target),
        kind = quote_shell(kind)
    )
    .trim()
    .to_string()
}

fn windows_http_probe_script(url: &str) -> String {
    format!(
        r#"
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Url = {url}
Write-Output '== HTTP probe =='
Write-Output "URL: $Url"
try {{
  $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -MaximumRedirection 5 -TimeoutSec 15
  "Status: $($response.StatusCode) $($response.StatusDescription)"
  if ($response.BaseResponse.ResponseUri) {{ "Final URL: $($response.BaseResponse.ResponseUri.AbsoluteUri)" }}
  if ($response.Headers.Server) {{ "Server: $($response.Headers.Server)" }}
  if ($response.Headers.'Content-Type') {{ "Content-Type: $($response.Headers.'Content-Type')" }}
  if ($response.Headers.'Content-Length') {{ "Content-Length: $($response.Headers.'Content-Length')" }}
  if ($response.Content -match '<title[^>]*>(.*?)</title>') {{
    "Title: $([System.Net.WebUtility]::HtmlDecode($Matches[1]).Trim())"
  }}
  Write-Output ''
  Write-Output 'Security headers:'
  foreach ($name in @('Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy')) {{
    if ($response.Headers[$name]) {{ "$($name): $($response.Headers[$name])" }} else {{ "$($name): missing" }}
  }}
}} catch {{
  Write-Output "HTTP probe error: $($_.Exception.Message)"
}}
"#,
        url = quote_powershell(url)
    )
    .trim()
    .to_string()
}

fn unix_http_probe_script(url: &str) -> String {
    format!(
        r#"
url={url}
echo '== HTTP probe =='
printf 'URL: %s\n' "$url"
if command -v curl >/dev/null 2>&1; then
  curl -L -sS -D - -o /dev/null --max-time 15 "$url"
  echo ''
  echo 'Title:'
  curl -L -sS --max-time 15 "$url" | sed -n 's:.*<title[^>]*>\(.*\)</title>.*:\1:Ip' | head -n 1
else
  echo 'curl not found'
fi
"#,
        url = quote_shell(url)
    )
    .trim()
    .to_string()
}

fn windows_tls_cert_script(host: &str, port: u16) -> String {
    format!(
        r#"
$ErrorActionPreference = 'Continue'
$HostName = {host}
$Port = {port}
Write-Output '== TLS certificate =='
Write-Output "Target: $HostName`:$Port"
$tcp = $null
$ssl = $null
try {{
  $tcp = [System.Net.Sockets.TcpClient]::new()
  $tcp.Connect($HostName, $Port)
  $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, ({{ $true }}))
  $ssl.AuthenticateAsClient($HostName)
  $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
  "Protocol: $($ssl.SslProtocol)"
  "Subject: $($cert.Subject)"
  "Issuer: $($cert.Issuer)"
  "NotBefore: $($cert.NotBefore.ToUniversalTime().ToString('u'))"
  "NotAfter: $($cert.NotAfter.ToUniversalTime().ToString('u'))"
  "Thumbprint: $($cert.Thumbprint)"
  if ($cert.DnsNameList) {{
    "SAN DNS: $($cert.DnsNameList.Unicode -join ', ')"
  }}
}} catch {{
  Write-Output "TLS probe error: $($_.Exception.Message)"
}} finally {{
  if ($ssl) {{ $ssl.Dispose() }}
  if ($tcp) {{ $tcp.Dispose() }}
}}
"#,
        host = quote_powershell(host),
        port = port
    )
    .trim()
    .to_string()
}

fn unix_tls_cert_script(host: &str, port: u16) -> String {
    format!(
        r#"
host={host}
port={port}
echo '== TLS certificate =='
printf 'Target: %s:%s\n' "$host" "$port"
if command -v openssl >/dev/null 2>&1; then
  echo | openssl s_client -servername "$host" -connect "$host:$port" 2>/dev/null |
    openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 -ext subjectAltName
else
  echo 'openssl not found'
fi
"#,
        host = quote_shell(host),
        port = port
    )
    .trim()
    .to_string()
}

fn run_tcp_reachability(
    host: &str,
    port: u16,
    timeout: Duration,
    entities: Vec<EntityId>,
) -> Result<ProbeOutput> {
    let candidates = (host, port)
        .to_socket_addrs()
        .map_err(|err| SonarError::CommandFailed(format!("resolve {host}:{port}: {err}")))?
        .take(8)
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return Err(SonarError::CommandFailed(format!(
            "no socket addresses resolved for {host}:{port}"
        )));
    }

    let mut attempts = Vec::new();
    let mut connected = None;

    for addr in candidates {
        let started = Instant::now();
        let result = TcpStream::connect_timeout(&addr, timeout);
        let elapsed_ms = started.elapsed().as_millis();
        let ok = result.is_ok();

        attempts.push(json!({
            "address": addr.to_string(),
            "connected": ok,
            "elapsed_ms": elapsed_ms,
            "error": result.err().map(|err| err.to_string()),
        }));

        if ok {
            connected = Some((addr, elapsed_ms));
            break;
        }
    }

    let (summary, severity) = match connected {
        Some((addr, elapsed_ms)) => (
            format!("{host}:{port} reachable via {addr} in {elapsed_ms} ms"),
            Severity::Info,
        ),
        None => (
            format!(
                "{host}:{port} was not reachable within {} ms",
                timeout.as_millis()
            ),
            Severity::Low,
        ),
    };

    Ok(ProbeOutput {
        summary: Some(summary.clone()),
        summary_rows: compact_summary_rows([
            ("Target", format!("{host}:{port}")),
            (
                "Connected",
                if connected.is_some() {
                    "yes".to_string()
                } else {
                    "no".to_string()
                },
            ),
            (
                "Remote",
                connected
                    .as_ref()
                    .map(|(addr, _)| addr.to_string())
                    .unwrap_or_default(),
            ),
            (
                "Elapsed",
                connected
                    .as_ref()
                    .map(|(_, elapsed_ms)| format!("{elapsed_ms} ms"))
                    .unwrap_or_default(),
            ),
        ]),
        findings: vec![Finding {
            title: "TCP reachability checked".into(),
            severity,
            description: summary,
            evidence: Some(json!({
                "host": host,
                "port": port,
                "attempts": attempts,
            })),
            entities,
        }],
        raw: Some(json!({
            "host": host,
            "port": port,
            "attempts": attempts,
        })),
        ..ProbeOutput::default()
    })
}

fn run_os_command(
    descriptor: &ProbeDescriptor,
    invocation: CommandInvocation,
) -> Result<ProbeOutput> {
    let output = Command::new(&invocation.program)
        .args(&invocation.args)
        .output()
        .map_err(|err| SonarError::CommandFailed(format!("{}: {err}", invocation.display())))?;

    let exit_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let succeeded = output.status.success();
    let summary = if succeeded {
        format!("{} completed successfully.", descriptor.name)
    } else {
        format!(
            "{} finished with exit code {:?}.",
            descriptor.name, exit_code
        )
    };

    let mut warnings = Vec::new();
    if !succeeded {
        warnings.push(ProbeWarning {
            code: "command_exit_nonzero".into(),
            message: summary.clone(),
        });
    }

    let evidence = json!({
        "command": invocation.program,
        "args": invocation.args,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
    });
    let summary_rows = summarize_command_output(&descriptor.id, &stdout, &stderr, exit_code);

    Ok(ProbeOutput {
        summary: Some(summary.clone()),
        summary_rows,
        findings: vec![Finding {
            title: format!("{} command executed", descriptor.name),
            severity: if succeeded {
                Severity::Info
            } else {
                Severity::Low
            },
            description: summary,
            evidence: Some(evidence.clone()),
            entities: Vec::new(),
        }],
        warnings,
        raw: Some(evidence),
        ..ProbeOutput::default()
    })
}

fn summarize_command_output(
    probe_id: &str,
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
) -> Vec<SummaryRow> {
    let lines = command_lines(stdout, stderr);
    let mut rows = match probe_id {
        "connectivity.ping" => summarize_ping(&lines),
        "connectivity.traceroute" => summarize_traceroute(&lines),
        "connectivity.fast_trace" => summarize_traceroute(&lines),
        "connectivity.mtr" => summarize_mtr(&lines),
        "connectivity.path_mtu" => summarize_path_mtu(&lines),
        "connectivity.route_check" => summarize_route(&lines),
        "local.network_state" => summarize_local_network(&lines),
        "local.listening_ports" => summarize_listening_ports(&lines),
        "dns.lookup" => summarize_dns_lookup(&lines),
        "dns.leak_check" => summarize_dns_leak(&lines),
        "public.port_check" => summarize_public_port(&lines),
        "public.egress_check" => summarize_egress_dns(&lines),
        "recon.whois_rdap" => summarize_rdap(&lines),
        "web.http_probe" => summarize_http(&lines),
        "web.tls_cert" => summarize_tls(&lines),
        _ => summarize_generic(&lines),
    };

    if exit_code.is_some_and(|code| code != 0) {
        rows.push(SummaryRow::new(
            "Exit",
            exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "unknown".into()),
        ));
    }

    if rows.is_empty() && !lines.is_empty() {
        rows.push(SummaryRow::new("Lines", lines.len().to_string()));
    }

    rows
}

fn command_lines(stdout: &str, stderr: &str) -> Vec<String> {
    [stdout, stderr]
        .into_iter()
        .flat_map(str::lines)
        .map(clean_summary_text)
        .filter(|line| !line.is_empty())
        .collect()
}

fn summarize_ping(lines: &[String]) -> Vec<SummaryRow> {
    let target_line = lines.iter().find(|line| starts_with_ci(line, "Pinging "));
    let target = target_line
        .map(|line| {
            line.trim_start_matches("Pinging ")
                .split(" with ")
                .next()
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    let resolved_ip = target_line
        .and_then(|line| between(line, "[", "]"))
        .unwrap_or_default();
    let packet_line = lines
        .iter()
        .find(|line| line.to_ascii_lowercase().contains("packets:"));
    let replies = lines
        .iter()
        .filter(|line| starts_with_ci(line, "Reply from") || contains_ci(line, "bytes from"))
        .count();
    let (reply_count, loss) = packet_line
        .and_then(|line| parse_windows_ping_packets(line))
        .map(|(sent, received, lost)| (format!("{received}/{sent}"), lost))
        .unwrap_or_else(|| {
            let unix = lines
                .iter()
                .find(|line| contains_ci(line, "packets transmitted"))
                .and_then(|line| parse_unix_ping_packets(line));
            unix.unwrap_or_else(|| {
                (
                    if replies > 0 {
                        replies.to_string()
                    } else {
                        String::new()
                    },
                    String::new(),
                )
            })
        });
    let latency = lines
        .iter()
        .find(|line| contains_ci(line, "Minimum =") || contains_ci(line, "Average ="))
        .and_then(|line| parse_windows_ping_latency(line))
        .or_else(|| {
            lines
                .iter()
                .find(|line| contains_ci(line, "rtt") || contains_ci(line, "round-trip"))
                .and_then(|line| parse_unix_ping_latency(line))
        })
        .unwrap_or_default();

    compact_summary_rows([
        ("Target", clean_summary_text(&target)),
        ("Resolved IP", resolved_ip),
        ("Replies", reply_count),
        ("Packet loss", loss),
        ("Latency", latency),
    ])
}

fn summarize_traceroute(lines: &[String]) -> Vec<SummaryRow> {
    let target = first_label(lines, "Target").unwrap_or_else(|| {
        lines
            .iter()
            .find(|line| contains_ci(line, "Tracing route to"))
            .and_then(|line| line.split(" to ").nth(1))
            .and_then(|value| value.split(" over ").next())
            .map(clean_summary_text)
            .or_else(|| {
                lines
                    .iter()
                    .find(|line| starts_with_ci(line, "traceroute to "))
                    .and_then(|line| {
                        line.trim_start_matches("traceroute to ")
                            .split_once(" (")
                            .map(|(value, _)| value.to_string())
                    })
            })
            .unwrap_or_default()
    });
    let hop_lines: Vec<&String> = lines
        .iter()
        .filter(|line| line.chars().next().is_some_and(|ch| ch.is_ascii_digit()))
        .collect();
    let timeouts = hop_lines
        .iter()
        .filter(|line| line.contains('*') || contains_ci(line, "timed out"))
        .count();
    let last_hop = hop_lines
        .last()
        .map(|line| clean_summary_text(line))
        .unwrap_or_default();

    compact_summary_rows([
        ("Target", target),
        ("Hops", hop_lines.len().to_string()),
        ("Last hop", last_hop),
        (
            "Remote",
            first_label(lines, "RemoteAddress").unwrap_or_default(),
        ),
        (
            "TCP connected",
            first_label(lines, "TcpTestSucceeded").unwrap_or_default(),
        ),
        (
            "Timeouts",
            if timeouts > 0 {
                timeouts.to_string()
            } else {
                String::new()
            },
        ),
    ])
}

fn summarize_mtr(lines: &[String]) -> Vec<SummaryRow> {
    let target = lines
        .iter()
        .find(|line| contains_ci(line, "Tracing route to"))
        .and_then(|line| line.split(" to ").nth(1))
        .and_then(|value| value.split(" over ").next())
        .map(clean_summary_text)
        .or_else(|| {
            lines
                .iter()
                .find(|line| contains_ci(line, "HOST:") || contains_ci(line, "Source to Here"))
                .map(|line| clean_summary_text(line))
        })
        .unwrap_or_default();
    let hop_lines: Vec<String> = lines
        .iter()
        .filter(|line| line.chars().next().is_some_and(|ch| ch.is_ascii_digit()))
        .cloned()
        .collect();
    let loss_rows: Vec<String> = lines
        .iter()
        .filter(|line| contains_ci(line, "%") && line.chars().any(|ch| ch.is_ascii_digit()))
        .cloned()
        .collect();

    compact_summary_rows([
        ("Target", target),
        ("Hops", hop_lines.len().to_string()),
        ("Last hop", hop_lines.last().cloned().unwrap_or_default()),
        ("Loss samples", summarize_list(&loss_rows, 2)),
    ])
}

fn summarize_path_mtu(lines: &[String]) -> Vec<SummaryRow> {
    let attempts = lines
        .iter()
        .filter(|line| starts_with_ci(line, "Try payload"))
        .count();
    compact_summary_rows([
        ("Target", first_label(lines, "Target").unwrap_or_default()),
        (
            "Estimated MTU",
            first_label(lines, "Estimated MTU").unwrap_or_default(),
        ),
        (
            "Attempts",
            if attempts > 0 {
                attempts.to_string()
            } else {
                String::new()
            },
        ),
    ])
}

fn summarize_route(lines: &[String]) -> Vec<SummaryRow> {
    let route = lines
        .iter()
        .find(|line| starts_with_ci(line, "default") || line.starts_with("0.0.0.0"))
        .map(|line| line.to_string())
        .or_else(|| {
            lines
                .iter()
                .find(|line| contains_ci(line, "gateway"))
                .map(|line| line.to_string())
        })
        .unwrap_or_default();

    compact_summary_rows([("Route", route)])
}

fn summarize_local_network(lines: &[String]) -> Vec<SummaryRow> {
    let interfaces = lines
        .iter()
        .filter(|line| contains_ci(line, "adapter ") && line.ends_with(':'))
        .count();
    let ipv4 = unique_values(
        lines
            .iter()
            .filter_map(|line| {
                after_label(line, "IPv4 Address").or_else(|| after_label(line, "inet"))
            })
            .collect(),
    );
    let gateways = unique_values(
        lines
            .iter()
            .filter_map(|line| after_label(line, "Default Gateway"))
            .collect(),
    );
    let dns_rows = lines
        .iter()
        .filter(|line| contains_ci(line, "DNS Servers"))
        .count();

    compact_summary_rows([
        (
            "Interface",
            if interfaces > 0 {
                interfaces.to_string()
            } else {
                String::new()
            },
        ),
        ("Local IPs", summarize_list(&ipv4, 3)),
        ("Gateway", summarize_list(&gateways, 2)),
        (
            "DNS servers",
            if dns_rows > 0 {
                dns_rows.to_string()
            } else {
                String::new()
            },
        ),
    ])
}

fn summarize_listening_ports(lines: &[String]) -> Vec<SummaryRow> {
    let listeners: Vec<String> = lines
        .iter()
        .filter(|line| contains_ci(line, "LISTENING") || contains_ci(line, "LISTEN"))
        .map(|line| line.to_string())
        .collect();
    let public_binds = listeners
        .iter()
        .filter(|line| line.contains("0.0.0.0") || line.contains("[::]") || line.contains("*:"))
        .count();

    compact_summary_rows([
        (
            "Listeners",
            if listeners.is_empty() {
                String::new()
            } else {
                listeners.len().to_string()
            },
        ),
        (
            "Public binds",
            if public_binds > 0 {
                public_binds.to_string()
            } else {
                String::new()
            },
        ),
        ("Summary", summarize_list(&listeners, 2)),
    ])
}

fn summarize_dns_lookup(lines: &[String]) -> Vec<SummaryRow> {
    let server = first_label(lines, "Server").unwrap_or_default();
    let name = first_label(lines, "Name").unwrap_or_default();
    let addresses = unique_values(
        lines
            .iter()
            .filter_map(|line| first_label(std::slice::from_ref(line), "Address"))
            .filter(|address| address != &server)
            .collect(),
    );

    compact_summary_rows([
        ("Server", server),
        ("Target", name),
        ("Records", summarize_list(&addresses, 3)),
    ])
}

fn summarize_dns_leak(lines: &[String]) -> Vec<SummaryRow> {
    let configured: Vec<String> = lines
        .iter()
        .filter(|line| {
            line.contains("->")
                && !contains_ci(line, "whoami.cloudflare")
                && !contains_ci(line, "o-o.myaddr")
        })
        .cloned()
        .collect();
    let observed: Vec<String> = lines
        .iter()
        .filter(|line| contains_ci(line, "whoami.cloudflare") || contains_ci(line, "o-o.myaddr"))
        .cloned()
        .collect();
    let errors = observed
        .iter()
        .filter(|line| contains_ci(line, "ERROR:"))
        .count();
    let observed_ok: Vec<String> = observed
        .into_iter()
        .filter(|line| !contains_ci(line, "ERROR:"))
        .collect();

    compact_summary_rows([
        ("DNS servers", summarize_list(&configured, 2)),
        ("Observed DNS", summarize_list(&observed_ok, 2)),
        (
            "Errors",
            if errors > 0 {
                errors.to_string()
            } else {
                String::new()
            },
        ),
    ])
}

fn summarize_egress_dns(lines: &[String]) -> Vec<SummaryRow> {
    let public_ips = unique_values(
        lines
            .iter()
            .filter(|line| starts_with_ci(line, "http") && line.contains("->"))
            .filter_map(|line| {
                line.rsplit_once("->")
                    .map(|(_, value)| clean_summary_text(value))
            })
            .filter(|value| !contains_ci(value, "ERROR:"))
            .collect(),
    );
    let configured: Vec<String> = lines
        .iter()
        .filter(|line| {
            line.contains("->")
                && !starts_with_ci(line, "http")
                && !contains_ci(line, "whoami.cloudflare")
                && !contains_ci(line, "o-o.myaddr")
        })
        .cloned()
        .collect();
    let observed: Vec<String> = lines
        .iter()
        .filter(|line| contains_ci(line, "whoami.cloudflare") || contains_ci(line, "o-o.myaddr"))
        .filter(|line| !contains_ci(line, "ERROR:"))
        .cloned()
        .collect();
    let errors = lines
        .iter()
        .filter(|line| contains_ci(line, "ERROR:"))
        .count();

    compact_summary_rows([
        ("Public IP", summarize_list(&public_ips, 3)),
        ("DNS servers", summarize_list(&configured, 2)),
        ("Observed DNS", summarize_list(&observed, 2)),
        (
            "Errors",
            if errors > 0 {
                errors.to_string()
            } else {
                String::new()
            },
        ),
    ])
}

fn summarize_public_port(lines: &[String]) -> Vec<SummaryRow> {
    compact_summary_rows([
        ("Target", first_label(lines, "Target").unwrap_or_default()),
        (
            "Connected",
            first_label(lines, "TcpTestSucceeded").unwrap_or_default(),
        ),
        (
            "Remote",
            first_label(lines, "RemoteAddress").unwrap_or_default(),
        ),
        (
            "Interface",
            first_label(lines, "InterfaceAlias").unwrap_or_default(),
        ),
        (
            "Source",
            first_label(lines, "SourceAddress").unwrap_or_default(),
        ),
    ])
}

fn summarize_rdap(lines: &[String]) -> Vec<SummaryRow> {
    compact_summary_rows([
        ("Target", first_label(lines, "URI").unwrap_or_default()),
        (
            "Summary",
            first_label(lines, "ObjectClass").unwrap_or_default(),
        ),
        ("Handle", first_label(lines, "Handle").unwrap_or_default()),
        ("Title", first_label(lines, "Name").unwrap_or_default()),
        ("Country", first_label(lines, "Country").unwrap_or_default()),
        (
            "Nameservers",
            section_count(lines, "Nameservers:").unwrap_or_default(),
        ),
        (
            "Entities",
            section_count(lines, "Entities:").unwrap_or_default(),
        ),
    ])
}

fn summarize_http(lines: &[String]) -> Vec<SummaryRow> {
    let security_total = lines
        .iter()
        .filter(|line| is_security_header_row(line))
        .count();
    let security_missing = lines
        .iter()
        .filter(|line| is_security_header_row(line) && contains_ci(line, "missing"))
        .count();
    let security = if security_total > 0 {
        format!(
            "{}/{} present",
            security_total - security_missing,
            security_total
        )
    } else {
        String::new()
    };

    compact_summary_rows([
        ("Target", first_label(lines, "URL").unwrap_or_default()),
        (
            "HTTP status",
            first_label(lines, "Status").unwrap_or_default(),
        ),
        (
            "Final URL",
            first_label(lines, "Final URL").unwrap_or_default(),
        ),
        ("Server", first_label(lines, "Server").unwrap_or_default()),
        (
            "Content-Type",
            first_label(lines, "Content-Type").unwrap_or_default(),
        ),
        ("Title", first_label(lines, "Title").unwrap_or_default()),
        ("Security", security),
    ])
}

fn summarize_tls(lines: &[String]) -> Vec<SummaryRow> {
    compact_summary_rows([
        ("Target", first_label(lines, "Target").unwrap_or_default()),
        (
            "Protocol",
            first_label(lines, "Protocol").unwrap_or_default(),
        ),
        ("Subject", first_label(lines, "Subject").unwrap_or_default()),
        ("Issuer", first_label(lines, "Issuer").unwrap_or_default()),
        (
            "Expires",
            first_label(lines, "NotAfter").unwrap_or_default(),
        ),
    ])
}

fn summarize_generic(lines: &[String]) -> Vec<SummaryRow> {
    lines
        .iter()
        .filter_map(|line| line.split_once(':'))
        .take(4)
        .map(|(label, value)| SummaryRow::new(clean_summary_text(label), clean_summary_text(value)))
        .collect()
}

fn compact_summary_rows<I, L, V>(rows: I) -> Vec<SummaryRow>
where
    I: IntoIterator<Item = (L, V)>,
    L: Into<String>,
    V: Into<String>,
{
    rows.into_iter()
        .map(|(label, value)| (label.into(), clean_summary_text(&value.into())))
        .filter(|(_, value)| !value.is_empty() && value != "0")
        .map(|(label, value)| SummaryRow::new(label, truncate_summary_value(&value)))
        .collect()
}

fn parse_windows_ping_packets(line: &str) -> Option<(u32, u32, String)> {
    let numbers = numbers_in(line);
    if numbers.len() >= 4 {
        Some((numbers[0], numbers[1], format!("{}%", numbers[3])))
    } else {
        None
    }
}

fn parse_unix_ping_packets(line: &str) -> Option<(String, String)> {
    let lower = line.to_ascii_lowercase();
    let transmitted = lower.split(" packets transmitted").next()?.trim();
    let received = lower
        .split("packets transmitted,")
        .nth(1)?
        .split("received")
        .next()?
        .replace("packets", "")
        .trim()
        .to_string();
    let loss = lower
        .split("received,")
        .nth(1)?
        .split("packet loss")
        .next()?
        .trim()
        .to_string();

    Some((format!("{received}/{transmitted}"), loss))
}

fn parse_windows_ping_latency(line: &str) -> Option<String> {
    let mut minimum = String::new();
    let mut maximum = String::new();
    let mut average = String::new();

    for segment in line.split(',') {
        if let Some(value) = after_label(segment, "Minimum") {
            minimum = value;
        } else if let Some(value) = after_label(segment, "Maximum") {
            maximum = value;
        } else if let Some(value) = after_label(segment, "Average") {
            average = value;
        }
    }

    if minimum.is_empty() || maximum.is_empty() || average.is_empty() {
        return None;
    }

    Some(format!("avg {average}, min {minimum}, max {maximum}"))
}

fn parse_unix_ping_latency(line: &str) -> Option<String> {
    let values = line.split_once('=')?.1.split_whitespace().next()?;
    let parts: Vec<&str> = values.split('/').collect();
    if parts.len() >= 3 {
        Some(format!(
            "avg {} ms, min {} ms, max {} ms",
            parts[1], parts[0], parts[2]
        ))
    } else {
        None
    }
}

fn first_label(lines: &[String], label: &str) -> Option<String> {
    lines.iter().find_map(|line| after_label(line, label))
}

fn after_label(line: &str, label: &str) -> Option<String> {
    let (lhs, rhs) = line.split_once(':').or_else(|| line.split_once('='))?;
    if lhs.trim().eq_ignore_ascii_case(label)
        || lhs
            .trim()
            .to_ascii_lowercase()
            .starts_with(&label.to_ascii_lowercase())
    {
        Some(clean_summary_text(
            rhs.trim().trim_start_matches(':').trim_start_matches('='),
        ))
    } else {
        None
    }
}

fn section_count(lines: &[String], heading: &str) -> Option<String> {
    let start = lines.iter().position(|line| line.trim() == heading)?;
    let mut count = 0;
    for line in lines.iter().skip(start + 1) {
        if line.ends_with(':') && !line.starts_with(' ') {
            break;
        }
        if !line.trim().is_empty() {
            count += 1;
        }
    }
    (count > 0).then(|| count.to_string())
}

fn is_security_header_row(line: &str) -> bool {
    [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]
    .iter()
    .any(|header| starts_with_ci(line, header))
}

fn numbers_in(line: &str) -> Vec<u32> {
    line.split(|ch: char| !ch.is_ascii_digit())
        .filter_map(|value| value.parse::<u32>().ok())
        .collect()
}

fn unique_values(values: Vec<String>) -> Vec<String> {
    values.into_iter().fold(Vec::new(), |mut acc, value| {
        let value = clean_summary_text(&value);
        if !value.is_empty() && !acc.contains(&value) {
            acc.push(value);
        }
        acc
    })
}

fn summarize_list(values: &[String], max_items: usize) -> String {
    if values.is_empty() {
        return String::new();
    }

    let visible = values
        .iter()
        .take(max_items)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    let hidden = values.len().saturating_sub(max_items);
    if hidden > 0 {
        format!("{visible} +{hidden}")
    } else {
        visible
    }
}

fn contains_ci(value: &str, needle: &str) -> bool {
    value
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn starts_with_ci(value: &str, needle: &str) -> bool {
    value
        .to_ascii_lowercase()
        .starts_with(&needle.to_ascii_lowercase())
}

fn between(value: &str, left: &str, right: &str) -> Option<String> {
    let start = value.find(left)? + left.len();
    let end = value[start..].find(right)? + start;
    Some(value[start..end].to_string())
}

fn clean_summary_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_summary_value(value: &str) -> String {
    const MAX_LEN: usize = 180;
    if value.len() <= MAX_LEN {
        value.to_string()
    } else {
        format!("{}...", &value[..MAX_LEN.saturating_sub(3)])
    }
}

fn target_for_command(entity: &Entity) -> String {
    match entity {
        Entity::LocalMachine => "this-machine".into(),
        Entity::CurrentInternetPath => "current-internet-path".into(),
        Entity::Ip(ip) => ip.to_string(),
        Entity::Domain(domain) => domain.normalized.clone(),
        Entity::Host(host) => host
            .ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| host.name.clone()),
        Entity::Port(port) => port.ip.to_string(),
        Entity::Url(url) => url
            .host_str()
            .map(String::from)
            .unwrap_or_else(|| url.as_str().to_string()),
        _ => entity.stable_key(),
    }
}

fn port_check_target(entity: &Entity) -> (String, u16) {
    match entity {
        Entity::Port(port) => (port.ip.to_string(), port.port),
        Entity::Url(url) => (
            url.host_str()
                .map(String::from)
                .unwrap_or_else(|| url.as_str().to_string()),
            url.port_or_known_default().unwrap_or(443),
        ),
        _ => (target_for_command(entity), 443),
    }
}

fn tls_target(entity: &Entity) -> (String, u16) {
    match entity {
        Entity::Url(url) => (
            url.host_str()
                .map(String::from)
                .unwrap_or_else(|| url.as_str().to_string()),
            url.port_or_known_default().unwrap_or(443),
        ),
        Entity::Port(port) => (port.ip.to_string(), port.port),
        _ => (target_for_command(entity), 443),
    }
}

fn rdap_kind(entity: &Entity) -> &'static str {
    match entity {
        Entity::Ip(_) | Entity::Port(_) => "ip",
        Entity::Asn(_) => "autnum",
        _ => "domain",
    }
}

fn http_probe_url(entity: &Entity) -> String {
    match entity {
        Entity::Url(url) => url.as_str().to_string(),
        Entity::Port(port) => format!("http://{}:{}", port.ip, port.port),
        _ => format!("https://{}", target_for_command(entity)),
    }
}

fn quote_powershell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn quote_shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn reachability_target(entity: &Entity) -> (String, u16) {
    match entity {
        Entity::Port(port) => (port.ip.to_string(), port.port),
        Entity::Url(url) => (
            url.host_str()
                .map(String::from)
                .unwrap_or_else(|| url.as_str().to_string()),
            url.port_or_known_default().unwrap_or(443),
        ),
        _ => (target_for_command(entity), 443),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::parse_entity_guess;

    #[test]
    fn reachability_target_uses_domain_port_once() {
        let entity = parse_entity_guess("example.com:443").unwrap();

        assert_eq!(reachability_target(&entity), ("example.com".into(), 443));
    }
}
