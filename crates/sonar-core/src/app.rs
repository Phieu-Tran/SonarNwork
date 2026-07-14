use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::entity::{parse_entity_guess, Entity, EntityKind};
use crate::error::{Result, SonarError};
use crate::probe::{
    command_invocation_for_probe, dns_lookup_invocation, ping_invocation, run_command_invocation,
    run_port_check_profile, trace_invocation, CommandInvocation, DescribeEntityProbe,
    DnsLookupProfile, ListeningPortsProbe, LocalNetworkStateProbe, OsCommandKind, OsCommandProbe,
    PingProfile, PortCheckProfile, ProbeCategory, ProbeCtx, ProbeDescriptor, ProbeOutput,
    ProbeRegistry, ProbeRequirement, ProbeRisk, ProbeStatus, ReachabilityProbe, Severity,
    SummaryRow, TraceProfile,
};
use crate::scope::{ActionClass, ScopeDecision, ScopeGuard, ScopePolicy};
use crate::PivotGraph;

pub const PRODUCT_NAME: &str = "SonarNwork";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub core_crate: String,
    pub version: String,
    pub contract: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeProfile {
    BeginnerSafeLocal,
    ActiveNetworkScan,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ProbeTarget {
    Input(String),
    LocalMachine,
    CurrentInternetPath,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowDescriptor {
    pub id: String,
    pub title_key: String,
    pub description_key: String,
    pub target: ProbeTarget,
    pub primary_probe_ids: Vec<String>,
    pub advanced_probe_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultInterpretation {
    pub verdict: ResultVerdict,
    pub summary: Option<String>,
    pub summary_rows: Vec<crate::probe::SummaryRow>,
    pub next_actions: Vec<NextAction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultVerdict {
    pub status: VerdictStatus,
    pub title: String,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    Ok,
    Warning,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NextAction {
    pub id: String,
    pub label_key: String,
    pub probe_id: String,
    pub target: ProbeTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteVantageProvider {
    Globalping,
    SonarNworkRemoteScan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteMeasurementKind {
    Ping,
    Traceroute,
    Dns,
    Mtr,
    Http,
    TcpPort,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteVantageRequest {
    pub provider: RemoteVantageProvider,
    pub measurement: RemoteMeasurementKind,
    pub target: ProbeTarget,
    pub locations: Vec<String>,
    pub scope_token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteVantagePlan {
    pub request: RemoteVantageRequest,
    pub allowed_probe_ids: Vec<String>,
    pub warning: Option<String>,
}

#[derive(Clone)]
pub struct AppCore {
    scope: ScopeGuard,
    probes: ProbeRegistry,
}

impl Default for AppCore {
    fn default() -> Self {
        Self::for_profile(ProbeProfile::BeginnerSafeLocal)
    }
}

impl AppCore {
    pub fn for_profile(profile: ProbeProfile) -> Self {
        let mut probes = ProbeRegistry::new();
        probes.register(DescribeEntityProbe);
        register_default_probes(&mut probes);

        let scope_policy = match profile {
            ProbeProfile::BeginnerSafeLocal => ScopePolicy::default(),
            ProbeProfile::ActiveNetworkScan => ScopePolicy {
                allow_active_probe_by_default: true,
                ..ScopePolicy::default()
            },
        };

        Self {
            scope: ScopeGuard::new(scope_policy),
            probes,
        }
    }

    pub fn active_network_scan() -> Self {
        Self::for_profile(ProbeProfile::ActiveNetworkScan)
    }

    pub fn for_explicit_target(target: &ProbeTarget) -> Result<Self> {
        let entity = Self::default().resolve_probe_target(target)?;
        let policy = match &entity {
            Entity::Ip(ip) => ScopePolicy::default().allow_ip(*ip),
            Entity::Domain(domain) => ScopePolicy::default().allow_domain(&domain.normalized),
            Entity::Host(host) => match host.ip {
                Some(ip) => ScopePolicy::default().allow_ip(ip),
                None => ScopePolicy::default().allow_domain(&host.name),
            },
            Entity::Port(port) => ScopePolicy::default().allow_ip(port.ip),
            Entity::Url(url) => {
                let host = url
                    .host_str()
                    .ok_or_else(|| SonarError::InvalidTarget(url.to_string()))?;
                match host.parse::<IpAddr>() {
                    Ok(ip) => ScopePolicy::default().allow_ip(ip),
                    Err(_) => ScopePolicy::default().allow_domain(host),
                }
            }
            _ => return Err(SonarError::InvalidTarget(entity.stable_key())),
        };

        Ok(Self {
            scope: ScopeGuard::new(policy),
            ..Self::default()
        })
    }

    pub fn new(scope: ScopeGuard, probes: ProbeRegistry) -> Self {
        Self { scope, probes }
    }

    pub fn app_info(&self) -> AppInfo {
        AppInfo {
            name: PRODUCT_NAME.into(),
            core_crate: "sonar-core".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            contract: "CLI and Tauri app share this core API.".into(),
        }
    }

    pub fn parse_entity(&self, input: &str) -> Result<Entity> {
        parse_entity_guess(input)
    }

    pub fn resolve_probe_target(&self, target: &ProbeTarget) -> Result<Entity> {
        match target {
            ProbeTarget::Input(input) => self.parse_entity(input),
            ProbeTarget::LocalMachine => Ok(Entity::LocalMachine),
            ProbeTarget::CurrentInternetPath => Ok(Entity::CurrentInternetPath),
        }
    }

    pub fn all_probes(&self) -> Vec<ProbeDescriptor> {
        self.probes.descriptors()
    }

    pub fn probe_descriptor(&self, probe_id: &str) -> Option<ProbeDescriptor> {
        self.probes.descriptor(probe_id)
    }

    pub fn available_probes(&self, entity: &Entity) -> Vec<ProbeDescriptor> {
        self.probes.descriptors_for(entity)
    }

    pub fn available_probes_for_target(
        &self,
        target: &ProbeTarget,
    ) -> Result<Vec<ProbeDescriptor>> {
        let entity = self.resolve_probe_target(target)?;
        Ok(self.available_probes(&entity))
    }

    pub fn scope_decision(&self, entity: &Entity, action: ActionClass) -> ScopeDecision {
        self.scope.check(entity, action)
    }

    pub fn ensure_allowed_for_target(
        &self,
        target: &ProbeTarget,
        action: ActionClass,
    ) -> Result<()> {
        let entity = self.resolve_probe_target(target)?;
        self.scope.ensure_allowed(&entity, action)
    }

    pub async fn run_probe(
        &self,
        probe_id: &str,
        entity: &Entity,
    ) -> Result<(ProbeDescriptor, ProbeOutput, PivotGraph)> {
        let ctx = ProbeCtx::new(self.scope.clone());
        self.probes.run(probe_id, entity, &ctx).await
    }

    pub async fn run_probe_target(
        &self,
        probe_id: &str,
        target: &ProbeTarget,
    ) -> Result<(ProbeDescriptor, ProbeOutput, PivotGraph)> {
        let entity = self.resolve_probe_target(target)?;
        self.run_probe(probe_id, &entity).await
    }

    pub fn command_invocation(&self, probe_id: &str, entity: &Entity) -> Option<CommandInvocation> {
        command_invocation_for_probe(probe_id, entity)
    }

    pub fn command_invocation_for_target(
        &self,
        probe_id: &str,
        target: &ProbeTarget,
    ) -> Result<Option<CommandInvocation>> {
        let entity = self.resolve_probe_target(target)?;
        self.ensure_probe_allowed(probe_id, &entity)?;
        Ok(self.command_invocation(probe_id, &entity))
    }

    fn ensure_probe_allowed(&self, probe_id: &str, entity: &Entity) -> Result<ProbeDescriptor> {
        let probe = self
            .probes
            .get(probe_id)
            .ok_or_else(|| SonarError::ProbeNotFound(probe_id.to_string()))?;
        let descriptor = probe.descriptor();

        if !probe.applies_to(entity) {
            return Err(SonarError::ProbeDoesNotApply {
                probe_id: descriptor.id.clone(),
                entity_id: entity.id().to_string(),
            });
        }

        if descriptor.status != ProbeStatus::Ready {
            return Err(SonarError::ProbeNotReady {
                probe_id: descriptor.id.clone(),
                status: format!("{:?}", descriptor.status).to_ascii_lowercase(),
            });
        }

        self.scope
            .ensure_allowed(entity, descriptor.risk.action_class())?;

        Ok(descriptor)
    }

    pub fn workflows(&self) -> Vec<WorkflowDescriptor> {
        product_workflows()
    }

    pub fn interpret_result(
        &self,
        descriptor: &ProbeDescriptor,
        output: &ProbeOutput,
    ) -> ResultInterpretation {
        ResultInterpretation {
            verdict: verdict_for_result(descriptor, output),
            summary: output.summary.clone(),
            summary_rows: output.summary_rows.clone(),
            next_actions: next_actions_for_probe(&descriptor.id),
        }
    }

    pub fn remote_vantage_plan(
        &self,
        provider: RemoteVantageProvider,
        measurement: RemoteMeasurementKind,
        target: ProbeTarget,
    ) -> RemoteVantagePlan {
        let allowed_probe_ids = match (provider, measurement) {
            (_, RemoteMeasurementKind::Ping) => vec!["connectivity.ping".into()],
            (_, RemoteMeasurementKind::Traceroute) => vec!["connectivity.traceroute".into()],
            (_, RemoteMeasurementKind::Dns) => vec!["dns.lookup".into()],
            (_, RemoteMeasurementKind::Mtr) => vec!["connectivity.mtr".into()],
            (_, RemoteMeasurementKind::Http) => vec!["web.http_probe".into()],
            (RemoteVantageProvider::Globalping, RemoteMeasurementKind::TcpPort) => {
                vec!["public.port_check".into()]
            }
            (RemoteVantageProvider::SonarNworkRemoteScan, RemoteMeasurementKind::TcpPort) => {
                vec!["public.port_check".into()]
            }
        };
        let warning = match (provider, measurement) {
            (RemoteVantageProvider::Globalping, RemoteMeasurementKind::TcpPort) => Some(
                "Globalping-style TCP vantage checks whether the target port is reachable from outside your local network. Local netstat/listeners are evidence only, not the public ingress verdict."
                    .into(),
            ),
            (RemoteVantageProvider::Globalping, _) => Some(
                "Globalping-style vantage is for outside-in measurements; use TCP port for public ingress and local listener checks only as supporting evidence."
                    .into(),
            ),
            (RemoteVantageProvider::SonarNworkRemoteScan, RemoteMeasurementKind::TcpPort) => {
                Some(
                    "Remote-scan plan prepared; execution requires token handoff and explicit target scope."
                        .into(),
                )
            }
            (RemoteVantageProvider::SonarNworkRemoteScan, _) => {
                Some("Remote-scan requires token handoff and explicit target scope.".into())
            }
        };

        RemoteVantagePlan {
            request: RemoteVantageRequest {
                provider,
                measurement,
                target,
                locations: Vec::new(),
                scope_token: None,
            },
            allowed_probe_ids,
            warning,
        }
    }

    pub fn ping_invocation(&self, profile: &PingProfile) -> CommandInvocation {
        ping_invocation(profile)
    }

    pub fn trace_invocation(&self, profile: &TraceProfile) -> CommandInvocation {
        trace_invocation(profile)
    }

    pub fn dns_lookup_invocation(&self, profile: &DnsLookupProfile) -> CommandInvocation {
        dns_lookup_invocation(profile)
    }

    pub fn run_command_invocation(
        &self,
        probe_id: &str,
        invocation: CommandInvocation,
    ) -> Result<(ProbeDescriptor, ProbeOutput, PivotGraph)> {
        let descriptor = self
            .probe_descriptor(probe_id)
            .ok_or_else(|| crate::error::SonarError::ProbeNotFound(probe_id.to_string()))?;
        let output = run_command_invocation(&descriptor, invocation)?;
        Ok((descriptor, output, PivotGraph::new()))
    }

    pub fn run_port_profile(
        &self,
        profile: &PortCheckProfile,
    ) -> Result<(ProbeDescriptor, ProbeOutput, PivotGraph)> {
        let descriptor = self
            .probe_descriptor("connectivity.reachability")
            .ok_or_else(|| {
                crate::error::SonarError::ProbeNotFound("connectivity.reachability".into())
            })?;
        let output = run_port_check_profile(profile)?;
        Ok((descriptor, output, PivotGraph::new()))
    }
}

fn product_workflows() -> Vec<WorkflowDescriptor> {
    vec![
        WorkflowDescriptor {
            id: "local_network".into(),
            title_key: "workflow.local_network.title".into(),
            description_key: "workflow.local_network.description".into(),
            target: ProbeTarget::LocalMachine,
            primary_probe_ids: vec!["local.network_state".into(), "local.listening_ports".into()],
            advanced_probe_ids: vec!["connectivity.route_check".into()],
        },
        WorkflowDescriptor {
            id: "internet_path".into(),
            title_key: "workflow.internet_path.title".into(),
            description_key: "workflow.internet_path.description".into(),
            target: ProbeTarget::CurrentInternetPath,
            primary_probe_ids: vec![
                "public.egress_check".into(),
                "connectivity.ping".into(),
                "connectivity.traceroute".into(),
                "web.http_probe".into(),
            ],
            advanced_probe_ids: vec![
                "dns.leak_check".into(),
                "dns.lookup".into(),
                "connectivity.mtr".into(),
                "connectivity.path_mtu".into(),
                "web.tls_cert".into(),
            ],
        },
        WorkflowDescriptor {
            id: "public_service".into(),
            title_key: "workflow.public_service.title".into(),
            description_key: "workflow.public_service.description".into(),
            target: ProbeTarget::Input(String::new()),
            primary_probe_ids: vec![
                "local.listening_ports".into(),
                "connectivity.reachability".into(),
                "public.port_check".into(),
            ],
            advanced_probe_ids: vec!["local.network_state".into()],
        },
    ]
}

fn next_actions_for_probe(probe_id: &str) -> Vec<NextAction> {
    match probe_id {
        "public.egress_check" => vec![NextAction {
            id: "check_dns_leak".into(),
            label_key: "next_action.check_dns_leak".into(),
            probe_id: "dns.leak_check".into(),
            target: ProbeTarget::CurrentInternetPath,
        }],
        "connectivity.ping" => vec![NextAction {
            id: "trace_path".into(),
            label_key: "next_action.trace_path".into(),
            probe_id: "connectivity.traceroute".into(),
            target: ProbeTarget::Input(String::new()),
        }],
        "local.listening_ports" => vec![NextAction {
            id: "check_public_port".into(),
            label_key: "next_action.check_public_port".into(),
            probe_id: "public.port_check".into(),
            target: ProbeTarget::Input(String::new()),
        }],
        _ => Vec::new(),
    }
}

fn verdict_for_result(descriptor: &ProbeDescriptor, output: &ProbeOutput) -> ResultVerdict {
    let status = verdict_status_for_result(descriptor, output);
    let title = verdict_title_for_probe(&descriptor.id, output)
        .or_else(|| output.summary.clone())
        .unwrap_or_else(|| format!("{} completed.", descriptor.name));
    let detail = verdict_detail_for_result(output, &title);

    ResultVerdict {
        status,
        title,
        detail,
    }
}

fn verdict_status_for_result(descriptor: &ProbeDescriptor, output: &ProbeOutput) -> VerdictStatus {
    if raw_exit_code(output).is_some_and(|code| code != 0) {
        return VerdictStatus::Failed;
    }

    if descriptor.id == "connectivity.reachability"
        && row_value(&output.summary_rows, "Connected")
            .is_some_and(|value| value.eq_ignore_ascii_case("no"))
    {
        return VerdictStatus::Warning;
    }

    if descriptor.id == "connectivity.ping"
        && row_value(&output.summary_rows, "Packet loss")
            .is_some_and(|value| percent_value_is_non_zero(&value))
    {
        return VerdictStatus::Warning;
    }

    if descriptor.id == "local.listening_ports"
        && row_value(&output.summary_rows, "Public binds")
            .is_some_and(|value| positive_integer_text(&value))
    {
        return VerdictStatus::Warning;
    }

    if !output.warnings.is_empty() {
        return VerdictStatus::Warning;
    }

    let max_severity = output
        .findings
        .iter()
        .map(|finding| finding.severity)
        .max_by_key(|severity| severity_rank(*severity));
    match max_severity {
        Some(Severity::Critical | Severity::High) => VerdictStatus::Failed,
        Some(Severity::Medium | Severity::Low) => VerdictStatus::Warning,
        Some(Severity::Info) => VerdictStatus::Ok,
        None if output.summary.is_some() || !output.summary_rows.is_empty() => VerdictStatus::Ok,
        None => VerdictStatus::Unknown,
    }
}

fn verdict_title_for_probe(probe_id: &str, output: &ProbeOutput) -> Option<String> {
    let rows = &output.summary_rows;
    let title = match probe_id {
        "public.egress_check" => row_value(rows, "Public IP")
            .map(|public_ip| format!("This machine exits through {public_ip}.")),
        "dns.leak_check" => row_value(rows, "Observed DNS")
            .or_else(|| row_value(rows, "DNS servers"))
            .map(|dns| format!("DNS path observed as {dns}.")),
        "connectivity.ping" => {
            let target = row_value(rows, "Target").unwrap_or_else(|| "target".into());
            let latency = row_value(rows, "Latency");
            let loss = row_value(rows, "Packet loss");
            match (latency, loss) {
                (Some(latency), Some(loss)) => {
                    Some(format!("Reached {target}: {latency}, packet loss {loss}."))
                }
                (Some(latency), None) => Some(format!("Reached {target}: {latency}.")),
                (None, Some(loss)) => Some(format!("Reached {target}: packet loss {loss}.")),
                (None, None) => row_value(rows, "Replies")
                    .map(|replies| format!("Ping to {target} returned {replies} replies.")),
            }
        }
        "connectivity.traceroute" | "connectivity.fast_trace" => {
            let hops = row_value(rows, "Hops");
            let last_hop = row_value(rows, "Last hop");
            match (hops, last_hop) {
                (Some(hops), Some(last_hop)) => {
                    Some(format!("Trace reached {last_hop} in {hops} hops."))
                }
                (Some(hops), None) => Some(format!("Trace sampled {hops} hops.")),
                _ => None,
            }
        }
        "connectivity.mtr" => row_value(rows, "Loss samples")
            .or_else(|| row_value(rows, "Hops"))
            .map(|sample| format!("Path loss sample collected: {sample}.")),
        "connectivity.path_mtu" => {
            row_value(rows, "Estimated MTU").map(|mtu| format!("Estimated path MTU is {mtu}."))
        }
        "connectivity.route_check" => {
            row_value(rows, "Route").map(|route| format!("Route selected: {route}."))
        }
        "connectivity.reachability" => {
            let target = row_value(rows, "Target").unwrap_or_else(|| "target".into());
            match row_value(rows, "Connected").as_deref() {
                Some("yes") => Some(format!("{target} is reachable from this machine.")),
                Some("no") => Some(format!("{target} is not reachable from this machine.")),
                _ => None,
            }
        }
        "local.network_state" => {
            let ips = row_value(rows, "Local IPs");
            let gateway = row_value(rows, "Gateway");
            match (ips, gateway) {
                (Some(ips), Some(gateway)) => {
                    Some(format!("This machine has {ips}; gateway {gateway}."))
                }
                (Some(ips), None) => Some(format!("This machine has local IP {ips}.")),
                (None, Some(gateway)) => Some(format!("Default gateway is {gateway}.")),
                _ => None,
            }
        }
        "local.listening_ports" => {
            let listeners = row_value(rows, "Listeners");
            let public_binds = row_value(rows, "Public binds");
            match (listeners, public_binds) {
                (Some(listeners), Some(public_binds)) => Some(format!(
                    "{listeners} local listeners found; {public_binds} bind to all interfaces."
                )),
                (Some(listeners), None) => Some(format!("{listeners} local listeners found.")),
                _ => None,
            }
        }
        "dns.lookup" => {
            let target = row_value(rows, "Target").unwrap_or_else(|| "target".into());
            row_value(rows, "Records").map(|records| format!("{target} resolves to {records}."))
        }
        "web.http_probe" => row_value(rows, "HTTP status")
            .map(|status| format!("HTTP from here returned {status}.")),
        "web.tls_cert" => {
            row_value(rows, "Expires").map(|expires| format!("TLS certificate expires {expires}."))
        }
        "recon.whois_rdap" => row_value(rows, "Target")
            .or_else(|| row_value(rows, "Handle"))
            .map(|target| format!("Public registration record checked for {target}.")),
        _ => None,
    };

    title.map(|value| trim_sentence_spacing(&value))
}

fn verdict_detail_for_result(output: &ProbeOutput, title: &str) -> Option<String> {
    let detail = output
        .warnings
        .first()
        .map(|warning| warning.message.clone())
        .or_else(|| {
            output
                .findings
                .iter()
                .find(|finding| finding.severity != Severity::Info)
                .map(|finding| finding.description.clone())
        });

    detail
        .map(|value| trim_sentence_spacing(&value))
        .filter(|value| !value.is_empty() && value != title)
}

fn raw_exit_code(output: &ProbeOutput) -> Option<i64> {
    output
        .raw
        .as_ref()
        .and_then(|raw| raw.get("exit_code"))
        .and_then(serde_json::Value::as_i64)
}

fn row_value(rows: &[SummaryRow], label: &str) -> Option<String> {
    rows.iter()
        .find(|row| row.label.eq_ignore_ascii_case(label))
        .map(|row| row.value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn percent_value_is_non_zero(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .find_map(|part| part.parse::<f64>().ok())
        .is_some_and(|percent| percent > 0.0)
}

fn positive_integer_text(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_digit())
        .find_map(|part| part.parse::<u64>().ok())
        .is_some_and(|number| number > 0)
}

fn trim_sentence_spacing(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn register_default_probes(registry: &mut ProbeRegistry) {
    let targetish = vec![
        EntityKind::Ip,
        EntityKind::Domain,
        EntityKind::Host,
        EntityKind::Url,
    ];
    let endpointish = vec![
        EntityKind::Ip,
        EntityKind::Domain,
        EntityKind::Host,
        EntityKind::Url,
        EntityKind::Port,
    ];
    let domainish = vec![EntityKind::Domain, EntityKind::Host, EntityKind::Url];
    let webish = vec![
        EntityKind::Domain,
        EntityKind::Host,
        EntityKind::Url,
        EntityKind::Port,
    ];
    let current_internet_path = vec![EntityKind::CurrentInternetPath];

    registry.register(OsCommandProbe::new(
        "connectivity.ping",
        "Ping",
        "Measure packet reachability, latency, jitter, and loss to a target.",
        ProbeCategory::Connectivity,
        ProbeRisk::SafeActive,
        vec![ProbeRequirement::Network],
        targetish.clone(),
        OsCommandKind::Ping,
    ));
    registry.register(OsCommandProbe::new(
        "connectivity.traceroute",
        "Traceroute",
        "Trace the route to a target with ICMP, UDP, or TCP methods.",
        ProbeCategory::Connectivity,
        ProbeRisk::SafeActive,
        vec![ProbeRequirement::Network, ProbeRequirement::RawSocket],
        targetish.clone(),
        OsCommandKind::Traceroute,
    ));
    registry.register(OsCommandProbe::new(
        "connectivity.fast_trace",
        "Fast trace",
        "Run a short hop-limited trace for a quick path check.",
        ProbeCategory::Connectivity,
        ProbeRisk::SafeActive,
        vec![ProbeRequirement::Network],
        targetish.clone(),
        OsCommandKind::FastTrace,
    ));
    registry.register(OsCommandProbe::new(
        "connectivity.mtr",
        "Path loss",
        "Measure hop path and packet-loss style samples with pathping or mtr.",
        ProbeCategory::Connectivity,
        ProbeRisk::SafeActive,
        vec![ProbeRequirement::Network],
        targetish.clone(),
        OsCommandKind::Mtr,
    ));
    registry.register(OsCommandProbe::new(
        "connectivity.path_mtu",
        "Path MTU",
        "Estimate the largest non-fragmented packet size to a target.",
        ProbeCategory::Connectivity,
        ProbeRisk::SafeActive,
        vec![ProbeRequirement::Network],
        targetish.clone(),
        OsCommandKind::PathMtu,
    ));
    registry.register(OsCommandProbe::new(
        "connectivity.route_check",
        "Route print",
        "Show the local route table and default gateway selection.",
        ProbeCategory::Connectivity,
        ProbeRisk::Passive,
        vec![],
        vec![EntityKind::LocalMachine],
        OsCommandKind::RouteCheck,
    ));
    registry.register(ReachabilityProbe::new(endpointish.clone()));
    registry.register(LocalNetworkStateProbe);
    registry.register(ListeningPortsProbe);
    registry.register(OsCommandProbe::new(
        "dns.lookup",
        "DNS lookup",
        "Resolve A, AAAA, MX, TXT, NS, CAA, and SOA records.",
        ProbeCategory::Dns,
        ProbeRisk::Passive,
        vec![ProbeRequirement::Network],
        domainish.clone(),
        OsCommandKind::DnsLookup,
    ));
    registry.register(OsCommandProbe::new(
        "dns.leak_check",
        "DNS leak check",
        "Compare configured resolvers with the resolver path observed by whoami DNS probes.",
        ProbeCategory::Dns,
        ProbeRisk::SafeActive,
        vec![ProbeRequirement::Network],
        endpointish
            .iter()
            .copied()
            .chain(current_internet_path.iter().copied())
            .collect(),
        OsCommandKind::DnsLeakCheck,
    ));
    registry.register(OsCommandProbe::new_with_status(
        "public.port_check",
        "Public remote port",
        "Check whether an outside remote vantage can reach a host:port. Requires remote-scan.",
        ProbeCategory::PublicExposure,
        ProbeStatus::Ready,
        ProbeRisk::SafeActive,
        vec![
            ProbeRequirement::Network,
            ProbeRequirement::ExternalTool("sonarnwork-remote-scan".into()),
        ],
        endpointish.clone(),
        OsCommandKind::PublicPortCheck,
    ));
    registry.register(OsCommandProbe::new(
        "public.egress_check",
        "Egress IP + DNS",
        "Show this machine's public egress IP and the DNS servers/path used to reach the Internet.",
        ProbeCategory::PublicExposure,
        ProbeRisk::SafeActive,
        vec![ProbeRequirement::Network],
        current_internet_path,
        OsCommandKind::EgressDns,
    ));
    registry.register(OsCommandProbe::new(
        "recon.whois_rdap",
        "WHOIS / RDAP",
        "Look up ownership and registration data through RDAP and selectable WHOIS sources.",
        ProbeCategory::Recon,
        ProbeRisk::Passive,
        vec![ProbeRequirement::Network],
        endpointish,
        OsCommandKind::WhoisRdap,
    ));
    registry.register(OsCommandProbe::new(
        "web.http_probe",
        "HTTP probe",
        "Check status, title, redirects, detected technologies, and security headers.",
        ProbeCategory::WebTls,
        ProbeRisk::SafeActive,
        vec![ProbeRequirement::Network],
        webish.clone(),
        OsCommandKind::HttpProbe,
    ));
    registry.register(OsCommandProbe::new(
        "web.tls_cert",
        "TLS certificate",
        "Inspect protocol support, certificate chain, SANs, expiry, and mismatch risks.",
        ProbeCategory::WebTls,
        ProbeRisk::SafeActive,
        vec![ProbeRequirement::Network],
        webish,
        OsCommandKind::TlsCert,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_exposes_port_aware_probes() {
        let core = AppCore::default();
        let entity = core.parse_entity("127.0.0.1:443").unwrap();
        let probe_ids = core
            .available_probes(&entity)
            .into_iter()
            .map(|probe| probe.id)
            .collect::<Vec<_>>();

        assert!(probe_ids.iter().any(|id| id == "connectivity.reachability"));
        assert!(probe_ids.iter().any(|id| id == "public.port_check"));
        assert!(probe_ids.iter().any(|id| id == "web.http_probe"));
        assert!(probe_ids.iter().any(|id| id == "web.tls_cert"));

        let public_remote = core
            .available_probes(&entity)
            .into_iter()
            .find(|probe| probe.id == "public.port_check")
            .unwrap();
        assert_eq!(public_remote.status, ProbeStatus::Ready);
    }

    #[test]
    fn ip_exposes_trace_phase_two_probes() {
        let core = AppCore::default();
        let entity = core.parse_entity("127.0.0.1").unwrap();
        let probe_ids = core
            .available_probes(&entity)
            .into_iter()
            .map(|probe| probe.id)
            .collect::<Vec<_>>();

        assert!(probe_ids.iter().any(|id| id == "connectivity.fast_trace"));
        assert!(probe_ids.iter().any(|id| id == "connectivity.mtr"));
        assert!(probe_ids.iter().any(|id| id == "connectivity.path_mtu"));
    }

    #[test]
    fn dns_leak_check_accepts_explicit_cli_targets() {
        let core = AppCore::default();
        for target in ["example.com", "1.1.1.1"] {
            let entity = core.parse_entity(target).unwrap();
            let probe_ids = core
                .available_probes(&entity)
                .into_iter()
                .map(|probe| probe.id)
                .collect::<Vec<_>>();

            assert!(
                probe_ids.iter().any(|id| id == "dns.leak_check"),
                "dns.leak_check should apply to {target}"
            );
        }
    }

    #[test]
    fn default_core_keeps_public_active_probe_out_of_scope() {
        let core = AppCore::default();
        let entity = core.parse_entity("example.com").unwrap();

        assert!(matches!(
            core.scope_decision(&entity, ActionClass::ActiveProbe),
            ScopeDecision::Denied { .. }
        ));
    }

    #[test]
    fn command_invocation_requires_scope_for_public_active_probe() {
        let core = AppCore::default();
        let result = core.command_invocation_for_target(
            "connectivity.ping",
            &ProbeTarget::Input("example.com".into()),
        );

        assert!(matches!(result, Err(SonarError::ScopeDenied(_))));
    }

    #[test]
    fn command_invocation_allows_targetless_current_path_probe() {
        let core = AppCore::default();
        let invocation = core
            .command_invocation_for_target("public.egress_check", &ProbeTarget::CurrentInternetPath)
            .unwrap()
            .unwrap();

        assert!(!invocation.program.is_empty());
    }

    #[test]
    fn external_tool_requires_explicit_scope() {
        let core = AppCore::default();

        assert!(matches!(
            core.ensure_allowed_for_target(
                &ProbeTarget::CurrentInternetPath,
                ActionClass::ExternalTool
            ),
            Err(SonarError::ScopeDenied(_))
        ));
    }

    #[test]
    fn local_workflow_targets_are_beginner_safe() {
        let core = AppCore::default();
        let current_path = core
            .resolve_probe_target(&ProbeTarget::CurrentInternetPath)
            .unwrap();

        assert_eq!(
            core.scope_decision(&current_path, ActionClass::ActiveProbe),
            ScopeDecision::Allowed
        );
    }

    #[test]
    fn targetless_probe_targets_expose_local_workflows() {
        let core = AppCore::default();
        let local_probe_ids = core
            .available_probes_for_target(&ProbeTarget::LocalMachine)
            .unwrap()
            .into_iter()
            .map(|probe| probe.id)
            .collect::<Vec<_>>();
        let path_probe_ids = core
            .available_probes_for_target(&ProbeTarget::CurrentInternetPath)
            .unwrap()
            .into_iter()
            .map(|probe| probe.id)
            .collect::<Vec<_>>();

        assert!(local_probe_ids.iter().any(|id| id == "local.network_state"));
        assert!(local_probe_ids
            .iter()
            .any(|id| id == "local.listening_ports"));
        assert!(local_probe_ids
            .iter()
            .any(|id| id == "connectivity.route_check"));
        assert!(path_probe_ids.iter().any(|id| id == "public.egress_check"));
        assert!(path_probe_ids.iter().any(|id| id == "dns.leak_check"));
    }

    #[test]
    fn public_service_workflow_includes_local_network_state_for_nat_hints() {
        let core = AppCore::default();
        let workflow = core
            .workflows()
            .into_iter()
            .find(|workflow| workflow.id == "public_service")
            .unwrap();

        assert!(workflow
            .advanced_probe_ids
            .iter()
            .any(|id| id == "local.network_state"));
    }

    #[test]
    fn globalping_remote_plan_excludes_public_port_check() {
        let core = AppCore::default();
        let plan = core.remote_vantage_plan(
            RemoteVantageProvider::Globalping,
            RemoteMeasurementKind::Traceroute,
            ProbeTarget::Input("example.com".into()),
        );

        assert!(!plan
            .allowed_probe_ids
            .iter()
            .any(|id| id == "public.port_check"));
        assert!(plan.warning.is_some());
    }

    #[test]
    fn remote_scan_plan_allows_public_port_check() {
        let core = AppCore::default();
        let plan = core.remote_vantage_plan(
            RemoteVantageProvider::SonarNworkRemoteScan,
            RemoteMeasurementKind::TcpPort,
            ProbeTarget::Input("example.com:443".into()),
        );

        assert!(plan
            .allowed_probe_ids
            .iter()
            .any(|id| id == "public.port_check"));
        assert!(plan.warning.is_some());
    }

    #[test]
    fn globalping_tcp_port_plan_allows_public_port_check() {
        let core = AppCore::default();
        let plan = core.remote_vantage_plan(
            RemoteVantageProvider::Globalping,
            RemoteMeasurementKind::TcpPort,
            ProbeTarget::Input("example.com:443".into()),
        );

        assert!(plan
            .allowed_probe_ids
            .iter()
            .any(|id| id == "public.port_check"));
        assert!(plan.warning.is_some());
    }

    #[test]
    fn interpretation_includes_verdict_and_next_actions() {
        let core = AppCore::default();
        let descriptor = core.probe_descriptor("public.egress_check").unwrap();
        let output = ProbeOutput {
            summary: Some("Egress check completed.".into()),
            summary_rows: vec![SummaryRow::new("Public IP", "203.0.113.10")],
            ..ProbeOutput::default()
        };

        let interpretation = core.interpret_result(&descriptor, &output);

        assert_eq!(interpretation.verdict.status, VerdictStatus::Ok);
        assert!(interpretation.verdict.title.contains("203.0.113.10"));
        assert!(interpretation
            .next_actions
            .iter()
            .any(|action| action.probe_id == "dns.leak_check"));
    }

    #[test]
    fn ping_packet_loss_marks_verdict_warning() {
        let core = AppCore::default();
        let descriptor = core.probe_descriptor("connectivity.ping").unwrap();
        let output = ProbeOutput {
            summary: Some("Ping completed successfully.".into()),
            summary_rows: vec![
                SummaryRow::new("Target", "1.1.1.1"),
                SummaryRow::new("Latency", "avg 14 ms"),
                SummaryRow::new("Packet loss", "2%"),
            ],
            ..ProbeOutput::default()
        };

        let interpretation = core.interpret_result(&descriptor, &output);

        assert_eq!(interpretation.verdict.status, VerdictStatus::Warning);
        assert!(interpretation.verdict.title.contains("packet loss 2%"));
    }
}
