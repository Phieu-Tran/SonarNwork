use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{ActionClass, ExternalScannerKind};

pub const INTERACTION_SCHEMA_VERSION: u16 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionCatalog {
    pub schema_version: u16,
    pub namespaces: Vec<InteractionNamespace>,
}

impl InteractionCatalog {
    pub fn new(namespaces: Vec<InteractionNamespace>) -> Self {
        Self {
            schema_version: INTERACTION_SCHEMA_VERSION,
            namespaces,
        }
    }

    pub fn extend(&mut self, namespaces: impl IntoIterator<Item = InteractionNamespace>) {
        self.namespaces.extend(namespaces);
    }

    pub fn namespace(&self, id: &str) -> Option<&InteractionNamespace> {
        self.namespaces.iter().find(|item| item.id == id)
    }

    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.schema_version == 0 {
            return Err("interaction schema version must be non-zero".into());
        }

        let mut identities = HashSet::new();
        for namespace in &self.namespaces {
            namespace.validate()?;
            for identity in std::iter::once(&namespace.trigger).chain(namespace.aliases.iter()) {
                if !identities.insert(identity.to_ascii_lowercase()) {
                    return Err(format!(
                        "duplicate interaction trigger or alias: {identity}"
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionGroup {
    Diagnose,
    Scanner,
    Tooling,
    Remote,
    Capture,
    Inventory,
    Monitor,
    History,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionCapability {
    Status,
    Install,
    Update,
    Preview,
    Run,
    Stop,
    OpenInCli,
    View,
    Delete,
    Clear,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionFieldKind {
    Target,
    Text,
    Integer,
    Choice,
    Toggle,
    Ports,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionChoice {
    pub value: String,
    pub label: String,
    pub help: String,
    pub risk: Option<InteractionRisk>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionVisibility {
    pub field_id: String,
    pub equals: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionField {
    pub id: String,
    pub label: String,
    pub help: String,
    pub kind: InteractionFieldKind,
    pub required: bool,
    pub default_value: Option<String>,
    pub placeholder: Option<String>,
    pub choices: Vec<InteractionChoice>,
    pub visible_when: Option<InteractionVisibility>,
}

impl InteractionField {
    fn validate(&self, namespace_id: &str) -> std::result::Result<(), String> {
        if self.id.trim().is_empty() || self.label.trim().is_empty() {
            return Err(format!(
                "namespace {namespace_id} has a field with an empty id or label"
            ));
        }
        if self.kind == InteractionFieldKind::Choice && self.choices.is_empty() {
            return Err(format!(
                "choice field {namespace_id}.{} must declare choices",
                self.id
            ));
        }

        let mut choice_values = HashSet::new();
        for choice in &self.choices {
            if choice.value.trim().is_empty()
                || !choice_values.insert(choice.value.to_ascii_lowercase())
            {
                return Err(format!(
                    "field {namespace_id}.{} has an empty or duplicate choice",
                    self.id
                ));
            }
        }
        if self.kind == InteractionFieldKind::Choice
            && self
                .default_value
                .as_ref()
                .is_some_and(|default| !self.choices.iter().any(|choice| choice.value == *default))
        {
            return Err(format!(
                "field {namespace_id}.{} has a default outside its choices",
                self.id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionRisk {
    Safe,
    Medium,
    High,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionNamespace {
    pub id: String,
    pub trigger: String,
    pub aliases: Vec<String>,
    pub label: String,
    pub description: String,
    pub group: InteractionGroup,
    pub risk: InteractionRisk,
    pub action_class: ActionClass,
    pub fields: Vec<InteractionField>,
    pub capabilities: Vec<InteractionCapability>,
    pub examples: Vec<String>,
}

impl InteractionNamespace {
    fn validate(&self) -> std::result::Result<(), String> {
        if self.id.trim().is_empty() || self.label.trim().is_empty() {
            return Err("interaction namespace id and label must be non-empty".into());
        }
        if !valid_trigger(&self.trigger) {
            return Err(format!(
                "namespace {} has invalid trigger {}",
                self.id, self.trigger
            ));
        }
        if self.aliases.iter().any(|alias| !valid_trigger(alias)) {
            return Err(format!("namespace {} has an invalid alias", self.id));
        }

        let mut fields = HashSet::new();
        for field in &self.fields {
            if !fields.insert(field.id.to_ascii_lowercase()) {
                return Err(format!(
                    "namespace {} has duplicate field {}",
                    self.id, field.id
                ));
            }
            field.validate(&self.id)?;
        }
        for field in &self.fields {
            if let Some(visibility) = &field.visible_when {
                if !fields.contains(&visibility.field_id.to_ascii_lowercase()) {
                    return Err(format!(
                        "field {}.{} depends on unknown field {}",
                        self.id, field.id, visibility.field_id
                    ));
                }
            }
        }

        let mut capabilities = HashSet::new();
        if self
            .capabilities
            .iter()
            .any(|capability| !capabilities.insert(*capability))
        {
            return Err(format!("namespace {} has duplicate capabilities", self.id));
        }
        Ok(())
    }
}

fn valid_trigger(value: &str) -> bool {
    let Some(body) = value.strip_prefix('/') else {
        return false;
    };
    !body.is_empty()
        && body.split(' ').all(|token| {
            !token.is_empty()
                && token
                    .chars()
                    .all(|character| character.is_ascii_lowercase() || character == '-')
        })
}

pub fn core_interaction_catalog() -> InteractionCatalog {
    let catalog = InteractionCatalog::new(vec![
        namespace(
            "check",
            "Beginner check",
            "Choose a safe first probe for a target and show a structured verdict.",
            InteractionGroup::Diagnose,
            InteractionRisk::Safe,
            ActionClass::LocalInspection,
            vec![target_field(
                "target",
                "Target",
                "IP, domain, URL, or host:port",
            )],
            &[InteractionCapability::Run, InteractionCapability::View],
            &["/check 192.168.1.1", "/check example.com"],
        ),
        namespace(
            "ping",
            "Ping",
            "Measure local reachability and latency without changing the target.",
            InteractionGroup::Diagnose,
            InteractionRisk::Safe,
            ActionClass::ActiveProbe,
            vec![
                target_field("target", "Target", "IP address or domain"),
                integer_field("count", "Packets", "Number of echo requests", "4"),
                integer_field(
                    "timeout_ms",
                    "Timeout (ms)",
                    "Per-request timeout in milliseconds",
                    "1000",
                ),
                optional_integer_field(
                    "packet_size",
                    "Packet size",
                    "Optional payload size in bytes",
                ),
            ],
            &[InteractionCapability::Preview, InteractionCapability::Run],
            &["/ping 1.1.1.1", "/ping gateway.local"],
        ),
        namespace_with_aliases(
            "trace",
            &["mtr"],
            "Trace route",
            "Inspect hop-by-hop path behavior with an explicitly selected protocol.",
            InteractionGroup::Diagnose,
            InteractionRisk::Safe,
            ActionClass::ActiveProbe,
            vec![
                target_field("target", "Target", "IP address or domain"),
                choice_field(
                    "protocol",
                    "Protocol",
                    "Probe protocol",
                    "icmp",
                    &[
                        ("icmp", "ICMP", "Default route trace", None),
                        ("tcp", "TCP", "TCP-based trace", None),
                        ("udp", "UDP", "UDP-based trace", None),
                    ],
                ),
                optional_integer_field("port", "Port", "TCP/UDP destination port"),
                integer_field("max_hops", "Maximum hops", "Hop limit", "30"),
            ],
            &[InteractionCapability::Preview, InteractionCapability::Run],
            &["/trace example.com", "/mtr 1.1.1.1"],
        ),
        namespace(
            "dns",
            "DNS lookup",
            "Resolve one record through the local resolver or a selected server.",
            InteractionGroup::Diagnose,
            InteractionRisk::Safe,
            ActionClass::PassiveLookup,
            vec![
                target_field("domain", "Domain", "Domain name to resolve"),
                choice_field(
                    "record",
                    "Record",
                    "DNS record type",
                    "A",
                    &[
                        ("A", "A", "IPv4 address", None),
                        ("AAAA", "AAAA", "IPv6 address", None),
                        ("CNAME", "CNAME", "Canonical name", None),
                        ("MX", "MX", "Mail exchanger", None),
                        ("NS", "NS", "Authoritative name server", None),
                        ("TXT", "TXT", "Text record", None),
                    ],
                ),
                optional_text_field("server", "DNS server", "Optional resolver IP"),
            ],
            &[InteractionCapability::Preview, InteractionCapability::Run],
            &["/dns example.com", "/dns example.com --record MX"],
        ),
        namespace(
            "port",
            "Port check",
            "Check one host and one TCP port from this machine.",
            InteractionGroup::Diagnose, InteractionRisk::Safe, ActionClass::ActiveProbe,
            vec![
                target_field("host", "Host", "IP address or domain"),
                integer_field("port", "Port", "TCP destination port", "443"),
                integer_field(
                    "timeout_ms",
                    "Timeout (ms)",
                    "Connection timeout in milliseconds",
                    "3000",
                ),
            ],
            &[InteractionCapability::Run],
            &["/port example.com --port 443"],
        ),
        namespace(
            "myip",
            "My Internet path",
            "Show this machine's public egress and resolver path.",
            InteractionGroup::Diagnose, InteractionRisk::Safe, ActionClass::PassiveLookup,
            vec![],
            &[InteractionCapability::Run],
            &["/myip"],
        ),
        namespace(
            "probe",
            "Core probe",
            "Select a registered core probe for a parsed target.",
            InteractionGroup::Diagnose, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![
                text_field("probe_id", "Probe", "Registered probe ID", true),
                target_field("target", "Target", "Target accepted by the selected probe"),
            ],
            &[InteractionCapability::Preview, InteractionCapability::Run],
            &["/probe connectivity.ping 192.168.1.1"],
        ),
        namespace(
            "tools",
            "Tool packages",
            "Browse plugin status, install policy, path, version, and supported actions.",
            InteractionGroup::Tooling, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![],
            &[InteractionCapability::Status, InteractionCapability::View],
            &["/tools"],
        ),
        InteractionNamespace {
            id: "open-ui".into(),
            trigger: "/open ui".into(),
            aliases: vec!["/ui".into()],
            label: "Open desktop app".into(),
            description: "Launch the SonarNwork desktop interface from this terminal.".into(),
            group: InteractionGroup::Tooling,
            risk: InteractionRisk::Safe, action_class: ActionClass::LocalInspection, fields: vec![], capabilities: vec![InteractionCapability::View], examples: vec!["/open ui".into()],
        },
        InteractionNamespace {
            id: "app-update".into(),
            trigger: "/update".into(),
            aliases: vec!["/upgrade".into()],
            label: "Update SonarNwork".into(),
            description: "Install the latest published SonarNwork version through the current install channel.".into(),
            group: InteractionGroup::Tooling,
            risk: InteractionRisk::Safe, action_class: ActionClass::LocalInspection, fields: vec![confirmation_field("confirm", "Confirm update")], capabilities: vec![InteractionCapability::Update], examples: vec!["/update".into()],
        },
        namespace(
            "tool-status",
            "Tool status",
            "Check one plugin executable path and version without running it.",
            InteractionGroup::Tooling, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![text_field("tool_id", "Tool", "Plugin/tool ID", true)],
            &[InteractionCapability::Status],
            &["/tool-status nmap"],
        ),
        namespace(
            "tool-lifecycle",
            "Tool lifecycle",
            "Inspect the install/update policy for one plugin package.",
            InteractionGroup::Tooling, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![text_field("tool_id", "Tool", "Plugin/tool ID", true)],
            &[InteractionCapability::View],
            &["/tool-lifecycle nuclei"],
        ),
        namespace(
            "tool-install",
            "Install tool package",
            "Explicitly install or hand off the official installer for one plugin.",
            InteractionGroup::Tooling, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![
                text_field("tool_id", "Tool", "Plugin/tool ID", true),
                confirmation_field("confirm", "Confirm install"),
            ],
            &[InteractionCapability::Install],
            &["/tool-install nuclei"],
        ),
        namespace(
            "tool-update",
            "Update tool package",
            "Explicitly update one managed plugin package.",
            InteractionGroup::Tooling, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![
                text_field("tool_id", "Tool", "Plugin/tool ID", true),
                confirmation_field("confirm", "Confirm update"),
            ],
            &[InteractionCapability::Update],
            &["/tool-update nuclei"],
        ),
        namespace(
            "globalping",
            "Remote measurement",
            "Run a bounded Globalping measurement; this is not a public port scan.",
            InteractionGroup::Remote, InteractionRisk::Medium, ActionClass::ActiveProbe,
            vec![
                target_field("target", "Target", "Public target accepted by Globalping"),
                choice_field(
                    "measurement",
                    "Measurement",
                    "Remote measurement type",
                    "ping",
                    &[
                        ("ping", "Ping", "Remote latency and reachability", None),
                        ("trace", "Trace", "Remote route trace", None),
                        ("mtr", "MTR", "Remote loss and latency path", None),
                        ("dns", "DNS", "Remote DNS resolution", None),
                        ("http", "HTTP", "Remote HTTP request", None),
                    ],
                ),
                optional_text_field("location", "Location", "Optional probe location hint"),
            ],
            &[InteractionCapability::Preview, InteractionCapability::Run],
            &["/globalping example.com"],
        ),
        namespace(
            "remote-port",
            "Remote port check",
            "Run a bounded single-port TCP check through the configured remote provider.",
            InteractionGroup::Remote, InteractionRisk::Medium, ActionClass::ActiveProbe,
            vec![
                target_field("target", "Public host", "Public IP address or domain"),
                integer_field("port", "Port", "One TCP port", "443"),
            ],
            &[InteractionCapability::Preview, InteractionCapability::Run],
            &["/remote-port example.com --port 443"],
        ),
        namespace(
            "capture",
            "Packet capture",
            "Capture a bounded packet sample and explicitly hand off the resulting file.",
            InteractionGroup::Capture, InteractionRisk::High, ActionClass::IntrusiveScan,
            vec![
                text_field("interface_id", "Interface", "Capture interface ID", true),
                integer_field(
                    "duration_seconds",
                    "Duration (seconds)",
                    "Bounded capture duration",
                    "10",
                ),
                integer_field(
                    "packet_limit",
                    "Packet limit",
                    "Maximum packets to capture",
                    "500",
                ),
            ],
            &[
                InteractionCapability::Status,
                InteractionCapability::Run,
                InteractionCapability::OpenInCli,
            ],
            &["/capture"],
        ),
        namespace(
            "capture-status",
            "Capture runtime status",
            "Check TShark/Wireshark availability and version.",
            InteractionGroup::Capture, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![],
            &[InteractionCapability::Status],
            &["/capture-status"],
        ),
        namespace(
            "capture-interfaces",
            "Capture interfaces",
            "List packet capture interface IDs exposed by TShark.",
            InteractionGroup::Capture, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![],
            &[InteractionCapability::View],
            &["/capture-interfaces"],
        ),
        namespace(
            "capture-open",
            "Open packet capture",
            "Hand off one SonarNwork pcapng file to Wireshark or the file manager.",
            InteractionGroup::Capture, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![text_field(
                "path",
                "Capture path",
                "Path returned by a completed SonarNwork capture",
                true,
            )],
            &[InteractionCapability::OpenInCli],
            &["/capture-open <capture.pcapng>"],
        ),
        namespace(
            "inventory",
            "Device inventory",
            "Collect a passive local neighbor inventory snapshot.",
            InteractionGroup::Inventory, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![],
            &[InteractionCapability::Run, InteractionCapability::View],
            &["/inventory"],
        ),
        namespace(
            "monitor",
            "Background monitor",
            "Monitor a target while the application is running and record threshold events.",
            InteractionGroup::Monitor, InteractionRisk::Medium, ActionClass::ActiveProbe,
            vec![
                target_field("target", "Target", "IP address or domain"),
                integer_field(
                    "interval_seconds",
                    "Interval (seconds)",
                    "Time between checks",
                    "30",
                ),
                integer_field(
                    "latency_alert_ms",
                    "Latency alert (ms)",
                    "Create an event above this latency",
                    "250",
                ),
                integer_field(
                    "loss_alert_percent",
                    "Loss alert (%)",
                    "Create an event at or above this loss",
                    "25",
                ),
            ],
            &[
                InteractionCapability::Run,
                InteractionCapability::Stop,
                InteractionCapability::View,
            ],
            &["/monitor 192.168.1.1"],
        ),
        namespace(
            "monitor-list",
            "List monitors",
            "Show persisted monitor configurations and whether each is enabled.",
            InteractionGroup::Monitor, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![],
            &[InteractionCapability::View],
            &["/monitor-list"],
        ),
        namespace(
            "monitor-stop",
            "Stop monitor",
            "Stop one persisted monitor by ID.",
            InteractionGroup::Monitor, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![text_field(
                "monitor_id",
                "Monitor ID",
                "Persisted monitor ID",
                true,
            )],
            &[InteractionCapability::Stop],
            &["/monitor-stop <id>"],
        ),
        namespace(
            "timeline",
            "Event timeline",
            "Browse or explicitly clear persisted monitoring and operation events.",
            InteractionGroup::History, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![],
            &[InteractionCapability::View, InteractionCapability::Clear],
            &["/timeline"],
        ),
        namespace(
            "timeline-clear",
            "Clear event timeline",
            "Explicitly clear all persisted monitoring and operation events.",
            InteractionGroup::History, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![confirmation_field("confirm", "Confirm clear")],
            &[InteractionCapability::Clear],
            &["/timeline-clear"],
        ),
        namespace(
            "history",
            "Run history",
            "Browse, compare, or explicitly delete saved structured runs.",
            InteractionGroup::History, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![],
            &[InteractionCapability::View, InteractionCapability::Delete],
            &["/history"],
        ),
        namespace(
            "history-get",
            "Open saved run",
            "Load one saved structured run by ID.",
            InteractionGroup::History, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![text_field("run_id", "Run ID", "Saved run ID", true)],
            &[InteractionCapability::View],
            &["/history-get <id>"],
        ),
        namespace(
            "history-compare",
            "Compare saved runs",
            "Compare two runs of the same probe and normalized target.",
            InteractionGroup::History, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![
                text_field("left_id", "Earlier run", "Earlier saved run ID", true),
                text_field("right_id", "Later run", "Later saved run ID", true),
            ],
            &[InteractionCapability::View],
            &["/history-compare <left-id> <right-id>"],
        ),
        namespace(
            "history-delete",
            "Delete saved run",
            "Explicitly delete one saved structured run.",
            InteractionGroup::History, InteractionRisk::Safe, ActionClass::LocalInspection,
            vec![
                text_field("run_id", "Run ID", "Saved run ID", true),
                confirmation_field("confirm", "Confirm delete"),
            ],
            &[InteractionCapability::Delete],
            &["/history-delete <id>"],
        ),
    ]);
    debug_assert!(catalog.validate().is_ok());
    catalog
}

pub fn scanner_interaction_namespace(kind: ExternalScannerKind) -> InteractionNamespace {
    let target = target_field("target", "Target", scanner_target_help(kind));
    let (label, description, fields, examples) = match kind {
        ExternalScannerKind::Nmap => (
            "Nmap",
            "Discover hosts, ports, services, and versions with an explicit bounded profile.",
            vec![
                target,
                choice_field(
                    "profile",
                    "Scan profile",
                    "Only Nmap profiles are valid in this namespace",
                    "nmap_top_ports",
                    &[
                        ("nmap_top_ports", "Top ports", "Fast common-port discovery", Some(InteractionRisk::Safe)),
                        ("nmap_version", "Version", "Light service/version detection", Some(InteractionRisk::Medium)),
                        (
                            "nmap_service_deep",
                            "Deep service",
                            "More detailed service detection",
                            Some(InteractionRisk::Medium),
                        ),
                        ("nmap_udp_quick", "Quick UDP", "Bounded UDP discovery", Some(InteractionRisk::Medium)),
                    ],
                ),
                choice_field(
                    "ports",
                    "Ports",
                    "Port selection for the Nmap profile",
                    "top",
                    &[
                        ("top", "Top", "Profile-selected common ports", Some(InteractionRisk::Safe)),
                        ("all", "All", "All ports; slower and more intrusive", Some(InteractionRisk::Medium)),
                        ("custom", "Custom", "Explicit list or ranges", Some(InteractionRisk::Medium)),
                    ],
                ),
                InteractionField {
                    visible_when: Some(InteractionVisibility {
                        field_id: "ports".into(),
                        equals: "custom".into(),
                    }),
                    ..text_field(
                        "custom_ports",
                        "Custom ports",
                        "Comma-separated ports or ranges, for example 22,80,443,8000-8100",
                        true,
                    )
                },
            ],
            vec!["/nmap 192.168.1.10", "/nmap 192.168.1.0/24"],
        ),
        ExternalScannerKind::Nuclei => (
            "Nuclei",
            "Run a bounded template-based security scan with Nuclei-only profiles.",
            vec![
                target,
                choice_field(
                    "profile",
                    "Template profile",
                    "Only Nuclei profiles are valid in this namespace",
                    "nuclei_safe",
                    &[
                        ("nuclei_safe", "Safe", "Lower-impact template set", Some(InteractionRisk::Safe)),
                        (
                            "nuclei_http_exposure",
                            "HTTP exposure",
                            "Web exposure and misconfiguration templates",
                            Some(InteractionRisk::Medium),
                        ),
                        (
                            "nuclei_known_vulns",
                            "Known vulnerabilities",
                            "Known-vulnerability templates",
                            Some(InteractionRisk::Medium),
                        ),
                        ("nuclei_full", "Full", "Broad intrusive template profile", Some(InteractionRisk::High)),
                    ],
                ),
            ],
            vec!["/nuclei https://example.com"],
        ),
        ExternalScannerKind::Httpx => (
            "httpx",
            "Probe one web target and retain structured response metadata.",
            vec![target],
            vec!["/httpx https://example.com"],
        ),
        ExternalScannerKind::Naabu => (
            "naabu",
            "Discover ports on one host with bounded settings.",
            vec![
                target,
                ports_field("ports", "Ports", "Optional ports or ranges"),
            ],
            vec!["/naabu 192.168.1.10"],
        ),
        ExternalScannerKind::Subfinder => (
            "subfinder",
            "Perform passive subdomain discovery for one domain.",
            vec![target],
            vec!["/subfinder example.com"],
        ),
        ExternalScannerKind::Dnsx => (
            "dnsx",
            "Resolve one domain with the managed dnsx runner.",
            vec![target],
            vec!["/dnsx example.com"],
        ),
        ExternalScannerKind::Trippy => (
            "Trippy",
            "Inspect route latency and loss with the managed Trippy runner.",
            vec![target],
            vec!["/trippy 1.1.1.1"],
        ),
        ExternalScannerKind::Nexttrace => (
            "NextTrace",
            "Inspect a route with ASN and geographic enrichment when available.",
            vec![target],
            vec!["/nexttrace 1.1.1.1"],
        ),
    };

    InteractionNamespace {
        id: format!("scanner.{}", kind.tool_id()),
        trigger: format!("/{}", kind.tool_id()),
        aliases: vec![],
        label: label.into(),
        description: description.into(),
        group: InteractionGroup::Scanner,
        risk: InteractionRisk::Safe, action_class: kind.action_class(),
        fields,
        capabilities: vec![
            InteractionCapability::Status,
            InteractionCapability::Preview,
            InteractionCapability::Run,
            InteractionCapability::Stop,
            InteractionCapability::OpenInCli,
        ],
        examples: examples.into_iter().map(str::to_string).collect(),
    }
}

fn scanner_target_help(kind: ExternalScannerKind) -> &'static str {
    match kind {
        ExternalScannerKind::Nmap | ExternalScannerKind::Naabu => "Single IP, host, or CIDR",
        ExternalScannerKind::Nuclei | ExternalScannerKind::Httpx => "HTTP(S) URL or host",
        ExternalScannerKind::Subfinder | ExternalScannerKind::Dnsx => "Domain name",
        ExternalScannerKind::Trippy | ExternalScannerKind::Nexttrace => "IP address or domain",
    }
}

#[allow(clippy::too_many_arguments)]
fn namespace(
    id: &str,
    label: &str,
    description: &str,
    group: InteractionGroup,
    risk: InteractionRisk,
    action_class: ActionClass,
    fields: Vec<InteractionField>,
    capabilities: &[InteractionCapability],
    examples: &[&str],
) -> InteractionNamespace {
    namespace_with_aliases(
        id,
        &[],
        label,
        description,
        group,
        risk,
        action_class,
        fields,
        capabilities,
        examples,
    )
}

#[allow(clippy::too_many_arguments)]
fn namespace_with_aliases(
    id: &str,
    aliases: &[&str],
    label: &str,
    description: &str,
    group: InteractionGroup,
    risk: InteractionRisk,
    action_class: ActionClass,
    fields: Vec<InteractionField>,
    capabilities: &[InteractionCapability],
    examples: &[&str],
) -> InteractionNamespace {
    InteractionNamespace {
        id: id.into(),
        trigger: format!("/{id}"),
        aliases: aliases.iter().map(|alias| format!("/{alias}")).collect(),
        label: label.into(),
        description: description.into(),
        group,
        risk,
        action_class,
        fields,
        capabilities: capabilities.to_vec(),
        examples: examples.iter().map(|example| (*example).into()).collect(),
    }
}

fn target_field(id: &str, label: &str, help: &str) -> InteractionField {
    InteractionField {
        id: id.into(),
        label: label.into(),
        help: help.into(),
        kind: InteractionFieldKind::Target,
        required: true,
        default_value: None,
        placeholder: Some(help.into()),
        choices: vec![],
        visible_when: None,
    }
}

fn text_field(id: &str, label: &str, help: &str, required: bool) -> InteractionField {
    InteractionField {
        id: id.into(),
        label: label.into(),
        help: help.into(),
        kind: InteractionFieldKind::Text,
        required,
        default_value: None,
        placeholder: Some(help.into()),
        choices: vec![],
        visible_when: None,
    }
}

fn optional_text_field(id: &str, label: &str, help: &str) -> InteractionField {
    text_field(id, label, help, false)
}

fn integer_field(id: &str, label: &str, help: &str, default: &str) -> InteractionField {
    InteractionField {
        id: id.into(),
        label: label.into(),
        help: help.into(),
        kind: InteractionFieldKind::Integer,
        required: true,
        default_value: Some(default.into()),
        placeholder: None,
        choices: vec![],
        visible_when: None,
    }
}

fn optional_integer_field(id: &str, label: &str, help: &str) -> InteractionField {
    InteractionField {
        id: id.into(),
        label: label.into(),
        help: help.into(),
        kind: InteractionFieldKind::Integer,
        required: false,
        default_value: None,
        placeholder: None,
        choices: vec![],
        visible_when: None,
    }
}

fn ports_field(id: &str, label: &str, help: &str) -> InteractionField {
    InteractionField {
        kind: InteractionFieldKind::Ports,
        ..text_field(id, label, help, false)
    }
}

fn choice_field(
    id: &str,
    label: &str,
    help: &str,
    default: &str,
    choices: &[(&str, &str, &str, Option<InteractionRisk>)],
) -> InteractionField {
    InteractionField {
        id: id.into(),
        label: label.into(),
        help: help.into(),
        kind: InteractionFieldKind::Choice,
        required: true,
        default_value: Some(default.into()),
        placeholder: None,
        choices: choices
            .iter()
            .map(|(value, label, help, risk)| InteractionChoice {
                value: (*value).into(),
                label: (*label).into(),
                help: (*help).into(),
                risk: *risk,
            })
            .collect(),
        visible_when: None,
    }
}

fn confirmation_field(id: &str, label: &str) -> InteractionField {
    choice_field(
        id,
        label,
        "Select Yes only after reviewing the destructive or mutating action",
        "no",
        &[
            ("no", "No", "Do not perform the action", None),
            ("yes", "Yes", "I explicitly confirm this action", None),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_catalog_is_valid_and_covers_desktop_operation_families() {
        let catalog = core_interaction_catalog();
        catalog.validate().unwrap();
        for id in [
            "ping",
            "trace",
            "dns",
            "globalping",
            "capture",
            "inventory",
            "monitor",
            "timeline",
            "history",
        ] {
            assert!(catalog.namespace(id).is_some(), "missing namespace {id}");
        }
        assert_eq!(catalog.namespace("open-ui").unwrap().trigger, "/open ui");
        assert_eq!(catalog.namespace("app-update").unwrap().trigger, "/update");
    }

    #[test]
    fn trigger_allows_separated_lowercase_command_tokens() {
        assert!(valid_trigger("/open ui"));
        assert!(valid_trigger("/open-ui"));
        assert!(!valid_trigger("/open  ui"));
        assert!(!valid_trigger("/Open ui"));
    }

    #[test]
    fn nuclei_profile_risk_labels_are_correct() {
        let nuclei = scanner_interaction_namespace(ExternalScannerKind::Nuclei);
        let profile_field = nuclei.fields.iter().find(|f| f.id == "profile").unwrap();

        let safe = profile_field.choices.iter().find(|c| c.value == "nuclei_safe").unwrap();
        assert_eq!(safe.risk, Some(InteractionRisk::Safe));

        let full = profile_field.choices.iter().find(|c| c.value == "nuclei_full").unwrap();
        assert_eq!(full.risk, Some(InteractionRisk::High));
    }

    #[test]
    fn nmap_profile_risk_labels_are_correct() {
        let nmap = scanner_interaction_namespace(ExternalScannerKind::Nmap);
        let profile_field = nmap.fields.iter().find(|f| f.id == "profile").unwrap();

        let top = profile_field.choices.iter().find(|c| c.value == "nmap_top_ports").unwrap();
        assert_eq!(top.risk, Some(InteractionRisk::Safe));

        let deep = profile_field.choices.iter().find(|c| c.value == "nmap_service_deep").unwrap();
        assert_eq!(deep.risk, Some(InteractionRisk::Medium));
    }

    #[test]
    fn nmap_and_nuclei_forms_cannot_share_profiles_or_ports() {
        let nmap = scanner_interaction_namespace(ExternalScannerKind::Nmap);
        let nuclei = scanner_interaction_namespace(ExternalScannerKind::Nuclei);

        let nmap_profile = nmap
            .fields
            .iter()
            .find(|field| field.id == "profile")
            .unwrap();
        let nuclei_profile = nuclei
            .fields
            .iter()
            .find(|field| field.id == "profile")
            .unwrap();
        assert!(nmap_profile
            .choices
            .iter()
            .all(|choice| choice.value.starts_with("nmap_")));
        assert!(nuclei_profile
            .choices
            .iter()
            .all(|choice| choice.value.starts_with("nuclei_")));
        assert!(nmap.fields.iter().any(|field| field.id == "ports"));
        assert!(!nuclei.fields.iter().any(|field| field.id == "ports"));
    }

    #[test]
    fn duplicate_aliases_are_rejected() {
        let mut first = scanner_interaction_namespace(ExternalScannerKind::Nmap);
        let mut second = scanner_interaction_namespace(ExternalScannerKind::Nuclei);
        first.aliases.push("/scan".into());
        second.aliases.push("/scan".into());
        let error = InteractionCatalog::new(vec![first, second])
            .validate()
            .unwrap_err();
        assert!(error.contains("duplicate"));
    }
}
