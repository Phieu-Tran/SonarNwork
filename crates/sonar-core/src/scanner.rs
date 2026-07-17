use std::{net::IpAddr, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    entity::Entity,
    error::{Result, SonarError},
    probe::{CommandInvocation, ProbeOutput, SummaryRow},
    scope::ActionClass,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalScannerKind {
    Nmap,
    Nuclei,
    Httpx,
    Naabu,
    Subfinder,
    Dnsx,
    Trippy,
    Nexttrace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalScannerMode {
    Default,
    NmapTopPorts,
    NmapVersion,
    NmapServiceDeep,
    NmapUdpQuick,
    NucleiSafe,
    NucleiHttpExposure,
    NucleiKnownVulns,
    NucleiFull,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalScannerPorts {
    Default,
    Top,
    All,
    Custom(String),
}

impl ExternalScannerKind {
    pub fn from_tool_id(tool_id: &str) -> Option<Self> {
        match tool_id {
            "nmap" => Some(Self::Nmap),
            "nuclei" => Some(Self::Nuclei),
            "httpx" => Some(Self::Httpx),
            "naabu" => Some(Self::Naabu),
            "subfinder" => Some(Self::Subfinder),
            "dnsx" => Some(Self::Dnsx),
            "trippy" => Some(Self::Trippy),
            "nexttrace" => Some(Self::Nexttrace),
            _ => None,
        }
    }

    pub fn tool_id(self) -> &'static str {
        match self {
            Self::Nmap => "nmap",
            Self::Nuclei => "nuclei",
            Self::Httpx => "httpx",
            Self::Naabu => "naabu",
            Self::Subfinder => "subfinder",
            Self::Dnsx => "dnsx",
            Self::Trippy => "trippy",
            Self::Nexttrace => "nexttrace",
        }
    }

    pub fn action_class(self) -> ActionClass {
        match self {
            Self::Nmap => ActionClass::ActiveProbe,
            Self::Nuclei => ActionClass::IntrusiveScan,
            Self::Httpx | Self::Trippy | Self::Nexttrace => ActionClass::ActiveProbe,
            Self::Naabu | Self::Dnsx => ActionClass::IntrusiveScan,
            Self::Subfinder => ActionClass::PassiveLookup,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalScannerProfile {
    pub kind: ExternalScannerKind,
    pub target: String,
    pub mode: ExternalScannerMode,
    pub ports: ExternalScannerPorts,
}

#[derive(Clone, Debug, Serialize)]
struct NmapHostPorts {
    host: String,
    ports: Vec<NmapOpenPort>,
}

#[derive(Clone, Debug, Serialize)]
struct NmapOpenPort {
    port: u16,
    proto: String,
    service: String,
    detail: String,
}

impl ExternalScannerProfile {
    pub fn new(kind: ExternalScannerKind, target: impl Into<String>) -> Result<Self> {
        let target = target.into().trim().to_string();
        if target.is_empty()
            || target.starts_with('-')
            || target.chars().any(char::is_control)
            || target.chars().any(char::is_whitespace)
        {
            return Err(SonarError::InvalidTarget(target));
        }
        Ok(Self {
            kind,
            target,
            mode: ExternalScannerMode::Default,
            ports: ExternalScannerPorts::Default,
        })
    }

    pub fn for_entity(kind: ExternalScannerKind, entity: &Entity) -> Result<Self> {
        Self::new(kind, scanner_target(kind, entity))
    }

    pub fn with_mode(mut self, mode: ExternalScannerMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_ports(mut self, ports: ExternalScannerPorts) -> Result<Self> {
        validate_scanner_ports(&ports)?;
        self.ports = ports;
        Ok(self)
    }

    pub fn invocation(&self, executable: &Path) -> CommandInvocation {
        let program = executable.to_string_lossy().to_string();
        match self.kind {
            ExternalScannerKind::Nmap => self.nmap_invocation(program),
            ExternalScannerKind::Nuclei => self.nuclei_invocation(program),
            ExternalScannerKind::Httpx => self.httpx_invocation(program),
            ExternalScannerKind::Naabu => self.naabu_invocation(program),
            ExternalScannerKind::Subfinder => self.subfinder_invocation(program),
            ExternalScannerKind::Dnsx => self.dnsx_invocation(program),
            ExternalScannerKind::Trippy => self.trippy_invocation(program),
            ExternalScannerKind::Nexttrace => self.nexttrace_invocation(program),
        }
    }

    fn nmap_invocation(&self, program: String) -> CommandInvocation {
        let mut args: Vec<String> = match self.mode {
            ExternalScannerMode::NmapVersion => {
                vec!["-sV".into(), "-T4".into(), "--open".into()]
            }
            ExternalScannerMode::NmapServiceDeep => {
                vec!["-sV".into(), "-A".into(), "-T4".into(), "--open".into()]
            }
            ExternalScannerMode::NmapUdpQuick => {
                vec!["-sU".into(), "-T3".into(), "--open".into()]
            }
            _ => vec!["-sT".into(), "-T4".into(), "--open".into()],
        };

        match &self.ports {
            ExternalScannerPorts::Default | ExternalScannerPorts::Top => {
                let count = if matches!(self.mode, ExternalScannerMode::NmapServiceDeep) {
                    "1000"
                } else if matches!(self.mode, ExternalScannerMode::NmapUdpQuick) {
                    "25"
                } else {
                    "100"
                };
                args.extend(["--top-ports".into(), count.into()]);
            }
            ExternalScannerPorts::All => args.push("-p-".into()),
            ExternalScannerPorts::Custom(ports) => args.extend(["-p".into(), ports.clone()]),
        }
        args.push(self.target.clone());

        CommandInvocation::from_parts(program, args)
    }

    fn nuclei_invocation(&self, program: String) -> CommandInvocation {
        let severity = match self.mode {
            ExternalScannerMode::NucleiSafe => "medium,high,critical",
            ExternalScannerMode::NucleiHttpExposure => "info,low,medium,high,critical",
            ExternalScannerMode::NucleiFull => "info,low,medium,high,critical",
            _ => "low,medium,high,critical",
        };
        let mut args = vec![
            "-u",
            &self.target,
            "-silent",
            "-jsonl",
            "-severity",
            severity,
            "-no-interactsh",
            "-rate-limit",
            "50",
            "-concurrency",
            "10",
            "-timeout",
            "10",
            "-retries",
            "1",
        ];
        match self.mode {
            ExternalScannerMode::NucleiSafe => args.extend(["-tags", "exposure,misconfig"]),
            ExternalScannerMode::NucleiHttpExposure => args.extend(["-tags", "exposure,http"]),
            ExternalScannerMode::NucleiKnownVulns => args.extend(["-tags", "cve,rce,lfi,sqli,xss"]),
            ExternalScannerMode::NucleiFull => {}
            _ => {}
        }
        CommandInvocation::from_parts(program, args)
    }

    fn httpx_invocation(&self, program: String) -> CommandInvocation {
        CommandInvocation::from_parts(
            program,
            vec![
                "-u",
                &self.target,
                "-silent",
                "-json",
                "-status-code",
                "-title",
                "-tech-detect",
                "-follow-redirects",
                "-timeout",
                "10",
                "-retries",
                "1",
                "-threads",
                "10",
                "-rate-limit",
                "20",
            ],
        )
    }

    fn naabu_invocation(&self, program: String) -> CommandInvocation {
        let mut args = vec![
            "-host".to_string(),
            self.target.clone(),
            "-scan-type".into(),
            "c".into(),
            "-silent".into(),
            "-json".into(),
            "-verify".into(),
            "-rate".into(),
            "100".into(),
            "-c".into(),
            "10".into(),
            "-retries".into(),
            "1".into(),
        ];
        match &self.ports {
            ExternalScannerPorts::Default | ExternalScannerPorts::Top => {
                args.extend(["-top-ports".into(), "100".into()]);
            }
            ExternalScannerPorts::All => args.extend(["-top-ports".into(), "full".into()]),
            ExternalScannerPorts::Custom(ports) => {
                args.extend(["-p".into(), ports.clone()]);
            }
        }
        CommandInvocation::from_parts(program, args)
    }

    fn subfinder_invocation(&self, program: String) -> CommandInvocation {
        CommandInvocation::from_parts(
            program,
            vec![
                "-d",
                &self.target,
                "-silent",
                "-json",
                "-timeout",
                "10",
                "-max-time",
                "1",
            ],
        )
    }

    fn dnsx_invocation(&self, program: String) -> CommandInvocation {
        // dnsx accepts a domain and comma-separated wordlist without a shell/stdin pipeline.
        // Keep this UI profile deliberately small: three common names, ten queries/second.
        CommandInvocation::from_parts(
            program,
            vec![
                "-d",
                &self.target,
                "-w",
                "www,mail,api",
                "-silent",
                "-json",
                "-resp",
                "-retry",
                "1",
                "-threads",
                "5",
                "-rate-limit",
                "10",
            ],
        )
    }

    fn trippy_invocation(&self, program: String) -> CommandInvocation {
        CommandInvocation::from_parts(
            program,
            vec![
                "--mode",
                "json",
                "--report-cycles",
                "1",
                "--unprivileged",
                &self.target,
            ],
        )
    }

    fn nexttrace_invocation(&self, program: String) -> CommandInvocation {
        CommandInvocation::from_parts(
            program,
            vec![
                "--json",
                "--no-color",
                "--queries",
                "3",
                "--max-attempts",
                "5",
                "--parallel-requests",
                "6",
                "--timeout",
                "1000",
                &self.target,
            ],
        )
    }
}

fn scanner_target(kind: ExternalScannerKind, entity: &Entity) -> String {
    match kind {
        ExternalScannerKind::Nuclei | ExternalScannerKind::Httpx => scanner_url_target(entity),
        ExternalScannerKind::Nmap
        | ExternalScannerKind::Naabu
        | ExternalScannerKind::Subfinder
        | ExternalScannerKind::Dnsx
        | ExternalScannerKind::Trippy
        | ExternalScannerKind::Nexttrace => scanner_host_target(entity),
    }
}

fn scanner_host_target(entity: &Entity) -> String {
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

fn scanner_url_target(entity: &Entity) -> String {
    match entity {
        Entity::Url(url) => url.as_str().to_string(),
        Entity::Port(port) => format!("https://{}:{}", url_host(&port.ip), port.port),
        Entity::Ip(ip) => format!("https://{}", url_host(ip)),
        Entity::Domain(domain) => format!("https://{}", domain.normalized),
        Entity::Host(host) => host
            .ip
            .map(|ip| format!("https://{}", url_host(&ip)))
            .unwrap_or_else(|| format!("https://{}", host.name)),
        _ => format!("https://{}", scanner_host_target(entity)),
    }
}

fn url_host(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => ip.to_string(),
        IpAddr::V6(_) => format!("[{ip}]"),
    }
}

fn validate_scanner_ports(ports: &ExternalScannerPorts) -> Result<()> {
    let ExternalScannerPorts::Custom(value) = ports else {
        return Ok(());
    };

    if value.trim() != value || value.is_empty() {
        return Err(SonarError::InvalidTarget(value.clone()));
    }

    for part in value.split(',') {
        validate_port_part(value, part)?;
    }

    Ok(())
}

fn validate_port_part(original: &str, part: &str) -> Result<()> {
    if part.is_empty() {
        return Err(SonarError::InvalidTarget(original.into()));
    }

    if let Some((start, end)) = part.split_once('-') {
        let start = parse_port_number(original, start)?;
        let end = parse_port_number(original, end)?;
        if start > end {
            return Err(SonarError::InvalidTarget(original.into()));
        }
        return Ok(());
    }

    parse_port_number(original, part).map(|_| ())
}

fn parse_port_number(original: &str, value: &str) -> Result<u16> {
    let port = value
        .parse::<u16>()
        .map_err(|_| SonarError::InvalidTarget(original.into()))?;
    if port == 0 {
        return Err(SonarError::InvalidTarget(original.into()));
    }
    Ok(port)
}

pub fn summarize_scanner_output(
    kind: ExternalScannerKind,
    exit_code: Option<i32>,
    stdout: &[String],
    stderr: &[String],
) -> ProbeOutput {
    match kind {
        ExternalScannerKind::Nmap => summarize_nmap(exit_code, stdout, stderr),
        ExternalScannerKind::Nuclei => summarize_nuclei(exit_code, stdout, stderr),
        ExternalScannerKind::Httpx => summarize_httpx(exit_code, stdout, stderr),
        ExternalScannerKind::Naabu
        | ExternalScannerKind::Subfinder
        | ExternalScannerKind::Dnsx
        | ExternalScannerKind::Trippy
        | ExternalScannerKind::Nexttrace => summarize_json_lines(kind, exit_code, stdout, stderr),
    }
}

fn summarize_httpx(
    _exit_code: Option<i32>,
    stdout: &[String],
    stderr: &[String],
) -> ProbeOutput {
    // Track status-code distribution; 0 means unresolvable/unreachable
    let mut total = 0usize;
    let mut by_status: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
    let mut all_tech: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for line in stdout {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
            total += 1;
            if let Some(code) = value.get("status_code").and_then(|v| v.as_u64()) {
                *by_status.entry(code as u16).or_insert(0) += 1;
            }
            if let Some(tech) = value
                .get("tech")
                .or_else(|| value.get("technologies"))
                .and_then(|v| v.as_array())
            {
                for t in tech {
                    if let Some(s) = t.as_str() {
                        all_tech.insert(s.to_string());
                    }
                }
            }
        }
        // Malformed JSON lines are silently skipped — no panic.
    }

    let mut rows = vec![SummaryRow::new("Hosts", total.to_string())];
    for (code, count) in &by_status {
        rows.push(SummaryRow::new(
            format!("Status {}", code),
            count.to_string(),
        ));
    }
    if !all_tech.is_empty() {
        let mut tech_list: Vec<&str> = all_tech.iter().map(|s| s.as_str()).collect();
        tech_list.sort_unstable();
        rows.push(SummaryRow::new("Technologies", tech_list.join(", ")));
    }

    let summary_line = format!(
        "httpx parsed {} host(s), {} status code(s), {} technology/technologie(s) detected",
        total,
        by_status.len(),
        all_tech.len(),
    );

    let mut output = ProbeOutput::with_summary(summary_line);
    output.summary_rows = rows;
    if !stderr.is_empty() {
        output.warnings.push(crate::probe::ProbeWarning {
            code: "scanner_stderr".into(),
            message: stderr.join("\n"),
        });
    }
    output.raw = Some(json!({
        "tool": "httpx",
        "exit_code": _exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "hosts": total,
        "status_codes": by_status,
        "technologies": all_tech,
    }));
    output
}

fn summarize_json_lines(
    kind: ExternalScannerKind,
    exit_code: Option<i32>,
    stdout: &[String],
    stderr: &[String],
) -> ProbeOutput {
    let records = stdout.iter().filter(|line| !line.trim().is_empty()).count();
    let tool = kind.tool_id();
    let mut output =
        ProbeOutput::with_summary(format!("{tool} completed with {records} result line(s)"));
    output.summary_rows = vec![
        SummaryRow::new("Tool", tool),
        SummaryRow::new(
            "Exit",
            exit_code.map_or_else(|| "unknown".into(), |v| v.to_string()),
        ),
        SummaryRow::new("Result lines", records.to_string()),
    ];
    if !stderr.is_empty() {
        output.warnings.push(crate::probe::ProbeWarning {
            code: format!("{tool}_stderr"),
            message: stderr.join("\n"),
        });
    }
    output.raw = Some(json!({
        "tool": tool,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
    }));
    output
}

fn summarize_nmap(exit_code: Option<i32>, stdout: &[String], stderr: &[String]) -> ProbeOutput {
    let hosts = parse_nmap_hosts(stdout);
    let open_port_count: usize = hosts.iter().map(|host| host.ports.len()).sum();
    let hosts_up = stdout
        .iter()
        .filter(|line| line.contains("Host is up"))
        .count();
    let mut output = ProbeOutput::with_summary(format!(
        "Nmap completed with {} open port(s)",
        open_port_count
    ));
    output.summary_rows = vec![
        SummaryRow::new(
            "Exit",
            exit_code.map_or_else(|| "unknown".into(), |v| v.to_string()),
        ),
        SummaryRow::new("Hosts up", hosts_up.to_string()),
        SummaryRow::new("Hosts with open ports", hosts.len().to_string()),
        SummaryRow::new("Open ports", open_port_count.to_string()),
    ];
    let service_summary = hosts
        .iter()
        .flat_map(|host| {
            host.ports.iter().map(move |port| {
                format!(
                    "{} {} {}/{}",
                    host.host, port.service, port.port, port.proto
                )
            })
        })
        .collect::<Vec<_>>();
    if !service_summary.is_empty() {
        output
            .summary_rows
            .push(SummaryRow::new("Services", service_summary.join("; ")));
    }
    if !stderr.is_empty() {
        output.warnings.push(crate::probe::ProbeWarning {
            code: "scanner_stderr".into(),
            message: stderr.join("\n"),
        });
    }
    output.raw = Some(json!({
        "kind": "nmap",
        "exitCode": exit_code,
        "hosts": hosts,
        "stdout": stdout,
        "stderr": stderr,
    }));
    output
}

fn parse_nmap_hosts(lines: &[String]) -> Vec<NmapHostPorts> {
    let mut hosts: Vec<NmapHostPorts> = Vec::new();
    let mut current_host: Option<String> = None;

    for line in lines {
        if let Some(host) = line.strip_prefix("Nmap scan report for ") {
            current_host = Some(host.trim().to_string());
            continue;
        }

        let Some(port) = parse_nmap_open_port(line) else {
            continue;
        };
        let host = current_host
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        if hosts.last().is_some_and(|item| item.host == host) {
            hosts.last_mut().expect("host exists").ports.push(port);
        } else {
            hosts.push(NmapHostPorts {
                host,
                ports: vec![port],
            });
        }
    }

    hosts
}

fn parse_nmap_open_port(line: &str) -> Option<NmapOpenPort> {
    let mut parts = line.split_whitespace();
    let port_proto = parts.next()?;
    let state = parts.next()?;
    if state != "open" {
        return None;
    }
    let (port, proto) = port_proto.split_once('/')?;
    let port = port.parse::<u16>().ok()?;
    let service = parts.next().unwrap_or_default().to_string();
    Some(NmapOpenPort {
        port,
        proto: proto.to_string(),
        service,
        detail: line.to_string(),
    })
}

fn summarize_nuclei(exit_code: Option<i32>, stdout: &[String], stderr: &[String]) -> ProbeOutput {
    let mut total = 0usize;
    let mut critical_high = 0usize;
    for line in stdout {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            total += 1;
            let severity = value
                .pointer("/info/severity")
                .or_else(|| value.get("severity"))
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            if matches!(severity, "critical" | "high") {
                critical_high += 1;
            }
        }
    }
    let mut output = ProbeOutput::with_summary(format!("Nuclei completed with {total} finding(s)"));
    output.summary_rows = vec![
        SummaryRow::new(
            "Exit",
            exit_code.map_or_else(|| "unknown".into(), |v| v.to_string()),
        ),
        SummaryRow::new("Findings", total.to_string()),
        SummaryRow::new("High/Critical", critical_high.to_string()),
    ];
    if !stderr.is_empty() {
        output.warnings.push(crate::probe::ProbeWarning {
            code: "scanner_stderr".into(),
            message: stderr.join("\n"),
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_option_injection_and_whitespace_targets() {
        assert!(ExternalScannerProfile::new(ExternalScannerKind::Nmap, "-Pn").is_err());
        assert!(ExternalScannerProfile::new(ExternalScannerKind::Nuclei, "a b").is_err());
    }

    #[test]
    fn nmap_profile_is_bounded_and_argv_only() {
        let profile = ExternalScannerProfile::new(ExternalScannerKind::Nmap, "127.0.0.1").unwrap();
        let invocation = profile.invocation(Path::new("nmap"));

        assert_eq!(invocation.program, "nmap");
        assert!(invocation
            .args
            .windows(2)
            .any(|args| args == ["--top-ports", "100"]));
        assert_eq!(invocation.args.last().unwrap(), "127.0.0.1");
    }

    #[test]
    fn nmap_version_all_ports_supports_cidr_targets() {
        let profile = ExternalScannerProfile::new(ExternalScannerKind::Nmap, "103.29.26.0/24")
            .unwrap()
            .with_mode(ExternalScannerMode::NmapVersion)
            .with_ports(ExternalScannerPorts::All)
            .unwrap();
        let invocation = profile.invocation(Path::new("nmap"));

        assert_eq!(invocation.program, "nmap");
        assert!(invocation.args.contains(&"-sV".into()));
        assert!(invocation.args.contains(&"-p-".into()));
        assert!(invocation.args.contains(&"-T4".into()));
        assert!(invocation.args.contains(&"--open".into()));
        assert_eq!(invocation.args.last().unwrap(), "103.29.26.0/24");
    }

    #[test]
    fn nuclei_profile_is_bounded_and_argv_only() {
        let profile =
            ExternalScannerProfile::new(ExternalScannerKind::Nuclei, "https://127.0.0.1").unwrap();
        let invocation = profile.invocation(Path::new("nuclei"));

        assert_eq!(invocation.program, "nuclei");
        assert!(invocation
            .args
            .windows(2)
            .any(|args| args == ["-u", "https://127.0.0.1"]));
        assert!(invocation.args.contains(&"-jsonl".into()));
        assert!(invocation.args.contains(&"-no-interactsh".into()));
        assert!(invocation
            .args
            .windows(2)
            .any(|args| args == ["-rate-limit", "50"]));
        assert!(invocation
            .args
            .windows(2)
            .any(|args| args == ["-concurrency", "10"]));
        assert!(!invocation.args.iter().any(|arg| arg.contains(';')));
    }

    #[test]
    fn catalog_scanners_have_single_target_bounded_invocations() {
        let cases = [
            (
                ExternalScannerKind::Httpx,
                "https://example.com",
                "-rate-limit",
            ),
            (ExternalScannerKind::Naabu, "example.com", "-rate"),
            (ExternalScannerKind::Subfinder, "example.com", "-max-time"),
            (ExternalScannerKind::Dnsx, "example.com", "-rate-limit"),
            (
                ExternalScannerKind::Trippy,
                "example.com",
                "--report-cycles",
            ),
            (
                ExternalScannerKind::Nexttrace,
                "example.com",
                "--max-attempts",
            ),
        ];
        for (kind, target, bounded_flag) in cases {
            let invocation = ExternalScannerProfile::new(kind, target)
                .unwrap()
                .invocation(Path::new(kind.tool_id()));
            assert!(
                invocation.args.iter().any(|arg| arg == bounded_flag),
                "{}",
                kind.tool_id()
            );
            assert!(
                invocation.args.iter().any(|arg| arg == target),
                "{}",
                kind.tool_id()
            );
            assert!(!invocation.args.iter().any(|arg| arg.contains(';')));
        }
    }

    #[test]
    fn nmap_entity_profile_uses_host_for_url_targets() {
        let entity = crate::entity::parse_entity_guess("https://example.com:8443/login").unwrap();
        let profile =
            ExternalScannerProfile::for_entity(ExternalScannerKind::Nmap, &entity).unwrap();

        assert_eq!(profile.target, "example.com");
    }

    #[test]
    fn nuclei_entity_profile_preserves_url_scheme_and_path() {
        let entity = crate::entity::parse_entity_guess("http://example.com:8080/login").unwrap();
        let profile =
            ExternalScannerProfile::for_entity(ExternalScannerKind::Nuclei, &entity).unwrap();

        assert_eq!(profile.target, "http://example.com:8080/login");
    }

    #[test]
    fn nuclei_entity_profile_adds_https_for_domain_targets() {
        let entity = crate::entity::parse_entity_guess("example.com").unwrap();
        let profile =
            ExternalScannerProfile::for_entity(ExternalScannerKind::Nuclei, &entity).unwrap();

        assert_eq!(profile.target, "https://example.com");
    }

    #[test]
    fn summarizes_nmap_open_ports() {
        let stdout = vec![
            "Nmap scan report for 103.29.26.1".into(),
            "Host is up (0.0010s latency).".into(),
            "22/tcp open ssh OpenSSH".into(),
            "443/tcp open https".into(),
        ];
        let output = summarize_scanner_output(ExternalScannerKind::Nmap, Some(0), &stdout, &[]);
        assert!(output.summary.unwrap().contains("2 open port"));
        let hosts = output
            .raw
            .as_ref()
            .and_then(|raw| raw.get("hosts"))
            .and_then(serde_json::Value::as_array)
            .unwrap();
        assert_eq!(hosts[0]["host"], "103.29.26.1");
        assert_eq!(hosts[0]["ports"][0]["port"], 22);
    }

    #[test]
    fn summarizes_nuclei_jsonl_findings() {
        let stdout = vec![
            r#"{"info":{"severity":"high"},"template-id":"one"}"#.into(),
            r#"{"info":{"severity":"low"},"template-id":"two"}"#.into(),
        ];
        let output = summarize_scanner_output(ExternalScannerKind::Nuclei, Some(0), &stdout, &[]);
        assert!(output.summary.unwrap().contains("2 finding"));
        assert_eq!(output.summary_rows[2].value, "1");
    }

    #[test]
    fn summarizes_httpx_multiline_jsonl_output() {
        let stdout = vec![
            r#"{"url":"https://a.example.com","status_code":200,"title":"Home","tech":["nginx","PHP"],"webserver":"nginx"}"#.into(),
            r#"{"url":"https://b.example.com","status_code":403,"title":"","tech":["Apache"],"webserver":"Apache/2.4"}"#.into(),
            r#"{"url":"https://c.example.com","status_code":200,"title":"API","tech":["nginx"],"webserver":"nginx"}"#.into(),
        ];
        let output = summarize_scanner_output(ExternalScannerKind::Httpx, Some(0), &stdout, &[]);
        // summary must reflect parsed count, not raw line count
        assert!(output.summary.unwrap().contains("3 host"));
        // First row = total hosts
        assert_eq!(output.summary_rows[0].label, "Hosts");
        assert_eq!(output.summary_rows[0].value, "3");
        // Status-code distribution
        assert!(output.summary_rows.iter().any(|r| r.label == "Status 200" && r.value == "2"));
        assert!(output.summary_rows.iter().any(|r| r.label == "Status 403" && r.value == "1"));
        // Technologies merged & sorted (ASCII order: uppercase before lowercase)
        assert!(output.summary_rows.iter().any(|r| r.label == "Technologies" && r.value == "Apache, PHP, nginx"));
    }

    #[test]
    fn summarizes_httpx_skips_malformed_json_lines() {
        let stdout = vec![
            r#"{"url":"https://ok.example.com","status_code":200,"title":"OK","tech":["nginx"]}"#.into(),
            "not json at all".into(),
            "".into(),
            r#"{"incomplete": true"#.into(),
            r#"{"url":"https://ok2.example.com","status_code":301,"title":"","tech":[],"webserver":"cloudflare"}"#.into(),
        ];
        let output = summarize_scanner_output(ExternalScannerKind::Httpx, Some(0), &stdout, &[]);
        assert!(output.summary.unwrap().contains("2 host"));
        assert_eq!(output.summary_rows[0].label, "Hosts");
        assert_eq!(output.summary_rows[0].value, "2");
        // 200 from first valid line
        assert!(output.summary_rows.iter().any(|r| r.label == "Status 200" && r.value == "1"));
        // 301 from last valid line
        assert!(output.summary_rows.iter().any(|r| r.label == "Status 301" && r.value == "1"));
    }

    #[test]
    fn summarizes_httpx_empty_output() {
        let stdout: Vec<String> = vec![];
        let output = summarize_scanner_output(ExternalScannerKind::Httpx, Some(0), &stdout, &[]);
        assert!(output.summary.unwrap().contains("0 host"));
        assert_eq!(output.summary_rows[0].label, "Hosts");
        assert_eq!(output.summary_rows[0].value, "0");
    }

    #[test]
    fn httpx_summary_includes_status_code_breakdown() {
        let input = vec![
            r#"{"url":"https://a.com","status_code":200}"#.into(),
            r#"{"url":"https://b.com","status_code":403}"#.into(),
            r#"{"url":"https://c.com","status_code":403}"#.into(),
            r#"{"url":"https://d.com","status_code":500}"#.into(),
            r#"{"url":"https://e.com","status_code":200}"#.into(),
        ];
        let output = summarize_scanner_output(ExternalScannerKind::Httpx, Some(0), &input, &[]);
        assert_eq!(output.summary_rows[0].label, "Hosts");
        assert_eq!(output.summary_rows[0].value, "5");
        assert!(output.summary_rows.iter().any(|r| r.label == "Status 200" && r.value == "2"));
        assert!(output.summary_rows.iter().any(|r| r.label == "Status 403" && r.value == "2"));
        assert!(output.summary_rows.iter().any(|r| r.label == "Status 500" && r.value == "1"));
    }

    #[test]
    fn httpx_output_raw_present_and_contains_expected_fields() {
        let input = vec![
            r#"{"url":"https://x.com","status_code":200,"title":"X","tech":["nginx"]}"#.into(),
            r#"{"url":"https://y.com","status_code":503,"title":"","tech":["apache"]}"#.into(),
            "".into(),
            "not json".into(),
        ];
        let output = summarize_scanner_output(ExternalScannerKind::Httpx, Some(0), &input, &[]);

        let raw = output.raw.as_ref().expect("output.raw must be Some");
        assert_eq!(raw["tool"], "httpx");
        assert_eq!(raw["exit_code"], 0);
        assert!(raw["stdout"].is_array());
        assert!(raw["stderr"].is_array());
        assert_eq!(raw["hosts"], 2);
        assert_eq!(raw["technologies"], serde_json::json!(["apache", "nginx"]));
    }
}
