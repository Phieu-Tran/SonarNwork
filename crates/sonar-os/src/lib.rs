use std::net::IpAddr;
use std::process::Command;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, OsError>;

#[derive(Debug, Error)]
pub enum OsError {
    #[error("not implemented for this platform yet: {0}")]
    NotImplemented(&'static str),

    #[error("os command failed: {0}")]
    CommandFailed(String),
}

pub trait OsNet {
    fn interfaces(&self) -> Result<Vec<Iface>>;
    fn listening_sockets(&self) -> Result<Vec<Socket>>;
    fn firewall_state(&self) -> Result<FirewallState>;
    fn configured_resolvers(&self) -> Result<Vec<Resolver>>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Iface {
    pub name: String,
    pub display_name: Option<String>,
    pub ips: Vec<IpAddr>,
    pub mac: Option<String>,
    pub gateway: Option<IpAddr>,
    pub is_up: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Socket {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub proto: L4Proto,
    pub owning_pid: Option<u32>,
    pub process_name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resolver {
    pub address: IpAddr,
    pub source: ResolverSource,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverSource {
    ResolvConf,
    SystemdResolved,
    WindowsAdapter,
    Manual,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallState {
    Enabled,
    Disabled,
    Mixed,
    Unknown,
}

#[derive(Clone, Copy, Debug)]
pub struct SystemOsNet;

impl SystemOsNet {
    pub fn current() -> Self {
        Self
    }
}

impl OsNet for SystemOsNet {
    fn interfaces(&self) -> Result<Vec<Iface>> {
        system_interfaces()
    }

    fn listening_sockets(&self) -> Result<Vec<Socket>> {
        system_listening_sockets()
    }

    fn firewall_state(&self) -> Result<FirewallState> {
        system_firewall_state()
    }

    fn configured_resolvers(&self) -> Result<Vec<Resolver>> {
        system_configured_resolvers()
    }
}

#[cfg(target_os = "windows")]
fn system_interfaces() -> Result<Vec<Iface>> {
    let output = command_output("ipconfig", ["/all"])?;
    Ok(parse_windows_ipconfig_interfaces(&output))
}

#[cfg(not(target_os = "windows"))]
fn system_interfaces() -> Result<Vec<Iface>> {
    let output = command_output(
        "sh",
        ["-c", "ip -o addr show 2>/dev/null || ifconfig 2>/dev/null"],
    )?;
    Ok(parse_unix_interfaces(&output))
}

#[cfg(target_os = "windows")]
fn system_configured_resolvers() -> Result<Vec<Resolver>> {
    let output = command_output("ipconfig", ["/all"])?;
    Ok(parse_windows_ipconfig_resolvers(&output))
}

#[cfg(not(target_os = "windows"))]
fn system_configured_resolvers() -> Result<Vec<Resolver>> {
    let contents = std::fs::read_to_string("/etc/resolv.conf")
        .map_err(|err| OsError::CommandFailed(format!("read /etc/resolv.conf: {err}")))?;
    Ok(contents
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver "))
        .filter_map(|value| value.split_whitespace().next())
        .filter_map(|value| value.parse::<IpAddr>().ok())
        .map(|address| Resolver {
            address,
            source: ResolverSource::ResolvConf,
        })
        .collect())
}

#[cfg(target_os = "windows")]
fn system_listening_sockets() -> Result<Vec<Socket>> {
    let output = command_output("netstat", ["-ano"])?;
    Ok(parse_netstat_listeners(&output))
}

#[cfg(not(target_os = "windows"))]
fn system_listening_sockets() -> Result<Vec<Socket>> {
    let output = command_output(
        "sh",
        [
            "-c",
            "ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null",
        ],
    )?;
    Ok(parse_unix_socket_listeners(&output))
}

#[cfg(target_os = "windows")]
fn system_firewall_state() -> Result<FirewallState> {
    let output = command_output("netsh", ["advfirewall", "show", "allprofiles", "state"])?;
    let enabled = output
        .lines()
        .filter(|line| line.to_ascii_lowercase().contains("state"))
        .filter(|line| line.to_ascii_lowercase().contains("on"))
        .count();
    let disabled = output
        .lines()
        .filter(|line| line.to_ascii_lowercase().contains("state"))
        .filter(|line| line.to_ascii_lowercase().contains("off"))
        .count();

    Ok(match (enabled > 0, disabled > 0) {
        (true, true) => FirewallState::Mixed,
        (true, false) => FirewallState::Enabled,
        (false, true) => FirewallState::Disabled,
        (false, false) => FirewallState::Unknown,
    })
}

#[cfg(not(target_os = "windows"))]
fn system_firewall_state() -> Result<FirewallState> {
    Ok(FirewallState::Unknown)
}

fn command_output<const N: usize>(program: &str, args: [&str; N]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| OsError::CommandFailed(format!("{program}: {err}")))?;

    if !output.status.success() {
        return Err(OsError::CommandFailed(format!(
            "{program} exited with {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_windows_ipconfig_interfaces(output: &str) -> Vec<Iface> {
    let mut interfaces = Vec::new();
    let mut current: Option<Iface> = None;

    for raw_line in output.lines() {
        let line = raw_line.trim_end();
        if line.is_empty() {
            continue;
        }

        if line.ends_with(':') && !raw_line.starts_with(' ') {
            if let Some(iface) = current.take() {
                interfaces.push(iface);
            }
            let name = line.trim_end_matches(':').to_string();
            current = Some(Iface {
                name: name.clone(),
                display_name: Some(name),
                ips: Vec::new(),
                mac: None,
                gateway: None,
                is_up: true,
            });
            continue;
        }

        let Some(iface) = current.as_mut() else {
            continue;
        };
        if let Some(value) = after_colon(line) {
            let label = line.split(':').next().unwrap_or("").to_ascii_lowercase();
            if label.contains("physical address") {
                iface.mac = non_empty(value.to_string());
            } else if label.contains("ipv4 address") || label.contains("ipv6 address") {
                if let Some(ip) = parse_ip_token(value) {
                    iface.ips.push(ip);
                }
            } else if label.contains("default gateway") {
                if let Some(ip) = parse_ip_token(value) {
                    iface.gateway = Some(ip);
                }
            } else if label.contains("media state")
                && value.to_ascii_lowercase().contains("disconnected")
            {
                iface.is_up = false;
            }
        }
    }

    if let Some(iface) = current {
        interfaces.push(iface);
    }

    interfaces
        .into_iter()
        .filter(|iface| !iface.name.to_ascii_lowercase().contains("tunnel adapter"))
        .collect()
}

fn parse_windows_ipconfig_resolvers(output: &str) -> Vec<Resolver> {
    let mut resolvers = Vec::new();
    let mut reading_dns = false;

    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            reading_dns = false;
            continue;
        }

        if line.to_ascii_lowercase().starts_with("dns servers") {
            reading_dns = true;
            if let Some(value) = after_colon(line) {
                push_resolver(&mut resolvers, value, ResolverSource::WindowsAdapter);
            }
            continue;
        }

        if reading_dns {
            if line.contains(':') && !looks_like_ip(line) {
                reading_dns = false;
            } else {
                push_resolver(&mut resolvers, line, ResolverSource::WindowsAdapter);
            }
        }
    }

    dedupe_resolvers(resolvers)
}

#[cfg(not(target_os = "windows"))]
fn parse_unix_interfaces(output: &str) -> Vec<Iface> {
    let mut interfaces: Vec<Iface> = Vec::new();

    for line in output.lines() {
        let clean = line.trim();
        if clean.is_empty() {
            continue;
        }

        if clean.contains(" inet ") || clean.contains(" inet6 ") {
            let parts: Vec<&str> = clean.split_whitespace().collect();
            let name = parts
                .get(1)
                .map(|value| value.trim_end_matches(':').to_string())
                .unwrap_or_else(|| "unknown".into());
            let ip = parts
                .iter()
                .position(|part| *part == "inet" || *part == "inet6")
                .and_then(|index| parts.get(index + 1))
                .and_then(|value| value.split('/').next())
                .and_then(|value| value.parse::<IpAddr>().ok());
            let iface = interfaces.iter_mut().find(|iface| iface.name == name);
            let iface = match iface {
                Some(iface) => iface,
                None => {
                    interfaces.push(Iface {
                        name: name.clone(),
                        display_name: Some(name),
                        ips: Vec::new(),
                        mac: None,
                        gateway: None,
                        is_up: !clean.contains(" DOWN "),
                    });
                    interfaces.last_mut().expect("just pushed")
                }
            };
            if let Some(ip) = ip {
                iface.ips.push(ip);
            }
        }
    }

    interfaces
}

fn parse_netstat_listeners(output: &str) -> Vec<Socket> {
    output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let proto = parts.first()?.to_ascii_lowercase();
            if proto != "tcp" && proto != "udp" {
                return None;
            }
            if proto == "tcp"
                && !parts
                    .iter()
                    .any(|part| part.eq_ignore_ascii_case("LISTENING"))
            {
                return None;
            }

            let local = parts.get(1)?;
            let (local_addr, local_port) = parse_addr_port(local)?;
            let owning_pid = parts.last().and_then(|value| value.parse::<u32>().ok());

            Some(Socket {
                local_addr,
                local_port,
                proto: if proto == "tcp" {
                    L4Proto::Tcp
                } else {
                    L4Proto::Udp
                },
                owning_pid,
                process_name: None,
            })
        })
        .collect()
}

#[cfg(not(target_os = "windows"))]
fn parse_unix_socket_listeners(output: &str) -> Vec<Socket> {
    output
        .lines()
        .filter_map(|line| {
            let clean = line.trim();
            let lower = clean.to_ascii_lowercase();
            if !(lower.starts_with("tcp") || lower.starts_with("udp")) {
                return None;
            }
            let proto = if lower.starts_with("tcp") {
                L4Proto::Tcp
            } else {
                L4Proto::Udp
            };
            if proto == L4Proto::Tcp && !lower.contains("listen") {
                return None;
            }
            let local = clean
                .split_whitespace()
                .find(|part| part.contains(':') && !part.contains("users:"))?;
            let (local_addr, local_port) = parse_addr_port(local)?;
            Some(Socket {
                local_addr,
                local_port,
                proto,
                owning_pid: parse_pid(clean),
                process_name: None,
            })
        })
        .collect()
}

fn after_colon(line: &str) -> Option<&str> {
    line.split_once(':').map(|(_, value)| value.trim())
}

fn parse_ip_token(value: &str) -> Option<IpAddr> {
    value
        .split(|ch: char| ch.is_whitespace() || ch == '(' || ch == ')' || ch == ',')
        .find_map(|token| token.trim_matches(['[', ']']).parse::<IpAddr>().ok())
}

fn looks_like_ip(value: &str) -> bool {
    parse_ip_token(value).is_some()
}

fn push_resolver(resolvers: &mut Vec<Resolver>, value: &str, source: ResolverSource) {
    if let Some(address) = parse_ip_token(value) {
        resolvers.push(Resolver { address, source });
    }
}

fn dedupe_resolvers(resolvers: Vec<Resolver>) -> Vec<Resolver> {
    let mut deduped = Vec::new();
    for resolver in resolvers {
        if !deduped
            .iter()
            .any(|item: &Resolver| item.address == resolver.address)
        {
            deduped.push(resolver);
        }
    }
    deduped
}

fn parse_addr_port(value: &str) -> Option<(IpAddr, u16)> {
    let clean = value.trim().trim_matches(['[', ']']);
    let (addr, port) = clean.rsplit_once(':')?;
    let addr = addr.trim_matches(['[', ']']);
    let addr = match addr {
        "*" | "0.0.0.0" => "0.0.0.0",
        "::" | "[::]" => "::",
        value if value.is_empty() => "0.0.0.0",
        value => value,
    };
    Some((addr.parse().ok()?, port.parse().ok()?))
}

#[cfg(not(target_os = "windows"))]
fn parse_pid(value: &str) -> Option<u32> {
    value
        .split(|ch: char| !ch.is_ascii_digit())
        .filter_map(|part| part.parse::<u32>().ok())
        .next()
}

fn non_empty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_netstat_listener() {
        let sockets =
            parse_netstat_listeners("  TCP    0.0.0.0:80    0.0.0.0:0    LISTENING    1234\n");

        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local_port, 80);
        assert_eq!(sockets[0].owning_pid, Some(1234));
    }

    #[test]
    fn parses_windows_dns_resolvers() {
        let resolvers = parse_windows_ipconfig_resolvers(
            "DNS Servers . . . . . . . . . . . : 1.1.1.1\n                                    8.8.8.8\n",
        );

        assert_eq!(resolvers.len(), 2);
    }
}
