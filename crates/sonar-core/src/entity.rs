use std::fmt;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Result, SonarError};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntityId(String);

impl EntityId {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_entity(entity: &Entity) -> Self {
        Self(format!(
            "{}:{}",
            entity.kind().as_str(),
            entity.stable_key()
        ))
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    LocalMachine,
    CurrentInternetPath,
    Ip,
    Domain,
    Host,
    Asn,
    Port,
    Certificate,
    Url,
    Dns,
}

impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalMachine => "local_machine",
            Self::CurrentInternetPath => "current_internet_path",
            Self::Ip => "ip",
            Self::Domain => "domain",
            Self::Host => "host",
            Self::Asn => "asn",
            Self::Port => "port",
            Self::Certificate => "certificate",
            Self::Url => "url",
            Self::Dns => "dns",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Entity {
    LocalMachine,
    CurrentInternetPath,
    Ip(IpAddr),
    Domain(DomainName),
    Host(HostEntity),
    Asn(u32),
    Port(PortEntity),
    Certificate(CertInfo),
    Url(Url),
    Dns(DnsRecord),
}

impl Entity {
    pub fn id(&self) -> EntityId {
        EntityId::from_entity(self)
    }

    pub fn kind(&self) -> EntityKind {
        match self {
            Self::LocalMachine => EntityKind::LocalMachine,
            Self::CurrentInternetPath => EntityKind::CurrentInternetPath,
            Self::Ip(_) => EntityKind::Ip,
            Self::Domain(_) => EntityKind::Domain,
            Self::Host(_) => EntityKind::Host,
            Self::Asn(_) => EntityKind::Asn,
            Self::Port(_) => EntityKind::Port,
            Self::Certificate(_) => EntityKind::Certificate,
            Self::Url(_) => EntityKind::Url,
            Self::Dns(_) => EntityKind::Dns,
        }
    }

    pub fn stable_key(&self) -> String {
        match self {
            Self::LocalMachine => "this-machine".into(),
            Self::CurrentInternetPath => "current-internet-path".into(),
            Self::Ip(ip) => ip.to_string(),
            Self::Domain(domain) => domain.normalized.clone(),
            Self::Host(host) => match host.ip {
                Some(ip) => format!("{}@{}", normalize_domain(&host.name), ip),
                None => normalize_domain(&host.name),
            },
            Self::Asn(asn) => asn.to_string(),
            Self::Port(port) => format!("{}:{}/{}", port.ip, port.port, port.proto.as_str()),
            Self::Certificate(cert) => cert
                .sha256_fingerprint
                .clone()
                .unwrap_or_else(|| normalize_for_key(&cert.subject)),
            Self::Url(url) => normalize_url(url),
            Self::Dns(record) => format!(
                "{}:{}:{}",
                normalize_domain(&record.name),
                record.record_type.to_ascii_uppercase(),
                normalize_for_key(&record.value)
            ),
        }
    }

    pub fn is_local_workflow_target(&self) -> bool {
        matches!(self, Self::LocalMachine | Self::CurrentInternetPath)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainName {
    pub normalized: String,
}

impl DomainName {
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let normalized = normalize_domain(value.as_ref());
        if !looks_like_domain(&normalized) {
            return Err(SonarError::InvalidTarget(value.as_ref().to_string()));
        }

        Ok(Self { normalized })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEntity {
    pub name: String,
    pub ip: Option<IpAddr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Proto {
    Tcp,
    Udp,
}

impl L4Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortEntity {
    pub ip: IpAddr,
    pub port: u16,
    pub proto: L4Proto,
    pub state: PortState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: Option<String>,
    pub sha256_fingerprint: Option<String>,
    pub san_dns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
}

pub fn parse_entity_guess(input: impl AsRef<str>) -> Result<Entity> {
    let raw = input.as_ref().trim();
    if raw.is_empty() {
        return Err(SonarError::InvalidTarget(input.as_ref().to_string()));
    }

    if let Ok(socket) = raw.parse::<SocketAddr>() {
        return Ok(Entity::Port(PortEntity {
            ip: socket.ip(),
            port: socket.port(),
            proto: L4Proto::Tcp,
            state: PortState::Unknown,
        }));
    }

    if let Some(url) = parse_domain_port_as_url(raw) {
        return Ok(Entity::Url(url));
    }

    if let Ok(url) = Url::parse(raw) {
        return Ok(Entity::Url(url));
    }

    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(Entity::Ip(ip));
    }

    if let Some(asn) = raw
        .strip_prefix("AS")
        .or_else(|| raw.strip_prefix("as"))
        .and_then(|value| value.parse::<u32>().ok())
    {
        return Ok(Entity::Asn(asn));
    }

    DomainName::new(raw).map(Entity::Domain)
}

fn parse_domain_port_as_url(raw: &str) -> Option<Url> {
    if raw.contains("://") || raw.contains('/') || raw.contains('?') || raw.contains('#') {
        return None;
    }

    let (host, port) = raw.rsplit_once(':')?;
    if host.is_empty() || port.parse::<u16>().ok()? == 0 {
        return None;
    }
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }

    let domain = DomainName::new(host).ok()?;
    Url::parse(&format!("https://{}:{port}", domain.normalized)).ok()
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_for_key(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(char::is_whitespace, " ")
}

fn normalize_url(url: &Url) -> String {
    let mut normalized = url.clone();
    normalized.set_fragment(None);
    normalized
        .to_string()
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn looks_like_domain(value: &str) -> bool {
    value.contains('.')
        && !value.contains(char::is_whitespace)
        && value.split('.').all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_domain_entity_id() {
        let entity = parse_entity_guess("Example.COM.").unwrap();

        assert_eq!(entity.id().as_str(), "domain:example.com");
    }

    #[test]
    fn parses_socket_as_tcp_port() {
        let entity = parse_entity_guess("1.1.1.1:443").unwrap();

        assert_eq!(entity.id().as_str(), "port:1.1.1.1:443/tcp");
    }

    #[test]
    fn parses_domain_port_as_url_with_default_scheme() {
        let entity = parse_entity_guess("example.com:443").unwrap();

        assert_eq!(entity.id().as_str(), "url:https://example.com");
        match entity {
            Entity::Url(url) => {
                assert_eq!(url.host_str(), Some("example.com"));
                assert_eq!(url.port_or_known_default(), Some(443));
            }
            other => panic!("expected url entity, got {other:?}"),
        }
    }

    #[test]
    fn local_target_entities_have_stable_ids() {
        assert_eq!(
            Entity::LocalMachine.id().as_str(),
            "local_machine:this-machine"
        );
        assert_eq!(
            Entity::CurrentInternetPath.id().as_str(),
            "current_internet_path:current-internet-path"
        );
    }
}
