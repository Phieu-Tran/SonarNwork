use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use url::Host;

use crate::entity::Entity;
use crate::error::{Result, SonarError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    LocalInspection,
    PassiveLookup,
    ActiveProbe,
    IntrusiveScan,
    ExternalTool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ScopeDecision {
    Allowed,
    Denied { reason: String },
    NeedsConfirmation { reason: String },
}

impl ScopeDecision {
    pub fn into_result(self) -> Result<()> {
        match self {
            Self::Allowed => Ok(()),
            Self::Denied { reason } | Self::NeedsConfirmation { reason } => {
                Err(SonarError::ScopeDenied(reason))
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopePolicy {
    pub allowed_ips: Vec<IpAddr>,
    pub allowed_cidrs: Vec<IpNet>,
    pub allowed_domains: Vec<String>,
    pub allow_passive_lookup_by_default: bool,
    pub allow_active_probe_by_default: bool,
}

impl Default for ScopePolicy {
    fn default() -> Self {
        Self {
            allowed_ips: vec![],
            allowed_cidrs: vec![],
            allowed_domains: vec![],
            allow_passive_lookup_by_default: true,
            allow_active_probe_by_default: false,
        }
    }
}

impl ScopePolicy {
    pub fn allow_ip(mut self, ip: IpAddr) -> Self {
        self.allowed_ips.push(ip);
        self
    }

    pub fn allow_cidr(mut self, cidr: IpNet) -> Self {
        self.allowed_cidrs.push(cidr);
        self
    }

    pub fn allow_domain(mut self, domain: impl AsRef<str>) -> Self {
        self.allowed_domains.push(normalize_domain(domain.as_ref()));
        self
    }
}

#[derive(Clone, Debug, Default)]
pub struct ScopeGuard {
    policy: ScopePolicy,
}

impl ScopeGuard {
    pub fn new(policy: ScopePolicy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &ScopePolicy {
        &self.policy
    }

    pub fn check(&self, entity: &Entity, action: ActionClass) -> ScopeDecision {
        match action {
            ActionClass::LocalInspection => ScopeDecision::Allowed,
            ActionClass::PassiveLookup | ActionClass::ActiveProbe
                if entity.is_local_workflow_target() =>
            {
                ScopeDecision::Allowed
            }
            ActionClass::PassiveLookup if self.policy.allow_passive_lookup_by_default => {
                ScopeDecision::Allowed
            }
            ActionClass::PassiveLookup => self.check_allowed_target(entity, "passive lookup"),
            ActionClass::ActiveProbe if self.policy.allow_active_probe_by_default => {
                ScopeDecision::Allowed
            }
            ActionClass::ActiveProbe => self.check_allowed_target(entity, "active probe"),
            ActionClass::IntrusiveScan => self.check_allowed_target(entity, "intrusive scan"),
            ActionClass::ExternalTool => self.check_allowed_target(entity, "external tool"),
        }
    }

    pub fn ensure_allowed(&self, entity: &Entity, action: ActionClass) -> Result<()> {
        self.check(entity, action).into_result()
    }

    fn check_allowed_target(&self, entity: &Entity, label: &str) -> ScopeDecision {
        if self.entity_is_allowed(entity) {
            ScopeDecision::Allowed
        } else {
            ScopeDecision::Denied {
                reason: format!(
                    "{} requires an explicitly allowed target; `{}` is not in scope",
                    label,
                    entity.id()
                ),
            }
        }
    }

    fn entity_is_allowed(&self, entity: &Entity) -> bool {
        match entity {
            Entity::LocalMachine | Entity::CurrentInternetPath => false,
            Entity::Ip(ip) => self.ip_is_allowed(ip),
            Entity::Domain(domain) => self.domain_is_allowed(&domain.normalized),
            Entity::Host(host) => {
                host.ip.as_ref().is_some_and(|ip| self.ip_is_allowed(ip))
                    || self.domain_is_allowed(&host.name)
            }
            Entity::Port(port) => self.ip_is_allowed(&port.ip),
            Entity::Url(url) => match url.host() {
                Some(Host::Ipv4(ip)) => self.ip_is_allowed(&IpAddr::V4(ip)),
                Some(Host::Ipv6(ip)) => self.ip_is_allowed(&IpAddr::V6(ip)),
                Some(Host::Domain(domain)) => self.domain_is_allowed(domain),
                None => false,
            },
            Entity::Asn(_) | Entity::Certificate(_) | Entity::Dns(_) => false,
        }
    }

    fn ip_is_allowed(&self, ip: &IpAddr) -> bool {
        self.policy.allowed_ips.contains(ip)
            || self
                .policy
                .allowed_cidrs
                .iter()
                .any(|cidr| cidr.contains(ip))
    }

    fn domain_is_allowed(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.policy
            .allowed_domains
            .iter()
            .any(|allowed| domain == *allowed || domain.ends_with(&format!(".{}", allowed)))
    }
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use crate::entity::parse_entity_guess;

    use super::*;

    #[test]
    fn active_probe_requires_scope() {
        let guard = ScopeGuard::default();
        let entity = parse_entity_guess("example.com").unwrap();

        assert!(matches!(
            guard.check(&entity, ActionClass::ActiveProbe),
            ScopeDecision::Denied { .. }
        ));
    }

    #[test]
    fn allows_subdomains_of_allowed_domain() {
        let guard = ScopeGuard::new(ScopePolicy::default().allow_domain("example.com"));
        let entity = parse_entity_guess("www.example.com").unwrap();

        assert_eq!(
            guard.check(&entity, ActionClass::ActiveProbe),
            ScopeDecision::Allowed
        );
    }
}
