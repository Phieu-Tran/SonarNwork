use std::path::PathBuf;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ToolError>;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("managed tool not found: {0}")]
    NotFound(String),

    #[error("managed tool operation is not implemented yet: {0}")]
    NotImplemented(&'static str),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedToolDescriptor {
    pub id: String,
    pub display_name: String,
    pub source: ToolSource,
    pub install_strategy: InstallStrategy,
    pub risk: ToolRisk,
    pub category: ToolCategory,
    pub capabilities: Vec<ToolCapability>,
    pub default_enabled: bool,
    pub notes: String,
    pub update: ToolUpdateInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSource {
    ProjectDiscovery,
    Trippy,
    NextTrace,
    Globalping,
    SonarNwork,
    NmapOrg,
    LocalSystem,
    Custom(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallStrategy {
    AutoDownload,
    DetectOnly,
    ApiOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolRisk {
    Passive,
    SafeRemoteVantage,
    ActiveScanner,
    IntrusiveScanner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    PathDiagnostics,
    Dns,
    Web,
    PortDiscovery,
    VulnScanning,
    RemoteVantage,
    LocalInspection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCapability {
    Ping,
    Trace,
    Mtr,
    DnsLookup,
    HttpProbe,
    TlsProbe,
    PortScan,
    SubdomainDiscovery,
    TemplateScan,
    RemoteMeasurement,
    LocalListenerInventory,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolUpdateInfo {
    pub source_label: String,
    pub source_url: String,
    pub latest_url: String,
    pub update_supported: bool,
    pub update_note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolUpdatePlan {
    pub tool_id: String,
    pub display_name: String,
    pub source_label: String,
    pub source_url: String,
    pub latest_url: String,
    pub update_supported: bool,
    pub update_note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolState {
    pub descriptor: ManagedToolDescriptor,
    pub installed_path: Option<PathBuf>,
    pub installed_version: Option<String>,
    pub latest_version: Option<String>,
    pub healthy: bool,
}

#[async_trait]
pub trait ManagedTool: Send + Sync {
    fn descriptor(&self) -> ManagedToolDescriptor;
    async fn detect(&self) -> Result<ToolState>;
    async fn install(&self) -> Result<ToolState>;
    async fn update(&self) -> Result<ToolState>;
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ToolCatalog {
    pub tools: Vec<ManagedToolDescriptor>,
}

impl ToolCatalog {
    pub fn phase_zero_defaults() -> Self {
        Self {
            tools: vec![
                descriptor(
                    "trippy",
                    "Trippy",
                    ToolSource::Trippy,
                    InstallStrategy::AutoDownload,
                    ToolRisk::ActiveScanner,
                    ToolCategory::PathDiagnostics,
                    &[ToolCapability::Trace, ToolCapability::Mtr],
                    true,
                    "Advanced trace/MTR view for packet loss, latency, and hop behavior.",
                    github_update(
                        "fujiapple852/trippy",
                        true,
                        "Auto-download can use the latest GitHub release when the managed tool runtime is enabled.",
                    ),
                ),
                descriptor(
                    "nexttrace",
                    "NextTrace",
                    ToolSource::NextTrace,
                    InstallStrategy::AutoDownload,
                    ToolRisk::ActiveScanner,
                    ToolCategory::PathDiagnostics,
                    &[ToolCapability::Trace],
                    true,
                    "Trace enrichment with ASN and geographic context when available.",
                    github_update(
                        "nxtrace/NTrace-core",
                        true,
                        "Auto-download can use the latest GitHub release when the managed tool runtime is enabled.",
                    ),
                ),
                descriptor(
                    "globalping",
                    "Globalping API",
                    ToolSource::Globalping,
                    InstallStrategy::ApiOnly,
                    ToolRisk::SafeRemoteVantage,
                    ToolCategory::RemoteVantage,
                    &[
                        ToolCapability::Ping,
                        ToolCapability::Trace,
                        ToolCapability::DnsLookup,
                        ToolCapability::HttpProbe,
                        ToolCapability::RemoteMeasurement,
                    ],
                    false,
                    "Remote public probes for ping, trace, DNS, MTR, and HTTP; not used for public port checks.",
                    ToolUpdateInfo {
                        source_label: "Globalping API".into(),
                        source_url: "https://www.jsdelivr.com/globalping".into(),
                        latest_url: "https://www.jsdelivr.com/globalping".into(),
                        update_supported: false,
                        update_note: "API-only provider; there is no local binary to update.".into(),
                    },
                ),
                descriptor(
                    "sonarnwork-remote-scan",
                    "SonarNwork remote scan",
                    ToolSource::SonarNwork,
                    InstallStrategy::ApiOnly,
                    ToolRisk::ActiveScanner,
                    ToolCategory::RemoteVantage,
                    &[ToolCapability::RemoteMeasurement, ToolCapability::PortScan],
                    false,
                    "Token handoff for explicitly scoped public service checks.",
                    ToolUpdateInfo {
                        source_label: "SonarNwork remote-scan".into(),
                        source_url: "sonarnwork://remote-scan".into(),
                        latest_url: "sonarnwork://remote-scan".into(),
                        update_supported: false,
                        update_note: "API-only provider; updates happen on the remote service side.".into(),
                    },
                ),
                descriptor(
                    "httpx",
                    "httpx",
                    ToolSource::ProjectDiscovery,
                    InstallStrategy::AutoDownload,
                    ToolRisk::ActiveScanner,
                    ToolCategory::Web,
                    &[ToolCapability::HttpProbe, ToolCapability::TlsProbe],
                    false,
                    "Managed web probing behind explicit target scope.",
                    github_update(
                        "projectdiscovery/httpx",
                        true,
                        "Auto-download can use the latest ProjectDiscovery GitHub release.",
                    ),
                ),
                descriptor(
                    "dnsx",
                    "dnsx",
                    ToolSource::ProjectDiscovery,
                    InstallStrategy::AutoDownload,
                    ToolRisk::Passive,
                    ToolCategory::Dns,
                    &[ToolCapability::DnsLookup],
                    false,
                    "Bulk DNS resolution for scoped lists.",
                    github_update(
                        "projectdiscovery/dnsx",
                        true,
                        "Auto-download can use the latest ProjectDiscovery GitHub release.",
                    ),
                ),
                descriptor(
                    "subfinder",
                    "subfinder",
                    ToolSource::ProjectDiscovery,
                    InstallStrategy::AutoDownload,
                    ToolRisk::Passive,
                    ToolCategory::Dns,
                    &[ToolCapability::SubdomainDiscovery],
                    false,
                    "Passive subdomain discovery for domains the user is allowed to assess.",
                    github_update(
                        "projectdiscovery/subfinder",
                        true,
                        "Auto-download can use the latest ProjectDiscovery GitHub release.",
                    ),
                ),
                descriptor(
                    "naabu",
                    "naabu",
                    ToolSource::ProjectDiscovery,
                    InstallStrategy::AutoDownload,
                    ToolRisk::ActiveScanner,
                    ToolCategory::PortDiscovery,
                    &[ToolCapability::PortScan],
                    false,
                    "Fast active port discovery, only behind explicit scan scope.",
                    github_update(
                        "projectdiscovery/naabu",
                        true,
                        "Auto-download can use the latest ProjectDiscovery GitHub release.",
                    ),
                ),
                descriptor(
                    "nuclei",
                    "nuclei",
                    ToolSource::ProjectDiscovery,
                    InstallStrategy::AutoDownload,
                    ToolRisk::IntrusiveScanner,
                    ToolCategory::VulnScanning,
                    &[ToolCapability::TemplateScan],
                    false,
                    "Template scanning is never beginner-default and requires explicit scope.",
                    github_update(
                        "projectdiscovery/nuclei",
                        true,
                        "Update from ProjectDiscovery GitHub releases; running templates still requires explicit scope.",
                    ),
                ),
                descriptor(
                    "nmap",
                    "nmap",
                    ToolSource::NmapOrg,
                    InstallStrategy::DetectOnly,
                    ToolRisk::ActiveScanner,
                    ToolCategory::PortDiscovery,
                    &[ToolCapability::PortScan],
                    false,
                    "Detect-only integration; SonarNwork does not bundle Nmap.",
                    ToolUpdateInfo {
                        source_label: "Nmap.org".into(),
                        source_url: "https://nmap.org/download.html".into(),
                        latest_url: "https://nmap.org/download.html".into(),
                        update_supported: false,
                        update_note: "Detect-only: install or update Nmap with the system installer/package manager, then refresh detection in SonarNwork.".into(),
                    },
                ),
            ],
        }
    }

    pub fn update_plan(&self, tool_id: &str) -> Result<ToolUpdatePlan> {
        let descriptor = self
            .tools
            .iter()
            .find(|tool| tool.id == tool_id)
            .ok_or_else(|| ToolError::NotFound(tool_id.to_string()))?;

        Ok(ToolUpdatePlan {
            tool_id: descriptor.id.clone(),
            display_name: descriptor.display_name.clone(),
            source_label: descriptor.update.source_label.clone(),
            source_url: descriptor.update.source_url.clone(),
            latest_url: descriptor.update.latest_url.clone(),
            update_supported: descriptor.update.update_supported,
            update_note: descriptor.update.update_note.clone(),
        })
    }
}

fn descriptor(
    id: &str,
    display_name: &str,
    source: ToolSource,
    install_strategy: InstallStrategy,
    risk: ToolRisk,
    category: ToolCategory,
    capabilities: &[ToolCapability],
    default_enabled: bool,
    notes: &str,
    update: ToolUpdateInfo,
) -> ManagedToolDescriptor {
    ManagedToolDescriptor {
        id: id.into(),
        display_name: display_name.into(),
        source,
        install_strategy,
        risk,
        category,
        capabilities: capabilities.to_vec(),
        default_enabled,
        notes: notes.into(),
        update,
    }
}

fn github_update(repo: &str, update_supported: bool, update_note: &str) -> ToolUpdateInfo {
    ToolUpdateInfo {
        source_label: format!("GitHub: {repo}"),
        source_url: format!("https://github.com/{repo}"),
        latest_url: format!("https://github.com/{repo}/releases/latest"),
        update_supported,
        update_note: update_note.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_is_detect_only() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let nmap = catalog.tools.iter().find(|tool| tool.id == "nmap").unwrap();

        assert!(matches!(nmap.install_strategy, InstallStrategy::DetectOnly));
        assert!(!nmap.default_enabled);
        assert!(!nmap.update.update_supported);
    }

    #[test]
    fn nuclei_updates_from_projectdiscovery_github() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let nuclei = catalog
            .tools
            .iter()
            .find(|tool| tool.id == "nuclei")
            .unwrap();

        assert!(nuclei.update.update_supported);
        assert_eq!(
            nuclei.update.latest_url,
            "https://github.com/projectdiscovery/nuclei/releases/latest"
        );
    }

    #[test]
    fn update_plan_returns_tool_policy() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let plan = catalog.update_plan("nuclei").unwrap();

        assert_eq!(plan.tool_id, "nuclei");
        assert!(plan.update_supported);
        assert!(plan.source_label.contains("projectdiscovery/nuclei"));
    }

    #[test]
    fn intrusive_tools_are_not_default_enabled() {
        let catalog = ToolCatalog::phase_zero_defaults();

        assert!(catalog
            .tools
            .iter()
            .filter(|tool| matches!(tool.risk, ToolRisk::IntrusiveScanner))
            .all(|tool| !tool.default_enabled));
    }

    #[test]
    fn globalping_is_not_a_public_port_checker() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let globalping = catalog
            .tools
            .iter()
            .find(|tool| tool.id == "globalping")
            .unwrap();

        assert!(matches!(globalping.risk, ToolRisk::SafeRemoteVantage));
        assert!(!globalping.capabilities.contains(&ToolCapability::PortScan));
    }
}
