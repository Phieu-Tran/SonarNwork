use std::{
    collections::HashSet,
    fs,
    io::{self, Cursor},
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, OnceLock},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sonar_core::{
    core_interaction_catalog, scanner_interaction_namespace, AppCore, CommandInvocation,
    ExternalScannerKind, InteractionCapability, InteractionCatalog, InteractionNamespace,
    ProbeTarget,
};
use thiserror::Error;

pub mod history;
pub mod operations;
pub mod remote;

pub type Result<T> = std::result::Result<T, ToolError>;

/// Scope gate for scanner invocations.
///
/// This is the single mandatory gate that all scanner call sites must pass through.
/// It validates that the target is within scope for the scanner's action class
/// before building/returning a runnable `CommandInvocation`.
///
/// Returns the invocation from the closure only if scope allows; otherwise returns
/// the scope denial error. There is no other path to obtain a `CommandInvocation`
/// for an external scanner.
pub fn scanner_scope_gate<F, E>(
    core: &AppCore,
    kind: ExternalScannerKind,
    target: &ProbeTarget,
    build_invocation: F,
) -> std::result::Result<CommandInvocation, E>
where
    F: FnOnce() -> std::result::Result<CommandInvocation, E>,
    E: From<sonar_core::error::SonarError>,
{
    let action_class = kind.action_class();
    core.ensure_allowed_for_target(target, action_class).map_err(E::from)?;
    build_invocation()
}

const MAX_NUCLEI_ARCHIVE_BYTES: u64 = 350 * 1024 * 1024;
static MANAGED_INSTALL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("managed tool not found: {0}")]
    NotFound(String),

    #[error("managed tool operation is not implemented yet: {0}")]
    NotImplemented(&'static str),

    #[error("managed tool descriptor is invalid: {0}")]
    InvalidDescriptor(String),

    #[error("managed tool operation failed: {0}")]
    Operation(String),
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
    pub target_kinds: Vec<ToolTargetKind>,
    pub interactions: Vec<ToolInteraction>,
    pub scope_requirement: ToolScopeRequirement,
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
    SystemInstaller,
    ManagedDownload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolTargetKind {
    Host,
    IpAddress,
    Url,
    Domain,
    NetworkRange,
    CurrentPath,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolInteraction {
    Preview,
    RunInApp,
    OpenInCli,
    Stop,
    StructuredOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolScopeRequirement {
    None,
    ActiveTarget,
    IntrusiveTarget,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolRuntimeStatus {
    pub tool_id: String,
    pub available: bool,
    pub executable: Option<PathBuf>,
    pub version: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolLifecyclePlan {
    pub tool_id: String,
    pub install_strategy: InstallStrategy,
    pub installed: bool,
    pub install_supported: bool,
    pub update_supported: bool,
    pub managed: bool,
    pub action_url: Option<String>,
    pub note: String,
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
    pub fn runtime_status(&self, tool_id: &str) -> Result<ToolRuntimeStatus> {
        if !self.tools.iter().any(|tool| tool.id == tool_id) {
            return Err(ToolError::NotFound(tool_id.to_string()));
        }

        let candidates: Vec<PathBuf> = match tool_id {
            "nmap" | "nuclei" | "httpx" | "naabu" | "subfinder" | "dnsx" | "trippy"
            | "nexttrace" => scanner_runtime_candidates(tool_id),
            _ => {
                return Ok(ToolRuntimeStatus {
                    tool_id: tool_id.to_string(),
                    available: false,
                    executable: None,
                    version: None,
                    error: Some("runtime detection is not implemented for this tool".into()),
                });
            }
        };

        let version_args: &[&str] = match tool_id {
            "nmap" => &["--version"],
            "trippy" | "nexttrace" => &["--version"],
            _ => &["-version"],
        };
        let mut errors = Vec::new();

        for candidate in candidates {
            if candidate.is_absolute() && !candidate.is_file() {
                continue;
            }

            match Command::new(&candidate).args(version_args).output() {
                Ok(output) => {
                    let combined = format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    let version = combined
                        .lines()
                        .map(str::trim)
                        .find(|line| !line.is_empty())
                        .map(str::to_string);
                    if output.status.success() && version_output_matches(tool_id, &combined) {
                        return Ok(ToolRuntimeStatus {
                            tool_id: tool_id.to_string(),
                            available: true,
                            executable: Some(candidate),
                            version,
                            error: None,
                        });
                    }
                    errors.push(if output.status.success() {
                        format!(
                            "{} is not the expected {tool_id} executable",
                            candidate.display()
                        )
                    } else {
                        format!(
                            "{} version command exited with {}",
                            candidate.display(),
                            output.status
                        )
                    });
                }
                Err(err) => errors.push(err.to_string()),
            }
        }

        Ok(ToolRuntimeStatus {
            tool_id: tool_id.to_string(),
            available: false,
            executable: None,
            version: None,
            error: Some(if errors.is_empty() {
                format!("{tool_id} was not found")
            } else {
                errors.join("; ")
            }),
        })
    }

    pub fn phase_zero_defaults() -> Self {
        let catalog = Self {
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
                    "Token handoff for public service checks with bounded targets.",
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
                    "Managed web probing with bounded target validation.",
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
                    "Bulk DNS resolution for target lists.",
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
                    "Fast active port discovery with bounded scan profiles.",
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
                    InstallStrategy::ManagedDownload,
                    ToolRisk::IntrusiveScanner,
                    ToolCategory::VulnScanning,
                    &[ToolCapability::TemplateScan],
                    false,
                    "Template scanning is never beginner-default and uses bounded profiles.",
                    github_update(
                        "projectdiscovery/nuclei",
                        true,
                        "Update from ProjectDiscovery GitHub releases; template execution remains bounded by profile.",
                    ),
                ),
                descriptor(
                    "nmap",
                    "nmap",
                    ToolSource::NmapOrg,
                    InstallStrategy::SystemInstaller,
                    ToolRisk::ActiveScanner,
                    ToolCategory::PortDiscovery,
                    &[ToolCapability::PortScan],
                    false,
                    "SonarNwork scanner package; the app manages detection and launch, while the official Nmap installer may request Npcap or system permission.",
                    ToolUpdateInfo {
                        source_label: "Nmap.org".into(),
                        source_url: "https://nmap.org/download.html".into(),
                        latest_url: "https://nmap.org/download.html".into(),
                        update_supported: true,
                        update_note: "Install or update from SonarNwork using the official Nmap installer, then refresh package detection.".into(),
                    },
                ),
            ],
        };
        debug_assert!(catalog.validate().is_ok());
        catalog
    }

    pub fn interaction_catalog(&self) -> InteractionCatalog {
        let mut catalog = core_interaction_catalog();
        catalog.extend(self.interaction_namespaces());
        debug_assert!(catalog.validate().is_ok());
        catalog
    }

    pub fn interaction_namespaces(&self) -> Vec<InteractionNamespace> {
        self.tools
            .iter()
            .filter_map(|tool| {
                let kind = ExternalScannerKind::from_tool_id(&tool.id)?;
                let mut namespace = scanner_interaction_namespace(kind);
                namespace.label = tool.display_name.clone();
                namespace.description = tool.notes.clone();
                namespace
                    .capabilities
                    .retain(|capability| match capability {
                        InteractionCapability::Preview => {
                            tool.interactions.contains(&ToolInteraction::Preview)
                        }
                        InteractionCapability::Run => {
                            tool.interactions.contains(&ToolInteraction::RunInApp)
                        }
                        InteractionCapability::Stop => {
                            tool.interactions.contains(&ToolInteraction::Stop)
                        }
                        InteractionCapability::OpenInCli => {
                            tool.interactions.contains(&ToolInteraction::OpenInCli)
                        }
                        _ => true,
                    });
                if matches!(
                    tool.install_strategy,
                    InstallStrategy::SystemInstaller
                        | InstallStrategy::ManagedDownload
                        | InstallStrategy::AutoDownload
                ) {
                    namespace.capabilities.push(InteractionCapability::Install);
                }
                if tool.update.update_supported {
                    namespace.capabilities.push(InteractionCapability::Update);
                }
                Some(namespace)
            })
            .collect()
    }

    pub fn validate(&self) -> Result<()> {
        let mut ids = HashSet::new();
        for tool in &self.tools {
            if tool.id.trim().is_empty() || tool.capabilities.is_empty() {
                return Err(ToolError::InvalidDescriptor(tool.id.clone()));
            }
            if !ids.insert(tool.id.as_str()) {
                return Err(ToolError::InvalidDescriptor(format!(
                    "duplicate tool id: {}",
                    tool.id
                )));
            }
            if matches!(tool.risk, ToolRisk::IntrusiveScanner)
                && tool.scope_requirement != ToolScopeRequirement::IntrusiveTarget
            {
                return Err(ToolError::InvalidDescriptor(format!(
                    "{} must require intrusive target scope",
                    tool.id
                )));
            }
            if tool.interactions.contains(&ToolInteraction::RunInApp)
                && !tool.interactions.contains(&ToolInteraction::Preview)
            {
                return Err(ToolError::InvalidDescriptor(format!(
                    "{} cannot run without command preview support",
                    tool.id
                )));
            }
        }
        Ok(())
    }

    pub fn lifecycle_plan(&self, tool_id: &str) -> Result<ToolLifecyclePlan> {
        let descriptor = self
            .tools
            .iter()
            .find(|tool| tool.id == tool_id)
            .ok_or_else(|| ToolError::NotFound(tool_id.to_string()))?;
        let installed = self.runtime_status(tool_id)?.available;
        let (install_supported, managed, action_url, note) = match descriptor.install_strategy {
            InstallStrategy::SystemInstaller => (
                true,
                true,
                Some(descriptor.update.source_url.clone()),
                "SonarNwork manages this scanner package through the official installer; Nmap may require Npcap or system permission."
                    .into(),
            ),
            InstallStrategy::ManagedDownload => (
                cfg!(target_os = "windows"),
                true,
                None,
                "Install or update explicitly into per-user SonarNwork application data.".into(),
            ),
            InstallStrategy::AutoDownload => (
                cfg!(target_os = "windows"),
                true,
                None,
                "Install or update explicitly from the tool's allow-listed official GitHub release into per-user SonarNwork application data.".into(),
            ),
            _ => (false, false, None, descriptor.notes.clone()),
        };
        Ok(ToolLifecyclePlan {
            tool_id: tool_id.into(),
            install_strategy: descriptor.install_strategy.clone(),
            installed,
            install_supported,
            update_supported: descriptor.update.update_supported,
            managed,
            action_url,
            note,
        })
    }

    pub fn install_managed(&self, tool_id: &str) -> Result<ToolRuntimeStatus> {
        let descriptor = self
            .tools
            .iter()
            .find(|tool| tool.id == tool_id)
            .ok_or_else(|| ToolError::NotFound(tool_id.to_string()))?;
        if !matches!(
            descriptor.install_strategy,
            InstallStrategy::ManagedDownload | InstallStrategy::AutoDownload
        ) {
            return Err(ToolError::Operation(format!(
                "{tool_id} uses a managed installer handoff, not direct binary download"
            )));
        }
        if !matches!(
            tool_id,
            "nuclei" | "httpx" | "naabu" | "subfinder" | "dnsx" | "trippy" | "nexttrace"
        ) || !cfg!(target_os = "windows")
        {
            return Err(ToolError::Operation(format!(
                "managed installation for {tool_id} is not supported on this platform"
            )));
        }
        install_latest_managed_tool(tool_id)?;
        self.runtime_status(tool_id)
    }

    /// Remove the per-user managed install of a managed-download tool. Only the
    /// SonarNwork-managed copy is deleted; a separate system/PATH install (if any)
    /// is left untouched. Returns whether a managed copy was actually removed.
    pub fn uninstall_managed(&self, tool_id: &str) -> Result<bool> {
        let descriptor = self
            .tools
            .iter()
            .find(|tool| tool.id == tool_id)
            .ok_or_else(|| ToolError::NotFound(tool_id.to_string()))?;
        if !matches!(
            descriptor.install_strategy,
            InstallStrategy::ManagedDownload | InstallStrategy::AutoDownload
        ) {
            return Err(ToolError::Operation(format!(
                "{tool_id} is not a managed-download tool; there is no managed copy to remove"
            )));
        }
        let root = managed_tool_root()
            .ok_or_else(|| ToolError::Operation("LOCALAPPDATA is unavailable".into()))?;
        remove_managed_tool(tool_id, &root)
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

#[allow(clippy::too_many_arguments)]
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
    let (target_kinds, interactions, scope_requirement) = match id {
        "nmap" | "naabu" => (
            vec![
                ToolTargetKind::Host,
                ToolTargetKind::IpAddress,
                ToolTargetKind::NetworkRange,
            ],
            scanner_interactions(),
            ToolScopeRequirement::ActiveTarget,
        ),
        "nuclei" | "httpx" => (
            vec![ToolTargetKind::Url],
            scanner_interactions(),
            if id == "nuclei" {
                ToolScopeRequirement::IntrusiveTarget
            } else {
                ToolScopeRequirement::ActiveTarget
            },
        ),
        "subfinder" => (
            vec![ToolTargetKind::Domain],
            scanner_interactions(),
            ToolScopeRequirement::ActiveTarget,
        ),
        "dnsx" => (
            vec![ToolTargetKind::Domain],
            scanner_interactions(),
            ToolScopeRequirement::IntrusiveTarget,
        ),
        "trippy" | "nexttrace" => (
            vec![
                ToolTargetKind::Host,
                ToolTargetKind::IpAddress,
                ToolTargetKind::Domain,
            ],
            scanner_interactions(),
            ToolScopeRequirement::ActiveTarget,
        ),
        _ => (Vec::new(), Vec::new(), ToolScopeRequirement::None),
    };
    ManagedToolDescriptor {
        id: id.into(),
        display_name: display_name.into(),
        source,
        install_strategy,
        risk,
        category,
        capabilities: capabilities.to_vec(),
        target_kinds,
        interactions,
        scope_requirement,
        default_enabled,
        notes: notes.into(),
        update,
    }
}

fn scanner_interactions() -> Vec<ToolInteraction> {
    vec![
        ToolInteraction::Preview,
        ToolInteraction::RunInApp,
        ToolInteraction::OpenInCli,
        ToolInteraction::Stop,
        ToolInteraction::StructuredOutput,
    ]
}

fn managed_tool_root() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|path| path.join("SonarNwork").join("tools"))
}

fn managed_tool_executable(tool_id: &str) -> Option<PathBuf> {
    managed_tool_root().map(|root| root.join(tool_id).join(format!("{tool_id}.exe")))
}

fn scanner_runtime_candidates(tool_id: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let executable_names = scanner_executable_names(tool_id);
    push_tool_env_candidates(&mut paths, tool_id, executable_names);
    if cfg!(target_os = "windows") {
        push_managed_and_common_windows_candidates(&mut paths, tool_id, executable_names);
        match tool_id {
            "nmap" => {
                push_unique(&mut paths, PathBuf::from(r"C:\Program Files\Nmap\nmap.exe"));
                push_unique(
                    &mut paths,
                    PathBuf::from(r"C:\Program Files (x86)\Nmap\nmap.exe"),
                );
            }
            "nuclei" => {
                push_unique(
                    &mut paths,
                    PathBuf::from(r"C:\ProgramData\chocolatey\bin\nuclei.exe"),
                );
                if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
                    push_unique(
                        &mut paths,
                        home.join("scoop").join("shims").join("nuclei.exe"),
                    );
                }
            }
            _ => {}
        }
        if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
            for executable in executable_names {
                push_unique(
                    &mut paths,
                    home.join("go")
                        .join("bin")
                        .join(format!("{executable}.exe")),
                );
                push_unique(
                    &mut paths,
                    home.join("scoop")
                        .join("shims")
                        .join(format!("{executable}.exe")),
                );
            }
        }
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            for executable in executable_names {
                push_unique(
                    &mut paths,
                    local_app_data
                        .join("Microsoft")
                        .join("WinGet")
                        .join("Links")
                        .join(format!("{executable}.exe")),
                );
            }
        }
        if let Some(path) = std::env::var_os("PATH") {
            for directory in std::env::split_paths(&path) {
                for executable in executable_names {
                    push_unique(&mut paths, directory.join(format!("{executable}.exe")));
                }
            }
        }
        for executable in executable_names {
            push_unique(&mut paths, PathBuf::from(format!("{executable}.exe")));
        }
    } else {
        if let Some(path) = std::env::var_os("PATH") {
            for directory in std::env::split_paths(&path) {
                for executable in executable_names {
                    push_unique(&mut paths, directory.join(executable));
                }
            }
        }
        for executable in executable_names {
            push_unique(&mut paths, PathBuf::from(executable));
        }
    }
    paths
}

fn scanner_executable_names(tool_id: &str) -> &'static [&'static str] {
    match tool_id {
        "trippy" => &["trip", "trippy"],
        "nexttrace" => &["nexttrace", "nexttrace-tiny"],
        "nmap" => &["nmap"],
        "nuclei" => &["nuclei"],
        "httpx" => &["httpx"],
        "naabu" => &["naabu"],
        "subfinder" => &["subfinder"],
        "dnsx" => &["dnsx"],
        _ => &[],
    }
}

fn version_output_matches(tool_id: &str, output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    match tool_id {
        "nmap" => lower.contains("nmap version"),
        // Trippy's binary is `trip`; `trip --version` prints "trip <ver>", which
        // does not contain the string "trippy".
        "trippy" => lower.contains("trip"),
        "nexttrace" => lower.contains("nexttrace"),
        "nuclei" | "httpx" | "naabu" | "subfinder" | "dnsx" => lower.contains("current version"),
        _ => false,
    }
}

fn push_tool_env_candidates(paths: &mut Vec<PathBuf>, tool_id: &str, executable_names: &[&str]) {
    let upper = tool_id.to_ascii_uppercase();
    for key in [
        format!("SONARNWORK_{}_PATH", upper),
        format!("{}_PATH", upper),
    ] {
        if let Some(path) = std::env::var_os(key) {
            let path = PathBuf::from(path);
            push_unique(paths, path.clone());
            for executable in executable_names {
                if cfg!(target_os = "windows") {
                    push_unique(paths, path.join(format!("{executable}.exe")));
                } else {
                    push_unique(paths, path.join(executable));
                }
            }
        }
    }
}

fn push_managed_and_common_windows_candidates(
    paths: &mut Vec<PathBuf>,
    tool_id: &str,
    executable_names: &[&str],
) {
    if let Some(path) = managed_tool_executable(tool_id) {
        push_unique(paths, path);
    }
    let common_tool_dir = PathBuf::from(format!(r"C:\tools\{tool_id}"));
    for executable in executable_names {
        push_windows_tool_dir_candidates(paths, executable, &common_tool_dir);
        push_unique(paths, PathBuf::from(format!(r"C:\tools\{executable}.exe")));
    }
    push_unique(paths, common_tool_dir);
}

fn push_windows_tool_dir_candidates(paths: &mut Vec<PathBuf>, tool_id: &str, root: &Path) {
    let executable = format!("{tool_id}.exe");
    push_unique(paths, root.join(&executable));
    push_unique(paths, root.join("bin").join(&executable));
    push_unique(paths, root.join("current").join(&executable));
    push_unique(paths, root.join("latest").join(&executable));

    let Ok(entries) = fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            push_unique(paths, path.join(&executable));
            push_unique(paths, path.join("bin").join(&executable));
        }
    }
}

fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

#[derive(Deserialize)]
struct GithubRelease {
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

/// A managed release asset that has already been downloaded into memory.
struct DownloadedAsset {
    name: String,
    bytes: Vec<u8>,
}

/// Full production install path: fetch the latest release over the network, then
/// stage/verify/promote it into the per-user managed tool directory.
///
/// The work is split into three seams so the file-system half (staging, backup,
/// promotion, removal) can be exercised by hermetic tests without any network
/// access or a real executable:
/// - [`fetch_latest_managed_asset`] performs the network download.
/// - [`install_downloaded_asset`] performs the pure file-system install and takes
///   the executable verification step as an injectable closure.
/// - [`remove_managed_tool`] deletes an installed managed tool.
fn install_latest_managed_tool(tool_id: &str) -> Result<()> {
    let _guard = MANAGED_INSTALL_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| ToolError::Operation("managed installer lock is poisoned".into()))?;
    let asset = fetch_latest_managed_asset(tool_id)?;
    let root = managed_tool_root()
        .ok_or_else(|| ToolError::Operation("LOCALAPPDATA is unavailable".into()))?;
    install_downloaded_asset(
        tool_id,
        &asset.name,
        &asset.bytes,
        &root,
        verify_managed_executable,
    )?;
    Ok(())
}

/// Download the latest allow-listed Windows release asset for `tool_id`.
///
/// This is the only step that touches the network; it is covered by the gated
/// real-lifecycle integration test rather than the hermetic unit tests.
fn fetch_latest_managed_asset(tool_id: &str) -> Result<DownloadedAsset> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("SonarNwork/0.1")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|err| ToolError::Operation(err.to_string()))?;
    let repository = managed_tool_repository(tool_id)
        .ok_or_else(|| ToolError::Operation(format!("no managed release policy for {tool_id}")))?;
    let release: GithubRelease = client
        .get(format!(
            "https://api.github.com/repos/{repository}/releases/latest"
        ))
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|err| ToolError::Operation(err.to_string()))?
        .json()
        .map_err(|err| ToolError::Operation(err.to_string()))?;
    let asset = release
        .assets
        .into_iter()
        .find(|asset| managed_windows_asset(tool_id, &asset.name))
        .ok_or_else(|| {
            ToolError::Operation(format!(
                "official Windows amd64 {tool_id} asset was not found"
            ))
        })?;
    let allowed_prefix = format!("https://github.com/{repository}/releases/download/");
    if !asset.browser_download_url.starts_with(&allowed_prefix) {
        return Err(ToolError::Operation(
            "release asset URL is not allow-listed".into(),
        ));
    }
    let bytes = client
        .get(asset.browser_download_url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|err| ToolError::Operation(err.to_string()))?
        .bytes()
        .map_err(|err| ToolError::Operation(err.to_string()))?
        .to_vec();
    Ok(DownloadedAsset {
        name: asset.name,
        bytes,
    })
}

/// Production verification seam: run the staged binary's version command and
/// confirm it identifies as the expected tool.
fn verify_managed_executable(tool_id: &str, path: &Path) -> Result<()> {
    let version_args: &[&str] = match tool_id {
        "trippy" | "nexttrace" => &["--version"],
        _ => &["-version"],
    };
    let output = Command::new(path)
        .args(version_args)
        .output()
        .map_err(|err| ToolError::Operation(err.to_string()))?;
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() || !version_output_matches(tool_id, &combined) {
        return Err(ToolError::Operation(format!(
            "downloaded {tool_id} failed its version check"
        )));
    }
    Ok(())
}

/// Install an already-downloaded asset into `root` (the managed tools directory,
/// i.e. `root/<tool_id>/<tool_id>.exe`). Pure file-system work; `verify` decides
/// whether the staged binary is acceptable before it is promoted into place.
///
/// On any failure the staged file is removed; when replacing an existing install,
/// a failed promotion restores the previous binary.
fn install_downloaded_asset<F>(
    tool_id: &str,
    asset_name: &str,
    bytes: &[u8],
    root: &Path,
    verify: F,
) -> Result<PathBuf>
where
    F: Fn(&str, &Path) -> Result<()>,
{
    let destination = root.join(tool_id).join(format!("{tool_id}.exe"));
    let parent = destination
        .parent()
        .ok_or_else(|| ToolError::Operation("invalid managed tool directory".into()))?;
    fs::create_dir_all(parent).map_err(|err| ToolError::Operation(err.to_string()))?;
    let staged = parent.join(format!("{tool_id}.exe.pending"));
    let stage_result = if asset_name.ends_with(".zip") {
        extract_named_executable(bytes, managed_archive_executable(tool_id), &staged)
    } else if bytes.is_empty() || bytes.len() as u64 > MAX_NUCLEI_ARCHIVE_BYTES {
        Err(ToolError::Operation(format!(
            "{tool_id} executable size is invalid"
        )))
    } else {
        fs::write(&staged, bytes).map_err(|err| ToolError::Operation(err.to_string()))
    };
    if let Err(err) = stage_result {
        let _ = fs::remove_file(&staged);
        return Err(err);
    }
    if let Err(err) = verify(tool_id, &staged) {
        let _ = fs::remove_file(&staged);
        return Err(err);
    }
    promote_staged(tool_id, &staged, &destination)?;
    Ok(destination)
}

/// Atomically move the verified staged binary into `destination`, backing up and
/// restoring any previous install if the rename fails.
fn promote_staged(tool_id: &str, staged: &Path, destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| ToolError::Operation("invalid managed tool directory".into()))?;
    let backup = parent.join(format!("{tool_id}.exe.previous"));
    let had_previous = destination.exists();
    if had_previous {
        let _ = fs::remove_file(&backup);
        fs::rename(destination, &backup).map_err(|err| ToolError::Operation(err.to_string()))?;
    }
    if let Err(err) = fs::rename(staged, destination) {
        if had_previous {
            let _ = fs::rename(&backup, destination);
        }
        let _ = fs::remove_file(staged);
        return Err(ToolError::Operation(err.to_string()));
    }
    let _ = fs::remove_file(backup);
    Ok(())
}

/// Delete the managed install of `tool_id` under `root`. Returns whether anything
/// was removed; removing a tool that is not installed is a no-op success.
fn remove_managed_tool(tool_id: &str, root: &Path) -> Result<bool> {
    let dir = root.join(tool_id);
    if !dir.exists() {
        return Ok(false);
    }
    fs::remove_dir_all(&dir).map_err(|err| ToolError::Operation(err.to_string()))?;
    Ok(true)
}

fn managed_tool_repository(tool_id: &str) -> Option<&'static str> {
    match tool_id {
        "nuclei" => Some("projectdiscovery/nuclei"),
        "httpx" => Some("projectdiscovery/httpx"),
        "naabu" => Some("projectdiscovery/naabu"),
        "subfinder" => Some("projectdiscovery/subfinder"),
        "dnsx" => Some("projectdiscovery/dnsx"),
        "trippy" => Some("fujiapple852/trippy"),
        "nexttrace" => Some("nxtrace/NTrace-core"),
        _ => None,
    }
}

fn managed_windows_asset(tool_id: &str, asset_name: &str) -> bool {
    match tool_id {
        "trippy" => asset_name.contains("x86_64-pc-windows-msvc") && asset_name.ends_with(".zip"),
        "nexttrace" => asset_name == "nexttrace_windows_amd64.exe",
        _ => asset_name.ends_with("_windows_amd64.zip"),
    }
}

fn managed_archive_executable(tool_id: &str) -> &str {
    if tool_id == "trippy" {
        "trip.exe"
    } else {
        match tool_id {
            "nuclei" => "nuclei.exe",
            "httpx" => "httpx.exe",
            "naabu" => "naabu.exe",
            "subfinder" => "subfinder.exe",
            "dnsx" => "dnsx.exe",
            _ => "",
        }
    }
}

#[cfg(test)]
fn extract_single_executable(bytes: &[u8], destination: &Path) -> Result<()> {
    extract_named_executable(bytes, "nuclei.exe", destination)
}

fn extract_named_executable(bytes: &[u8], executable: &str, destination: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|err| ToolError::Operation(err.to_string()))?;
    // Some official release archives (e.g. Trippy's msvc zip) nest the binary in a
    // single versioned directory rather than placing it at the archive root, so
    // match the entry by its file name instead of requiring an exact path.
    let index = (0..archive.len()).find(|&i| {
        archive
            .by_index(i)
            .map(|entry| archive_entry_matches(entry.name(), executable))
            .unwrap_or(false)
    });
    let Some(index) = index else {
        return Err(ToolError::Operation(format!(
            "archive does not contain {executable}"
        )));
    };
    let mut entry = archive
        .by_index(index)
        .map_err(|err| ToolError::Operation(err.to_string()))?;
    if entry.size() == 0 || entry.size() > MAX_NUCLEI_ARCHIVE_BYTES {
        return Err(ToolError::Operation(format!(
            "{executable} size is invalid"
        )));
    }
    let mut file =
        fs::File::create(destination).map_err(|err| ToolError::Operation(err.to_string()))?;
    io::copy(&mut entry, &mut file).map_err(|err| ToolError::Operation(err.to_string()))?;
    Ok(())
}

/// Whether a zip entry path is the wanted executable, either at the archive root
/// or nested one or more directories deep. Directory separators are normalized so
/// both `/` and `\` archives match.
fn archive_entry_matches(entry_name: &str, executable: &str) -> bool {
    let normalized = entry_name.replace('\\', "/");
    normalized == executable || normalized.rsplit('/').next() == Some(executable)
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
    use std::io::{Cursor, Write};

    use super::*;

    #[test]
    fn nmap_uses_managed_installer_without_being_bundled() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let nmap = catalog.tools.iter().find(|tool| tool.id == "nmap").unwrap();

        assert!(matches!(
            nmap.install_strategy,
            InstallStrategy::SystemInstaller
        ));
        assert!(!nmap.default_enabled);
        assert!(nmap.update.update_supported);
        assert!(nmap.notes.contains("SonarNwork scanner package"));
        assert_eq!(nmap.scope_requirement, ToolScopeRequirement::ActiveTarget);
        assert!(nmap.interactions.contains(&ToolInteraction::OpenInCli));
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
        assert!(matches!(
            nuclei.install_strategy,
            InstallStrategy::ManagedDownload
        ));
        assert_eq!(nuclei.target_kinds, [ToolTargetKind::Url]);
        assert_eq!(
            nuclei.scope_requirement,
            ToolScopeRequirement::IntrusiveTarget
        );
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

    #[test]
    fn runtime_status_rejects_unknown_tool() {
        let catalog = ToolCatalog::phase_zero_defaults();
        assert!(matches!(
            catalog.runtime_status("not-a-tool"),
            Err(ToolError::NotFound(_))
        ));
    }

    #[test]
    fn metadata_only_tool_reports_detection_as_unimplemented() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let status = catalog.runtime_status("globalping").unwrap();

        assert!(!status.available);
        assert!(status.executable.is_none());
        assert!(status.error.unwrap().contains("not implemented"));
    }

    #[test]
    fn nuclei_detection_checks_common_windows_tool_dirs() {
        let candidates = scanner_runtime_candidates("nuclei");

        if cfg!(target_os = "windows") {
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from(r"C:\tools\nuclei\nuclei.exe")));
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from(r"C:\tools\nuclei\bin\nuclei.exe")));
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from(r"C:\tools\nuclei\current\nuclei.exe")));
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from(r"C:\tools\nuclei.exe")));
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from(r"C:\tools\nuclei")));
        } else {
            assert!(candidates
                .iter()
                .any(|path| path == &PathBuf::from("nuclei")));
        }
    }

    #[test]
    fn scanner_detection_expands_every_path_directory() {
        let candidates = scanner_runtime_candidates("nuclei");
        if let Some(path) = std::env::var_os("PATH") {
            for directory in std::env::split_paths(&path) {
                let executable = if cfg!(target_os = "windows") {
                    directory.join("nuclei.exe")
                } else {
                    directory.join("nuclei")
                };
                assert!(candidates.contains(&executable), "{}", executable.display());
            }
        }
    }

    #[test]
    fn runtime_identity_rejects_the_python_httpx_cli() {
        assert!(!version_output_matches(
            "httpx",
            "Usage: httpx [OPTIONS] URL\nError: No such option: -e"
        ));
        assert!(version_output_matches(
            "httpx",
            "[INF] Current Version: v1.7.2"
        ));
    }

    #[test]
    fn managed_release_assets_are_platform_specific() {
        assert!(managed_windows_asset(
            "httpx",
            "httpx_1.7.2_windows_amd64.zip"
        ));
        assert!(managed_windows_asset(
            "trippy",
            "trippy-0.13.0-x86_64-pc-windows-msvc.zip"
        ));
        assert!(managed_windows_asset(
            "nexttrace",
            "nexttrace_windows_amd64.exe"
        ));
        assert!(!managed_windows_asset("nexttrace", "ntr_windows_amd64.exe"));
    }

    #[test]
    fn windows_tool_dir_candidates_include_shallow_extracted_subdirs() {
        let root =
            std::env::temp_dir().join(format!("sonarnwork-tool-detect-{}", std::process::id()));
        let extracted = root.join("nuclei_3.8.0_windows_amd64");
        fs::create_dir_all(&extracted).unwrap();

        let mut candidates = Vec::new();
        push_windows_tool_dir_candidates(&mut candidates, "nuclei", &root);

        assert!(candidates.iter().any(|path| {
            path == &extracted.join("nuclei.exe")
                || path == &extracted.join("bin").join("nuclei.exe")
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_contract_is_valid() {
        ToolCatalog::phase_zero_defaults().validate().unwrap();
    }

    #[test]
    fn interaction_catalog_is_descriptor_driven_and_side_effect_free() {
        let catalog = ToolCatalog::phase_zero_defaults().interaction_catalog();
        catalog.validate().unwrap();

        let nmap = catalog.namespace("scanner.nmap").unwrap();
        assert!(nmap.capabilities.contains(&InteractionCapability::Status));
        assert!(nmap.capabilities.contains(&InteractionCapability::Install));
        assert!(nmap.capabilities.contains(&InteractionCapability::Update));
        assert!(nmap.fields.iter().any(|field| field.id == "ports"));

        let nuclei = catalog.namespace("scanner.nuclei").unwrap();
        assert!(nuclei
            .capabilities
            .contains(&InteractionCapability::Install));
        assert!(!nuclei.fields.iter().any(|field| field.id == "ports"));
    }

    #[test]
    fn every_executable_scanner_has_exactly_one_namespace() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let namespaces = catalog.interaction_namespaces();
        for tool in &catalog.tools {
            if ExternalScannerKind::from_tool_id(&tool.id).is_some() {
                assert_eq!(
                    namespaces
                        .iter()
                        .filter(|namespace| namespace.id == format!("scanner.{}", tool.id))
                        .count(),
                    1,
                    "{} must have one interaction namespace",
                    tool.id
                );
            }
        }
    }

    #[test]
    fn scanner_contracts_do_not_overlap_business_meaning() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let nmap = catalog.tools.iter().find(|tool| tool.id == "nmap").unwrap();
        let nuclei = catalog
            .tools
            .iter()
            .find(|tool| tool.id == "nuclei")
            .unwrap();

        assert!(nmap.capabilities.contains(&ToolCapability::PortScan));
        assert!(!nmap.capabilities.contains(&ToolCapability::TemplateScan));
        assert!(nuclei.capabilities.contains(&ToolCapability::TemplateScan));
        assert!(!nuclei.capabilities.contains(&ToolCapability::PortScan));
    }

    #[test]
    fn lifecycle_plan_presents_scanners_as_app_managed_packages() {
        let catalog = ToolCatalog::phase_zero_defaults();
        let nmap = catalog.lifecycle_plan("nmap").unwrap();
        let nuclei = catalog.lifecycle_plan("nuclei").unwrap();

        assert!(nmap.managed);
        assert!(nmap
            .action_url
            .as_deref()
            .unwrap()
            .starts_with("https://nmap.org/"));
        assert!(nmap.note.contains("SonarNwork manages"));
        assert!(nuclei.managed);
        assert!(nuclei.action_url.is_none());
    }

    #[test]
    fn managed_nuclei_path_is_user_data_not_repository_tools() {
        if let Some(path) = managed_tool_executable("nuclei") {
            assert!(path.ends_with(Path::new("SonarNwork/tools/nuclei/nuclei.exe")));
            assert!(!path.to_string_lossy().contains(".tools"));
            assert!(!path.to_string_lossy().contains("CARGO_MANIFEST_DIR"));
        }
    }

    #[test]
    fn catalog_validation_rejects_duplicate_ids() {
        let mut catalog = ToolCatalog::phase_zero_defaults();
        catalog.tools.push(catalog.tools[0].clone());

        assert!(matches!(
            catalog.validate(),
            Err(ToolError::InvalidDescriptor(_))
        ));
    }

    #[test]
    fn managed_install_rejects_installer_handoff() {
        let error = ToolCatalog::phase_zero_defaults()
            .install_managed("nmap")
            .unwrap_err();

        assert!(error.to_string().contains("installer handoff"));
    }

    #[test]
    fn nuclei_archive_requires_exact_nonempty_executable() {
        let temp = std::env::temp_dir().join("sonarnwork-nuclei-archive-test.exe");
        assert!(extract_single_executable(b"not a zip", &temp).is_err());

        let mut empty_archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        empty_archive
            .start_file("nuclei.exe", zip::write::SimpleFileOptions::default())
            .unwrap();
        let empty_bytes = empty_archive.finish().unwrap().into_inner();
        assert!(extract_single_executable(&empty_bytes, &temp).is_err());

        let mut valid_archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        valid_archive
            .start_file("nuclei.exe", zip::write::SimpleFileOptions::default())
            .unwrap();
        valid_archive.write_all(b"MZ-test").unwrap();
        let valid_bytes = valid_archive.finish().unwrap().into_inner();
        extract_single_executable(&valid_bytes, &temp).unwrap();
        assert_eq!(fs::read(&temp).unwrap(), b"MZ-test");
        let _ = fs::remove_file(temp);
    }

    // ---- Simulated managed-tool lifecycle (download → install → remove) --------
    //
    // These are hermetic: they never touch the network and never execute a real
    // binary. The download is simulated with in-memory bytes/zip, and the binary
    // verification step is injected, so the full staging/backup/promote/delete
    // file-system flow runs against a private temp directory.

    /// A verifier that always accepts the staged binary (stands in for a real
    /// successful `-version` check).
    fn accept_binary(_tool: &str, _path: &Path) -> Result<()> {
        Ok(())
    }

    /// Build an in-memory zip archive containing a single entry, mirroring how the
    /// ProjectDiscovery / trippy Windows release archives are shaped.
    fn zip_with(entry: &str, contents: &[u8]) -> Vec<u8> {
        let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
        archive
            .start_file(entry, zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(contents).unwrap();
        archive.finish().unwrap().into_inner()
    }

    /// A unique, isolated temp directory acting as the managed tools root.
    fn unique_temp_root(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sonarnwork-managed-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    /// Shape the simulated release asset (name + bytes) the way GitHub ships it
    /// for each managed tool, so the install path picks the right stage strategy.
    fn simulated_asset(tool_id: &str, contents: &[u8]) -> (String, Vec<u8>) {
        match tool_id {
            // NextTrace ships a bare .exe asset, not a zip.
            "nexttrace" => ("nexttrace_windows_amd64.exe".to_string(), contents.to_vec()),
            // Trippy ships an msvc zip whose entry is `trip.exe`.
            "trippy" => (
                "trippy-0.13.0-x86_64-pc-windows-msvc.zip".to_string(),
                zip_with(managed_archive_executable(tool_id), contents),
            ),
            // ProjectDiscovery tools ship `<tool>_<ver>_windows_amd64.zip`.
            _ => (
                format!("{tool_id}_1.0.0_windows_amd64.zip"),
                zip_with(managed_archive_executable(tool_id), contents),
            ),
        }
    }

    #[test]
    fn simulated_lifecycle_covers_every_managed_download_tool() {
        for tool in [
            "nuclei",
            "httpx",
            "naabu",
            "subfinder",
            "dnsx",
            "trippy",
            "nexttrace",
        ] {
            let root = unique_temp_root(&format!("all-{tool}"));
            let (asset_name, bytes) = simulated_asset(tool, b"MZ-simulated-binary");

            // Download + install.
            let destination =
                install_downloaded_asset(tool, &asset_name, &bytes, &root, accept_binary)
                    .unwrap_or_else(|err| panic!("{tool} install should succeed: {err}"));
            assert!(destination.exists(), "{tool} must be installed on disk");
            assert!(
                destination.ends_with(Path::new(&format!("{tool}/{tool}.exe"))),
                "{tool} must install to <root>/{tool}/{tool}.exe, got {}",
                destination.display()
            );
            assert_eq!(fs::read(&destination).unwrap(), b"MZ-simulated-binary");

            // Delete.
            assert!(
                remove_managed_tool(tool, &root).unwrap(),
                "{tool} removal must report a deleted copy"
            );
            assert!(!destination.exists(), "{tool} binary must be gone");
            assert!(!root.join(tool).exists(), "{tool} directory must be gone");
            // Removing again is an idempotent no-op.
            assert!(!remove_managed_tool(tool, &root).unwrap());

            fs::remove_dir_all(&root).ok();
        }
    }

    #[test]
    fn simulated_upgrade_replaces_binary_without_leaving_scratch_files() {
        let root = unique_temp_root("upgrade");
        let (name_v1, v1) = simulated_asset("nuclei", b"MZ-v1");
        let destination =
            install_downloaded_asset("nuclei", &name_v1, &v1, &root, accept_binary).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"MZ-v1");

        let (name_v2, v2) = simulated_asset("nuclei", b"MZ-v2-upgraded");
        let upgraded =
            install_downloaded_asset("nuclei", &name_v2, &v2, &root, accept_binary).unwrap();
        assert_eq!(fs::read(&upgraded).unwrap(), b"MZ-v2-upgraded");

        let parent = upgraded.parent().unwrap();
        assert!(
            !parent.join("nuclei.exe.previous").exists(),
            "backup must be cleaned up after a successful upgrade"
        );
        assert!(
            !parent.join("nuclei.exe.pending").exists(),
            "staging file must be cleaned up after a successful upgrade"
        );

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn simulated_install_rejecting_binary_leaves_no_partial_files() {
        let root = unique_temp_root("verify-fail");
        let reject = |tool: &str, _path: &Path| -> Result<()> {
            Err(ToolError::Operation(format!(
                "downloaded {tool} failed its version check"
            )))
        };
        let (asset_name, bytes) = simulated_asset("httpx", b"MZ-fake");

        let error =
            install_downloaded_asset("httpx", &asset_name, &bytes, &root, reject).unwrap_err();
        assert!(error.to_string().contains("version check"));

        assert!(!root.join("httpx").join("httpx.exe").exists());
        assert!(!root.join("httpx").join("httpx.exe.pending").exists());

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn simulated_failed_upgrade_keeps_the_previous_binary_intact() {
        let root = unique_temp_root("failed-upgrade");
        let (name_v1, v1) = simulated_asset("dnsx", b"MZ-good-v1");
        let destination =
            install_downloaded_asset("dnsx", &name_v1, &v1, &root, accept_binary).unwrap();

        let reject = |tool: &str, _path: &Path| -> Result<()> {
            Err(ToolError::Operation(format!("{tool} rejected")))
        };
        let (name_v2, v2) = simulated_asset("dnsx", b"MZ-bad-v2");
        let error = install_downloaded_asset("dnsx", &name_v2, &v2, &root, reject).unwrap_err();
        assert!(error.to_string().contains("rejected"));

        // The verified v1 binary is never touched when the replacement is rejected.
        assert_eq!(fs::read(&destination).unwrap(), b"MZ-good-v1");
        assert!(!destination
            .parent()
            .unwrap()
            .join("dnsx.exe.pending")
            .exists());

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn simulated_install_rejects_empty_raw_binary() {
        let root = unique_temp_root("empty-raw");
        let error =
            install_downloaded_asset("nexttrace", "nexttrace_windows_amd64.exe", b"", &root, accept_binary)
                .unwrap_err();
        assert!(error.to_string().contains("invalid"));
        assert!(!root.join("nexttrace").join("nexttrace.exe").exists());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn simulated_install_rejects_zip_missing_the_expected_executable() {
        let root = unique_temp_root("wrong-zip");
        // A zip that contains some other file, not the tool executable.
        let bytes = zip_with("README.txt", b"not the binary");
        let error = install_downloaded_asset(
            "nuclei",
            "nuclei_1.0.0_windows_amd64.zip",
            &bytes,
            &root,
            accept_binary,
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not contain nuclei.exe"));
        assert!(!root.join("nuclei").join("nuclei.exe").exists());
        assert!(!root.join("nuclei").join("nuclei.exe.pending").exists());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn simulated_install_extracts_binary_nested_in_a_versioned_dir() {
        // Trippy's official Windows zip nests `trip.exe` under a versioned folder
        // rather than at the archive root; installation must still find it.
        let root = unique_temp_root("nested-zip");
        let bytes = zip_with(
            "trippy-0.13.0-x86_64-pc-windows-msvc/trip.exe",
            b"MZ-nested-trip",
        );
        let destination = install_downloaded_asset(
            "trippy",
            "trippy-0.13.0-x86_64-pc-windows-msvc.zip",
            &bytes,
            &root,
            accept_binary,
        )
        .unwrap();
        assert!(destination.ends_with(Path::new("trippy/trippy.exe")));
        assert_eq!(fs::read(&destination).unwrap(), b"MZ-nested-trip");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn archive_entry_matches_root_and_nested_paths() {
        assert!(archive_entry_matches("trip.exe", "trip.exe"));
        assert!(archive_entry_matches("trippy-0.13.0/trip.exe", "trip.exe"));
        assert!(archive_entry_matches(
            "trippy-0.13.0\\bin\\trip.exe",
            "trip.exe"
        ));
        assert!(!archive_entry_matches("nottrip.exe", "trip.exe"));
        assert!(!archive_entry_matches("dir/README.txt", "trip.exe"));
    }

    #[test]
    fn uninstall_managed_rejects_non_managed_tools() {
        let catalog = ToolCatalog::phase_zero_defaults();
        // nmap is a system-installer handoff, globalping is API-only: neither has
        // a managed copy that SonarNwork may delete.
        let nmap = catalog.uninstall_managed("nmap").unwrap_err();
        assert!(nmap.to_string().contains("not a managed-download tool"));
        let globalping = catalog.uninstall_managed("globalping").unwrap_err();
        assert!(globalping.to_string().contains("not a managed-download tool"));
        assert!(matches!(
            catalog.uninstall_managed("not-a-tool"),
            Err(ToolError::NotFound(_))
        ));
    }

    #[test]
    fn scope_gate_blocks_out_of_scope_target() {
        use sonar_core::{AppCore, ExternalScannerKind, ProbeTarget};

        // Default AppCore has an empty scope — all external targets are denied.
        let core = AppCore::default();
        let target = ProbeTarget::Input("1.1.1.1".into());
        let kind = ExternalScannerKind::Nmap;

        let result: std::result::Result<CommandInvocation, sonar_core::SonarError> =
            super::scanner_scope_gate(&core, kind, &target, || {
                panic!("invocation builder must not be called when scope is denied");
            });

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("scope denied"),
            "error should mention scope denial: {err_msg}"
        );
    }

    #[test]
    fn scope_gate_allows_target_in_scope() {
        use sonar_core::{AppCore, ExternalScannerKind, ProbeTarget};

        // For explicit targets, the target is added to the scope policy.
        let core = AppCore::for_explicit_target(&ProbeTarget::Input("1.1.1.1".into())).unwrap();
        let target = ProbeTarget::Input("1.1.1.1".into());
        let kind = ExternalScannerKind::Nmap; // ActiveProbe

        let result: std::result::Result<CommandInvocation, sonar_core::SonarError> =
            super::scanner_scope_gate(&core, kind, &target, || {
                Ok(CommandInvocation::from_parts("echo", ["ok"]))
            });

        assert!(result.is_ok());
        assert_eq!(result.unwrap().program, "echo");
    }

    #[test]
    fn scope_gate_allows_passive_lookup_on_explicit_target() {
        use sonar_core::{AppCore, ExternalScannerKind, ProbeTarget};

        // For explicit targets, all action classes should be allowed.
        let core = AppCore::for_explicit_target(&ProbeTarget::Input("1.1.1.1".into())).unwrap();
        let target = ProbeTarget::Input("1.1.1.1".into());
        let kind = ExternalScannerKind::Subfinder; // PassiveLookup

        let result: std::result::Result<CommandInvocation, sonar_core::SonarError> =
            super::scanner_scope_gate(&core, kind, &target, || {
                Ok(CommandInvocation::from_parts("echo", ["ok"]))
            });

        assert!(result.is_ok());
        assert_eq!(result.unwrap().program, "echo");
    }
}
