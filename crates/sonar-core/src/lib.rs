pub mod app;
pub mod entity;
pub mod error;
pub mod graph;
pub mod interaction;
pub mod probe;
pub mod scanner;
pub mod scope;

pub use app::{
    AppCore, AppInfo, NextAction, ProbeProfile, ProbeTarget, RemoteMeasurementKind,
    RemoteVantagePlan, RemoteVantageProvider, RemoteVantageRequest, ResultInterpretation,
    ResultVerdict, VerdictStatus, WorkflowDescriptor, PRODUCT_NAME,
};
pub use entity::{
    parse_entity_guess, CertInfo, DnsRecord, DomainName, Entity, EntityId, EntityKind, HostEntity,
    L4Proto, PortEntity, PortState,
};
pub use error::{Result, SonarError};
pub use graph::{Confidence, EntityEdge, EntityNode, PivotGraph, Provenance, RelationKind};
pub use interaction::{
    core_interaction_catalog, scanner_interaction_namespace, InteractionCapability,
    InteractionCatalog, InteractionChoice, InteractionField, InteractionFieldKind,
    InteractionGroup, InteractionNamespace, InteractionVisibility, INTERACTION_SCHEMA_VERSION,
};
pub use probe::{
    command_target, Artifact, ArtifactKind, CommandInvocation, DiscoveredEntity, DnsLookupProfile,
    EdgeDraft, Finding, HttpProbeProfile, PingProfile, PortCheckProfile, Probe, ProbeCategory,
    ProbeCtx, ProbeDescriptor, ProbeOutput, ProbeRegistry, ProbeRequirement, ProbeRisk,
    ProbeStatus, ProbeWarning, Severity, SummaryRow, TraceProfile, TraceProtocol,
};
pub use scanner::{
    summarize_scanner_output, ExternalScannerKind, ExternalScannerMode, ExternalScannerPorts,
    ExternalScannerProfile,
};
pub use scope::{ActionClass, ScopeDecision, ScopeGuard, ScopePolicy};
