use thiserror::Error;

pub type Result<T> = std::result::Result<T, SonarError>;

#[derive(Debug, Error)]
pub enum SonarError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),

    #[error("probe not found: {0}")]
    ProbeNotFound(String),

    #[error("probe `{probe_id}` does not apply to entity `{entity_id}`")]
    ProbeDoesNotApply { probe_id: String, entity_id: String },

    #[error("probe `{probe_id}` is {status} and cannot run yet")]
    ProbeNotReady { probe_id: String, status: String },

    #[error("scope denied: {0}")]
    ScopeDenied(String),

    #[error("command failed: {0}")]
    CommandFailed(String),
}
