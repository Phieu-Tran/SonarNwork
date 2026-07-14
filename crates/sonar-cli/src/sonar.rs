// `sonar` is the short, user-facing executable name. Keep it on the exact same
// code path as the compatibility `sonarnwork` binary so both shells expose the
// same catalog, validation, exit codes, and TUI behavior.
include!("main.rs");
