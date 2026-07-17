# Report: A3 — Bounded Profiles + Risk Labels

## Status: COMPLETE

## Scope of Changes

The implementation successfully replaced the "scope confirmation" model with "bounded profiles + risk labels".

### Changed Files
- `crates/sonar-core/src/interaction.rs`:
  - Added `InteractionRisk` enum (`Safe`, `Medium`, `High`).
  - Added `risk` field to `InteractionNamespace` and `InteractionChoice`.
  - Updated `namespace()` and `namespace_with_aliases()` to accept `risk` argument.
  - Updated `choice_field()` to accept risk labels for profiles.
  - Assigned risk levels to all core and scanner interaction namespaces:
    - Safe: Local inspection, passive lookups, bounded active probes (ping, trace, etc.).
    - Medium: Remote measurements, monitors, deep scanning profiles.
    - High: Intrusive scans (capture, nuclei full).
  - Added profile-specific risk labels for Nmap and Nuclei profiles.
  - Added unit tests: `nuclei_profile_risk_labels_are_correct`, `nmap_profile_risk_labels_are_correct`.

### Unchanged
- `crates/sonar-tools/src/lib.rs`: Already consistent with the new model.
- `crates/sonar-tools/src/operations.rs`: No changes required.
- `crates/sonar-tools/src/remote.rs`: No changes required.
- `crates/sonar-core/src/probe.rs`: `ProbeRisk` remains consistent with `InteractionRisk`.

## Test Results

### 1. `cargo test -p sonar-core --all-targets`
- **Exit Code**: 0
- **Result**: 39 passed, 0 failed.

### 2. `cargo test -p sonar-tools --all-targets`
- **Exit Code**: 0
- **Result**: All tests passed.

### 3. `cargo test --workspace`
- **Exit Code**: 0
- **Result**: 185 passed (183 baseline + 2 new risk-label tests).

### 4. Code Audit
- Grep `scope_confirmed` in `crates/sonar-{core,tools}`: No matches found.
- Scanner/Probe risk labels: All high-risk tools (IntrusiveScan) and profiles are explicitly labeled or default to safe.
- Test locks: Added `nuclei_profile_risk_labels_are_correct` and `nmap_profile_risk_labels_are_correct`.

### 5. Schema Check
- `InteractionNamespace` and `InteractionChoice` contracts updated with `risk` fields.
- `schema_version` is set to 2 (consistent with the working tree state).
- `interaction.rs` and tests pass validation.

### 6. Clippy
- **Exit Code**: 0
- **Result**: `cargo clippy --workspace --all-targets -- -D warnings` passed with no warnings.

## Blockers
None.
