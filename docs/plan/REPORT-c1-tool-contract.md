# REPORT — C1: Scope Gate for External Scanner Invocations

## Status

- **Task:** C1
- **Branch:** `work/c1-tool-contract`
- **Status:** DONE — round 1

## Gate Function

**Name:** `scanner_scope_gate`
**Location:** `crates/sonar-tools/src/lib.rs`
**Signature:**

```rust
pub fn scanner_scope_gate<F, E>(
    core: &AppCore,
    kind: ExternalScannerKind,
    target: &ProbeTarget,
    build_invocation: F,
) -> std::result::Result<CommandInvocation, E>
where
    F: FnOnce() -> std::result::Result<CommandInvocation, E>,
    E: From<sonar_core::error::SonarError>,
```

**Properties:**
- Accepts an `AppCore` (scoped to the target), the `ExternalScannerKind` (to derive `action_class()`), a `ProbeTarget`, and a closure that builds the `CommandInvocation`.
- Calls `core.ensure_allowed_for_target(target, action_class)` before invoking the closure.
- Returns the closure result only if scope allows; returns `SonarError::ScopeDenied` (converted to `E`) otherwise.
- Generic over the error type `E` so both app-tauri (`String`) and sonar-cli (`anyhow::Error`) can use it without conversion overhead.

## Call Sites Fixed

### 1. `scanner_invocation` (app-tauri)

**File:** `app/src-tauri/src/lib.rs:128`
**Change:** After resolving `AppCore` via `app_core_for_target(target)` and resolving the tool's runtime, the invocation building (profile construction + invocation generation) is wrapped inside `scanner_scope_gate(...)`. Scope is checked before any `CommandInvocation` is built.

### 2. `run_scanner_command` (sonar-cli)

**File:** `crates/sonar-cli/src/main.rs:1676`
**Change:** After parsing mode/ports but before execution, creates `AppCore::for_explicit_target(ProbeTarget::Input(target))` and wraps the entire profile building + invocation building + runtime resolution inside `scanner_scope_gate(...)`. The scope is validated before the command is executed.

## Tests Added

All in `crates/sonar-tools/src/lib.rs` (tests module):

1. **`scope_gate_blocks_out_of_scope_target`** — Default `AppCore` (empty scope) denies Nmap/ActiveProbe on `1.1.1.1`. Verifies closure is NOT called.
2. **`scope_gate_allows_target_in_scope`** — `AppCore::for_explicit_target("1.1.1.1")` allows Nmap/ActiveProbe on the same IP. Verifies closure IS called.
3. **`scope_gate_allows_passive_lookup_on_explicit_target`** — `AppCore::for_explicit_target("1.1.1.1")` allows Subfinder/PassiveLookup. Verifies closure returns invocation.

## Test Results

```
cargo test --workspace:
  202 passed, 4 ignored, 0 failed
  (baseline: 199 passed, 4 ignored — delta: +3 new tests)

cargo clippy --workspace --all-targets -- -D warnings:
  0 warnings
```

## Files Changed

| File | Change |
|------|--------|
| `crates/sonar-tools/src/lib.rs` | Added `scanner_scope_gate` function + 3 tests |
| `app/src-tauri/src/lib.rs` | `scanner_invocation` now calls `scanner_scope_gate` |
| `crates/sonar-cli/src/main.rs` | `run_scanner_command` now calls `scanner_scope_gate` |

## Not Changed

- No changes to `app/src/` (React UI)
- No changes to `operations.rs`, `remote.rs`
- No changes to `sonar-core/src/scanner.rs` (only read, not modified)
- No changes to `scanner_cli_invocation` (app-tauri, "open terminal" preview path)
- No changes to `ExternalScannerKind::action_class()` or risk tables
