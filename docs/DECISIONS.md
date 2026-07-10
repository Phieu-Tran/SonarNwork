# Decisions

This file records durable project decisions. Current code and tests are the
source of truth.

## 0001. Product Name

**Decision:** The official product name is **SonarNwork**. Internal Rust crates
retain the concise `sonar-*` prefix.

**Rationale:** The product name remains consistent in user-facing surfaces,
while short crate names keep workspace imports readable.

## 0002. Shared Core, Multiple Shells

**Decision:** CLI and desktop behavior share `sonar-core`. Probe definitions,
parsers, scope rules, command generation, interpretations, workflows, and graph
semantics belong in the core rather than in a shell.

**Rationale:** The CLI and GUI may present results differently without
disagreeing about what was executed or what the result means.

## 0003. Implemented Documentation Replaces Planning Briefs

**Decision:** Completed proposals, redesign handoffs, reference surveys, and
phase plans are removed from the working tree after their durable conclusions
have been captured in code, tests, `ARCHITECTURE.md`, or this file. Git history
remains the archive for those inputs.

**Rationale:** Keeping stale plans beside living documentation creates multiple
conflicting sources of truth and makes implemented behavior look unfinished.

## 0004. Beginner-First, Raw-Output-Preserving Surfaces

**Decision:** Default surfaces show structured summaries, verdicts, workflows,
and next actions. Raw output and advanced commands remain available.

**Rationale:** New users need an explanation before command detail, while
experienced users still need evidence and escape hatches.

## 0005. Probe Registry Is the Execution Gate

**Decision:** A structured probe run must pass through `ProbeRegistry::run`.
The registry validates probe existence, target applicability, readiness, and
scope before execution, then constructs the run graph.

**Rationale:** Central enforcement prevents a UI, CLI command, or future adapter
from bypassing status and safety policy.

## 0006. Scope Is Derived From Declared Risk

**Decision:** Each `ProbeDescriptor` declares a `ProbeRisk`, which maps to an
`ActionClass` checked by `ScopeGuard`. A user-supplied command override is always
treated as `ExternalTool`, even when it replaces a safe built-in invocation.

**Rationale:** Safety must follow the action actually performed, not the button
or workflow from which it originated.

## 0007. Structured and Live Runs Are Separate Paths

**Decision:** `run_probe` returns the canonical `ProbeRunView`, including
descriptor, structured output, graph, and interpretation. `run_probe_live`
streams child-process output and returns a `ProbeLiveSummary`; it does not claim
to produce a structured probe result.

**Rationale:** Live terminal feedback and domain interpretation have different
lifecycle and data requirements. Keeping them explicit avoids treating partial
or cancelled output as a completed diagnostic result.

## 0008. Live Processes Are Addressed by Run ID

**Decision:** Tauri owns a synchronized `LiveProcesses` registry keyed by a
frontend-generated `run_id`. Events include that ID, and cancellation targets
the registered child process.

**Rationale:** IDs isolate stale/concurrent events and allow cancellation while
preserving output already delivered to the UI.

## 0009. Platform Commands and Parsers Live in Shared Rust

**Decision:** Windows/Unix command selection, command profiles, and raw-output
summarization live in `sonar-core::probe`; OS inventory abstractions live in
`sonar-os`.

**Rationale:** Platform differences are product behavior and must remain
consistent across CLI and desktop shells.

## 0010. Graphs Preserve Probe Provenance

**Decision:** Each structured run produces a `PivotGraph` whose nodes and edges
carry probe/run provenance and confidence. Entities are deduplicated by stable
entity ID.

**Rationale:** Findings need traceability, and later pivots must distinguish
observed relationships from presentation-only associations.

## 0011. Remote Vantage Is Planned Explicitly

**Decision:** Remote-vantage APIs currently return a `RemoteVantagePlan` with
allowed probes and warnings. Globalping-style measurements do not perform
public ingress port checks; those require the separately scoped SonarNwork
remote-scan provider.

**Rationale:** Planning without implicit execution makes provider capability,
token handoff, and authorization boundaries visible.

## 0012. Managed Tools Are Policy Metadata, Not a Bypass

**Decision:** `sonar-tools` describes tool sources, capabilities, install/update
strategy, and risk. A managed-tool workflow does not bypass probe readiness or
scope enforcement.

**Rationale:** Tool availability and authorization are separate concerns.

## 0013. Tauri Owns Desktop Transport and Process Lifecycle

**Decision:** The Tauri crate owns IPC registration, serialization adapters,
terminal handoff, live child processes, and desktop-only snapshots. It delegates
probe meaning and safety to shared crates.

**Rationale:** This keeps framework-specific concerns at the boundary and makes
the core reusable by the CLI, reports, tests, and future adapters.
