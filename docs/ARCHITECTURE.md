# Architecture

SonarNwork is a Rust workspace with two user-facing shells: a Clap CLI and a
React application hosted by Tauri 2. Product semantics live in shared Rust
crates; the shells adapt those semantics to terminal and desktop interaction.

```text
React/TypeScript UI                         Clap CLI
        |                                     |
        | invoke / probe-live-output          |
        v                                     v
Tauri command adapter -----------------> sonar-core
        |                              entity | probe | scope | graph
        |                                     |
        +-----------> sonar-tools             +-----------> sonar-os
                                                     |
                                                sonar-report
```

## Workspace Boundaries

| Component | Responsibility |
| --- | --- |
| `crates/sonar-core` | Entities, probe contracts and registry, scope enforcement, command construction, output interpretation, workflows, remote-vantage plans, and pivot graphs. |
| `crates/sonar-os` | Cross-platform network inventory behind the `OsNet` interface: interfaces, listeners, firewall state, and configured resolvers. |
| `crates/sonar-tools` | Optional-tool plugin contract and lifecycle policy. It owns detection, install/update strategy, target kinds, risk/scope, capabilities, interactions, and the managed Nuclei runtime adapter; scanner meaning and argv construction remain in core. |
| `crates/sonar-report` | JSON and Markdown rendering for completed runs and graphs. |
| `crates/sonar-cli` | Clap shell, output-mode selection, beginner guidance, and terminal rendering. |
| `app/src-tauri` | Tauri IPC adapter, live child-process lifecycle, terminal launching, and desktop-specific network summary. |
| `app/src` | React workflow selection, target entry, result presentation, live output, and stop controls. |

Dependencies should point inward toward `sonar-core`. A shell may own transport
or presentation behavior, but it must not create a second probe policy or parser.

## Core Domain

### Targets and entities

The shells submit a `ProbeTarget`:

- `Input(String)` for a user-supplied IP, host, domain, URL, or host/port;
- `LocalMachine` for host-local inspection;
- `CurrentInternetPath` for egress and resolver-path checks.

`AppCore::resolve_probe_target` converts that value into a normalized `Entity`.
Stable entity IDs are used by the graph layer to deduplicate nodes.

### Probe contract and registry

Every probe implements `Probe`:

1. `descriptor()` declares identity, status, category, risk, and requirements.
2. `applies_to()` limits supported entity kinds.
3. `run()` produces a `ProbeOutput`.

`ProbeRegistry::run` is the execution gate. It rejects unknown probes,
incompatible entities, and probes that are not `Ready`; applies scope policy
from the descriptor's risk; executes the probe; and builds a per-run
`PivotGraph` from the output.

The default registry currently includes connectivity, local-network, DNS,
public-egress, RDAP, HTTP, and TLS checks. `public.port_check` is deliberately
registered as `Planned`: public ingress testing belongs to an explicitly scoped
remote-scan provider, not an ordinary local or Globalping-style measurement.

### Output and interpretation

`ProbeOutput` is the canonical result envelope. It carries:

- a compact summary and structured `summary_rows`;
- findings and warnings;
- discovered entities and edge drafts;
- artifacts and optional raw output.

`AppCore::interpret_result` derives the user-facing verdict and next actions
from the descriptor and output. Shells render this interpretation; they should
not independently redefine whether a result is healthy, warning, or failed.

### Scope policy

`ScopeGuard` evaluates an entity and `ActionClass` against `ScopePolicy`.
Passive lookups may be allowed by default, while active probes and external
command overrides require the corresponding scope permission. Both structured
runs and command-preview/live paths pass through core scope checks.

## Execution Paths

### Structured run

```text
App.runSelectedProbe
  -> invoke("run_probe")
  -> Tauri run_probe
  -> AppCore::run_probe_target
  -> resolve target
  -> ProbeRegistry::run
       validate applicability/status/scope
       execute Probe::run
       apply output to PivotGraph
  -> AppCore::interpret_result
  -> ProbeRunView { descriptor, output, graph, interpretation }
  -> React renders verdict, summary rows, warnings, and next actions
```

This is the authoritative path for persisted or reportable probe results.

### Live command run

```text
App.runLiveProbe
  -> invoke("run_probe_live", runId, probeId, target, commandOverride)
  -> AppCore::command_invocation_for_target
       resolve target + enforce probe scope
  -> optional override requires ActionClass::ExternalTool
  -> spawn_blocking(run_live_command)
       spawn child with piped stdout/stderr
       register Child by runId
       emit "probe-live-output" events
       collect lines and exit code
       remove Child from registry
  -> ProbeLiveSummary
```

`LiveProcesses` is Tauri-managed state containing synchronized child handles.
`cancel_probe_live` looks up the current `runId` and kills the child if it is
still running. Cancellation preserves already streamed output. The live path is
for interactive visibility; it does not manufacture a structured
`ProbeOutput`, interpretation, or graph.

### Command preview and terminal handoff

`probe_command` returns a platform-specific `CommandPreview` derived from the
same core invocation used by live execution. `open_probe_terminal` delegates to
the operating system terminal. User-edited command lines are treated as
external-tool actions and therefore receive a stricter scope check.

## Tauri Boundary

`app/src-tauri/src/lib.rs::run` owns the desktop process. It registers
`LiveProcesses` and exposes these command groups:

- metadata and discovery: `app_info`, `parse_entity`, `all_probes`,
  `available_probes`, `available_probes_for_target`, `workflows`;
- tool and remote planning: `tools_catalog`, `tool_update_plan`,
  `remote_vantage_plan`;
- execution: `run_probe`, `probe_command`, `open_probe_terminal`,
  `run_probe_live`, `cancel_probe_live`;
- desktop snapshot: `network_summary`.

Tauri DTOs are serialization adapters around core types. Desktop-only process
management stays here; probe meaning stays in `sonar-core`.

## Frontend Boundary

`app/src/App.tsx` orchestrates workflow selection and IPC. It may provide
fallback catalog data when no Tauri runtime is present, format localized copy,
and derive presentation-only readiness cards. It must use backend descriptors,
scope decisions, interpretations, and command previews whenever Tauri is
available.

The frontend listens for `probe-live-output` and filters events by `run_id` so
concurrent or stale events cannot be attached to the active display.

## Remote Vantage and Managed Tools

Remote-vantage support currently produces a plan, not an implicit remote
execution. `AppCore::remote_vantage_plan` maps provider/measurement combinations
to allowed probe IDs and warnings. Token handoff, locations, and explicit scope
remain prerequisites for a future remote executor.

Managed tools are optional plugins and are never bundled with the application.
The backend catalog is the single policy source; the frontend does not maintain
a second Nmap/Nuclei catalog. Nmap uses an official system-installer handoff and
is detected from supported system locations/PATH. Nuclei can be installed or
updated explicitly into per-user application data. Opening a page or refreshing
runtime status never installs or updates a tool.

Nmap and Nuclei have separate contracts. Nmap exposes bounded network/service
discovery; Nuclei exposes bounded URL template scanning with intrusive scope and
OAST disabled by default. Both expose Preview, Run in app, and Open in CLI from
the same core-owned argv invocation and cannot bypass scope enforcement.

## Extension Rules

When adding a probe:

1. Add or reuse normalized entity and target handling.
2. Implement `Probe`, including accurate status, risk, and requirements.
3. Register it in `register_default_probes`.
4. Keep OS command construction and raw-output summarization in shared Rust.
5. Add workflow/interpretation rules in `sonar-core` when they affect meaning.
6. Expose only transport and presentation changes in CLI/Tauri/React.
7. Test applicability, scope rejection, structured output, and platform command generation.

## Verification

- Rust workspace: `cargo test --workspace`
- Frontend unit tests: `pnpm test` from `app/`
- Frontend production build: `pnpm build` from `app/`

Architecture documentation is descriptive, not aspirational: update this file
when a boundary or execution path changes in code.
