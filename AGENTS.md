# SonarNwork Agent Notes

## Code Discovery

- Prefer `codebase-memory-mcp` for code discovery in this repository.
- If the `SonarNwork` project is missing or stale in the graph, run `index_repository` on `E:\Network` before broad code exploration.
- Use `search_graph`, `search_code`, `trace_path`, and `get_code_snippet` before falling back to `rg` or full-file reads.
- Use `rg`/file reads mainly for docs, config, CSS-wide scans, generated artifacts, or when graph results are incomplete.

## Useful Graph Targets

- Frontend app: `SonarNwork.app.src.App.App`
- Live command flow: `runLiveProbe`, `stopLiveProbe`, `run_probe_live`, `cancel_probe_live`
- Core probe flow: `AppCore.run_probe_target`, `interpret_result`, `command_invocation_for_target`
- Probe registry and commands: `register_default_probes`, `command_invocation_for_kind`

## Verification

- Frontend: run `pnpm build` from `app/`.
- Rust/workspace: run `cargo test --workspace` from the repo root.
