# Backend
- `sonar-core`: entities, probes, scope, graph, workflows, interpretation, remote plans.
- `sonar-os`: OS network inventory behind `OsNet`.
- `sonar-tools`: managed-tool policy/catalog, not probe execution.
- `sonar-report`: JSON/Markdown renderers.
- `sonar-cli`: Clap shell.
- `app/src-tauri`: IPC and child-process lifecycle only; delegate probe meaning/safety to core.
- `ProbeRegistry::run` validates existence, applicability, readiness and scope, executes, then builds a per-run graph.