# SonarNwork Core
- Rust workspace with shared product semantics in `sonar-core`; CLI and Tauri/React are shells.
- Architecture and durable decisions: `docs/ARCHITECTURE.md`, `docs/DECISIONS.md`.
- Probe execution must pass through registry applicability/readiness/scope checks.
- Structured and live command runs are deliberately separate paths.
- Backend details: `mem:backend/core`; frontend flow: `mem:frontend/core`.
- Toolchain and commands: `mem:tech_stack`, `mem:suggested_commands`, `mem:task_completion`.
- Coding conventions: `mem:conventions`.