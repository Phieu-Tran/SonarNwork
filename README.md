# SonarNwork

SonarNwork is a network and security toolkit with one shared Rust core, exposed
through both a CLI and a Tauri desktop app.

The workspace is organized as follows:

- `crates/sonar-core`: entity model, probe contracts, pivot graph, and scope guard.
- `crates/sonar-cli`: CLI shell that calls `sonar-core`.
- `app/src-tauri`: Tauri shell that calls `sonar-core`.
- `crates/sonar-os`: OS abstraction contracts.
- `crates/sonar-tools`: managed external tool contracts.
- `crates/sonar-report`: export helpers.

The implementation and tests are the source of truth. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for runtime boundaries and
[`docs/DECISIONS.md`](docs/DECISIONS.md) for durable design decisions.

## Core Rule

CLI and app must use the same `sonar-core` APIs and serialized DTOs. Product logic belongs in the core; shells only translate user interaction into core calls.

## Verification

```powershell
cargo test --workspace
cd app
pnpm test
pnpm build
```

## First Commands

```powershell
cargo check -p sonar-cli
cargo run -p sonar-cli -- info
cargo run -p sonar-cli -- guide
cargo run -p sonar-cli -- check example.com
cargo run -p sonar-cli -- ping 1.1.1.1 --count 4 --timeout 1000
cargo run -p sonar-cli -- trace 1.1.1.1 --tcp --port 443
cargo run -p sonar-cli -- probe run connectivity.fast_trace 127.0.0.1
cargo run -p sonar-cli -- probe run connectivity.path_mtu 127.0.0.1
cargo run -p sonar-cli -- dns example.com --record A
cargo run -p sonar-cli -- port 127.0.0.1 --port 443
cargo run -p sonar-cli -- myip
cargo run -p sonar-cli -- entity parse 1.1.1.1
cargo run -p sonar-cli -- probe list
```
