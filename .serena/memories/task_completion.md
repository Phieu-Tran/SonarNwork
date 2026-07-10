# Task Completion
- Rust-impacting change: `cargo fmt --all`, `cargo test --workspace`; add `cargo clippy --workspace` when logic changes materially.
- Frontend-impacting change: `pnpm test` and `pnpm build` from `app/`.
- Cross-boundary change: run Rust workspace tests plus frontend tests/build.
- Update `docs/ARCHITECTURE.md` or `docs/DECISIONS.md` when a durable boundary/decision changes.