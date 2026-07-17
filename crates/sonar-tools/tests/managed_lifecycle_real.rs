//! Real managed-tool lifecycle over the network: download → install → detect →
//! remove, using the public [`ToolCatalog`] API exactly as the app/CLI do.
//!
//! These tests are `#[ignore]` by default because they hit the internet and write
//! a real executable into the per-user managed tools directory. Enable them on
//! Windows with a network connection:
//!
//! ```powershell
//! $env:SONARNWORK_RUN_REAL_TOOL_TESTS = "1"
//! cargo test -p sonar-tools --test managed_lifecycle_real -- --ignored --nocapture
//! ```
//!
//! The hermetic simulation of the same flow lives in `sonar-tools`'s unit tests
//! (`simulated_lifecycle_*`) and runs on every `cargo test`.

use sonar_tools::ToolCatalog;

/// Whether the operator explicitly opted in to the real, network-touching flow.
fn real_flow_enabled() -> bool {
    std::env::var("SONARNWORK_RUN_REAL_TOOL_TESTS").is_ok_and(|value| value == "1")
}

/// Run install → detect → remove against one real managed tool.
fn assert_real_lifecycle(tool_id: &str) {
    let catalog = ToolCatalog::phase_zero_defaults();

    let status = catalog
        .install_managed(tool_id)
        .unwrap_or_else(|err| panic!("real install of {tool_id} failed: {err}"));
    assert!(
        status.available,
        "{tool_id} must be detected after a real install: {:?}",
        status.error
    );
    assert!(
        status.executable.is_some(),
        "{tool_id} must resolve to an executable path after install"
    );

    let removed = catalog
        .uninstall_managed(tool_id)
        .unwrap_or_else(|err| panic!("real uninstall of {tool_id} failed: {err}"));
    assert!(
        removed,
        "{tool_id} managed copy must be removed by uninstall_managed"
    );
}

#[test]
#[ignore = "downloads a real binary over the network; enable with SONARNWORK_RUN_REAL_TOOL_TESTS=1 on Windows"]
fn real_managed_lifecycle_passive_tool() {
    if !cfg!(target_os = "windows") || !real_flow_enabled() {
        eprintln!(
            "skipping real managed-tool lifecycle: needs Windows and SONARNWORK_RUN_REAL_TOOL_TESTS=1"
        );
        return;
    }
    // dnsx is a small, passive ProjectDiscovery tool — the safest real download.
    assert_real_lifecycle("dnsx");
}

#[test]
#[ignore = "downloads real binaries for every managed tool; enable with SONARNWORK_RUN_REAL_TOOL_TESTS=1 on Windows"]
fn real_managed_lifecycle_all_download_tools() {
    if !cfg!(target_os = "windows") || !real_flow_enabled() {
        eprintln!(
            "skipping real managed-tool lifecycle (all tools): needs Windows and SONARNWORK_RUN_REAL_TOOL_TESTS=1"
        );
        return;
    }
    // Every auto/managed-download tool, exercised end to end. nmap (system
    // installer) and globalping (API-only) are intentionally excluded — they have
    // no managed binary to download.
    for tool in ["httpx", "dnsx", "subfinder", "naabu", "trippy", "nexttrace", "nuclei"] {
        assert_real_lifecycle(tool);
    }
}
