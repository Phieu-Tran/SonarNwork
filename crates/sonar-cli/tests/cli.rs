//! Integration tests for the `sonarnwork` CLI binary.
//!
//! Deterministic only — NO real network commands (ping/http/dns/tls). Keeps the
//! suite stable, never touches public targets, and covers stable public CLI
//! behavior without depending on local manual test workflows.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static FAKE_TOOL_ID: AtomicU64 = AtomicU64::new(0);

fn cli() -> Command {
    Command::cargo_bin("sonarnwork").expect("binary `sonarnwork` builds")
}

fn short_cli() -> Command {
    Command::cargo_bin("sonar").expect("binary `sonar` builds")
}

fn cli_with_unhealthy_ping() -> (Command, PathBuf) {
    let id = FAKE_TOOL_ID.fetch_add(1, Ordering::Relaxed);
    let directory =
        std::env::temp_dir().join(format!("sonarnwork-cli-test-{}-{id}", std::process::id()));
    fs::create_dir_all(&directory).expect("create fake tool directory");

    #[cfg(windows)]
    fs::write(
        directory.join("ping.cmd"),
        "@echo off\r\necho Packets: Sent = 1, Received = 0, Lost = 1 (100%% loss),\r\nexit /b 1\r\n",
    )
    .expect("write fake ping command");

    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;

        let path = directory.join("ping");
        fs::write(
            &path,
            "#!/bin/sh\necho '1 packets transmitted, 0 received, 100% packet loss'\nexit 1\n",
        )
        .expect("write fake ping command");
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    let mut paths = vec![directory.clone()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let mut command = cli();
    command.env("PATH", std::env::join_paths(paths).unwrap());
    (command, directory)
}

fn assert_unhealthy_ping_mode(mode: &str) -> assert_cmd::assert::Assert {
    let (mut command, directory) = cli_with_unhealthy_ping();
    let assertion = command
        .args([
            "ping",
            "192.0.2.1",
            "--count",
            "1",
            "--timeout",
            "200",
            mode,
        ])
        .assert()
        .code(1);
    let _ = fs::remove_dir_all(directory);
    assertion
}

#[test]
fn info_prints_product_name() {
    cli()
        .arg("info")
        .assert()
        .success()
        .stdout(predicate::str::contains("SonarNwork"));
}

#[test]
fn forced_color_styles_human_output() {
    cli()
        .env("SONARNWORK_COLOR", "always")
        .env_remove("NO_COLOR")
        .arg("info")
        .assert()
        .success()
        .stdout(predicate::str::contains("\x1b[1;36mSonarNwork"));
}

#[test]
fn structured_output_never_contains_terminal_colors() {
    cli()
        .env("SONARNWORK_COLOR", "always")
        .env_remove("NO_COLOR")
        .args(["info", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\x1b[").not());
}

#[test]
fn entity_parse_ip() {
    cli()
        .args(["entity", "parse", "1.1.1.1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ip:1.1.1.1"));
}

/// Locks E10 at the CLI boundary: `domain:port` must normalize to a URL, not
/// double-append the port (previous bug produced `example.com:443:443`).
#[test]
fn entity_parse_domain_port_is_url() {
    cli()
        .args(["entity", "parse", "example.com:443"])
        .assert()
        .success()
        .stdout(predicate::str::contains("url:https://example.com"));
}

#[test]
fn probe_list_includes_core_probes() {
    cli().args(["probe", "list"]).assert().success().stdout(
        predicate::str::contains("connectivity.ping")
            .and(predicate::str::contains("public.port_check")),
    );
}

#[test]
fn help_lists_subcommands() {
    cli()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("probe"))
        .stdout(predicate::str::contains("open"));
}

#[test]
fn help_lists_self_update_command() {
    cli()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("update"));
}

#[test]
fn sonar_alias_uses_the_same_cli_entrypoint() {
    short_cli()
        .arg("info")
        .assert()
        .success()
        .stdout(predicate::str::contains("SonarNwork"));
}

#[test]
fn open_ui_launches_the_resolved_desktop_executable() {
    let desktop_stub = assert_cmd::cargo::cargo_bin("sonar");
    cli()
        .env("SONARNWORK_DESKTOP_PATH", desktop_stub)
        .args(["open", "ui"])
        .assert()
        .success()
        .stdout(predicate::str::contains("desktop opened"));
}

#[test]
fn no_args_starts_interactive_shell() {
    cli().write_stdin("info\nexit\n").assert().success().stdout(
        predicate::str::contains("SonarNwork CLI Shell")
            .and(predicate::str::contains("sonar >"))
            .and(predicate::str::contains("SonarNwork")),
    );
}

#[test]
fn unknown_command_fails() {
    cli().arg("definitely-not-a-command").assert().code(2);
}

#[test]
fn scanner_without_scope_confirmation_exits_four() {
    cli()
        .args(["scanner", "run", "nmap", "127.0.0.1"])
        .assert()
        .code(4);
}

#[test]
fn unhealthy_probe_summary_exits_one() {
    assert_unhealthy_ping_mode("--summary").stdout(predicate::str::contains("100%"));
}

#[test]
fn unhealthy_probe_json_exits_one() {
    assert_unhealthy_ping_mode("--json").stdout(predicate::str::contains("\"exit_code\": 1"));
}

#[test]
fn unhealthy_probe_raw_exits_one() {
    assert_unhealthy_ping_mode("--raw").stdout(predicate::str::contains("100%"));
}

/// Exercises the full structured-run → interpret → render path deterministically:
/// `core.describe_entity` normalizes an entity without touching the network.
#[test]
fn probe_run_describe_entity_renders_result() {
    cli()
        .args(["probe", "run", "core.describe_entity", "1.1.1.1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ip:1.1.1.1"));
}

/// Locks that the scanner CLI surface exists (the "focus on CLI" direction):
/// `sonarnwork scanner run <tool> <target>`.
#[test]
fn scanner_help_exposes_run() {
    cli()
        .args(["scanner", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("run"));
}

#[test]
fn tools_status_checks_version_without_running_a_scan() {
    cli()
        .args(["tools", "status", "nmap"])
        .assert()
        .success()
        .stdout(predicate::str::contains("installed").or(predicate::str::contains("unavailable")));
}

#[test]
fn tool_install_requires_explicit_confirmation() {
    cli()
        .args(["tools", "install", "nuclei"])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("confirm"));
}

#[test]
fn capture_requires_explicit_interface_authorization() {
    cli()
        .args([
            "capture",
            "run",
            "--interface",
            "1",
            "--duration",
            "1",
            "--packets",
            "1",
        ])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("authorized"));
}

#[test]
fn monitor_requires_explicit_target_authorization() {
    cli()
        .args(["monitor", "start", "example.com"])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("authorized"));
}

#[test]
fn history_list_is_available_without_the_desktop_runtime() {
    let data_dir =
        std::env::temp_dir().join(format!("sonarnwork-cli-history-{}", std::process::id()));
    cli()
        .env("SONARNWORK_DATA_DIR", data_dir)
        .args(["history", "list", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[]"));
}
