//! Integration tests for the `sonarnwork` CLI binary.
//!
//! Deterministic only — NO network commands (ping/http/dns/tls). Keeps the
//! suite stable and never touches public targets (repo rule: no public targets
//! in automated tests). Network-dependent CLI behavior stays in the manual
//! `CLI-*` cases in docs/test/TRANG-THAI-TEST.md.

use assert_cmd::Command;
use predicates::prelude::*;

fn cli() -> Command {
    Command::cargo_bin("sonarnwork").expect("binary `sonarnwork` builds")
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
        .stdout(predicate::str::contains("probe"));
}

#[test]
fn no_args_starts_interactive_shell() {
    cli().write_stdin("info\nexit\n").assert().success().stdout(
        predicate::str::contains("SonarNwork CLI Shell")
            .and(predicate::str::contains("sonarnwork >"))
            .and(predicate::str::contains("SonarNwork")),
    );
}

#[test]
fn unknown_command_fails() {
    cli().arg("definitely-not-a-command").assert().failure();
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
