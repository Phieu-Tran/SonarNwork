# Release v0.5.1

Status: local verification complete; tag not yet pushed.

## Scope

- Linux uses one Debian package containing the desktop app, `sonar`, and the
  `sonarnwork` compatibility alias.
- Windows releases include a checksum-verifying PowerShell bootstrap installer
  at `install.ps1`; it installs the portable bundle and adds the install folder
  to the user `PATH`.
- Scoop and WinGet manifests will be created from the published release's
  portable-bundle URL and SHA-256, never from an unverified local artifact.
- Since v0.1.3: mandatory scope check for external scanner invocations
  (`scanner_scope_gate`), a real JSONL parser for `httpx` scan output
  (structured status-code distribution + detected technologies instead of a
  raw line dump), and verified self-update channel detection/confirmation.

## Release procedure

1. Run the repository's non-packaging release checks locally.
2. Push tag `v0.5.1`; GitHub Actions builds, tests, packages, attests, and
   publishes the release.
3. Obtain the portable bundle's release checksum, then publish the Scoop
   manifest and submit the WinGet manifest for community review.

## Local verification

- `cargo test --workspace` - passed (205 tests, 4 intentionally ignored
  live-provider tests).
- `cargo clippy --workspace --all-targets -- -D warnings` - passed.
- `pnpm test` in `app/` - passed (30 tests).
- `pnpm build` in `app/` - passed.
- CLI release build (`cargo build -p sonar-cli --release`) exercised by hand:
  `--version`, `info`, `ping`, `check`, `probe run web.http_probe`, and a real
  `scanner run httpx scanme.nmap.org` (installed the real httpx binary via
  `tools install`) - parsed summary matched the live JSONL output.
- TUI: automated PTY harness (`scripts/tui-e2e/run.py`, pywinpty + pyte) - 3/3
  cases passed (boot to READY, `Ctrl+P` workflow palette, direct command
  execution). Additionally drove a live `scanner run httpx scanme.nmap.org`
  through the TUI command line and confirmed the parsed summary rendered
  correctly.
- Desktop app: built the real Tauri release bundle (`pnpm tauri build`) and
  drove it over CDP (`scripts/gui-e2e/run.mjs`) - 8/8 cases passed (failure
  verdict, explicit-target scope, Nmap detection, a real Nmap scan, probe
  selector cards, direction labels, operations dashboard, and history
  surviving an app restart). Additionally drove a live httpx scan from the
  Scanner tab in the real desktop app and confirmed the parsed summary
  rendered correctly there too.

No local production package was built. GitHub Actions is the source of truth for
the signed Windows assets, merged Linux `.deb`, provenance attestations, and the
published release.

## Published artifacts

Pending - will be filled in once the `v0.5.1` tag is pushed and the GitHub
Actions release run completes.

## Known limitations

- Scoop Extras requires a package-request issue before a manifest PR. The
  current GitHub token cannot create that upstream issue, so the repository
  publishes a custom SonarNwork bucket instead.
- WinGet publication requires review and merge by `microsoft/winget-pkgs`. Its
  manifest will need a version bump and re-validation before submission.
