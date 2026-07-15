# Release v0.1.3

Status: published on GitHub; package-manager publication in progress.

## Scope

- Linux uses one Debian package containing the desktop app, `sonar`, and the
  `sonarnwork` compatibility alias.
- Windows releases include a checksum-verifying PowerShell bootstrap installer
  at `install.ps1`; it installs the portable bundle and adds the install folder
  to the user `PATH`.
- Scoop and WinGet manifests will be created from the published release's
  portable-bundle URL and SHA-256, never from an unverified local artifact.

## Release procedure

1. Run the repository's non-packaging release checks locally.
2. Push tag `v0.1.3`; GitHub Actions builds, tests, packages, attests, and
   publishes the release.
3. Obtain the portable bundle's release checksum, then publish the Scoop
   manifest and submit the WinGet manifest for community review.

## Local verification

- `cargo test --workspace` - passed (144 tests, 2 intentionally ignored
  live-provider tests).
- `cargo clippy --workspace --all-targets -- -D warnings` - passed.
- `pnpm test` in `app/` - passed (30 tests).
- `pnpm build` in `app/` - passed.

No local production package was built. GitHub Actions is the source of truth for
the signed Windows assets, merged Linux `.deb`, provenance attestations, and the
published release.

## Published artifacts

- Release: https://github.com/Phieu-Tran/SonarNwork/releases/tag/v0.1.3
- Windows portable bundle:
  `SonarNwork-v0.1.3-windows-x64-portable.zip`
  - SHA-256: `95c82619c2aa525a78654d2ba8376d97792e688fd2f079d676e6a18a27bb7888`
- Linux combined package: `SonarNwork-0.1.3-linux-x64.deb`
  - SHA-256: `d4a83be0f863b61bf722811be7691d44452fce22998f47a79562d90adf8c9b66`
- Windows bootstrap installer: `install.ps1`.

The GitHub Actions run completed successfully for Linux, Windows, and release
publication: https://github.com/Phieu-Tran/SonarNwork/actions/runs/29425025484

## Known limitations

- Scoop Extras requires a package-request issue before a manifest PR. The
  current GitHub token cannot create that upstream issue, so the repository
  publishes a custom SonarNwork bucket instead.
- WinGet publication requires review and merge by `microsoft/winget-pkgs`. Its
  v0.1.3 manifest validates locally, but the current GitHub token cannot create
  the required upstream PR workflow.
