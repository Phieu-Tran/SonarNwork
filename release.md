# Release v0.1.3

Status: locally verified; GitHub release pending.

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

## Known limitations

- WinGet publication requires review and merge by `microsoft/winget-pkgs`.
- Scoop can be published immediately through the SonarNwork bucket once its
  versioned manifest is committed.
