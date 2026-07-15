# Changelog

All notable changes to SonarNwork are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `sonar update --check` and `sonar update` for checking and installing a newer
  SonarNwork release through the current install channel, including the `/update`
  TUI action.
- Linux x86_64 runtime support for system network probes and firewall status
  detection through UFW, firewalld, and nftables.
- Ubuntu 22.04 CI coverage and release artifacts for the desktop and CLI Debian
  packages.

### Changed

- Linux ping probes now honor the requested timeout.
- Release checksums cover both Windows and Linux artifacts.

## [0.1.2] - 2026-07-15

### Fixed

- Publish GitHub Releases from the tagged source revision.

## [0.1.1] - 2026-07-15

### Changed

- Use the repository signing key in the release workflow.

## [0.1.0] - 2026-07-15

### Added

- Initial SonarNwork desktop app and CLI release.
- Guided network-diagnostics workflows, scanner-shell support, and Nmap port
  workflow improvements.
- Windows CI, release packaging, and refreshed product branding.

[Unreleased]: https://github.com/Phieu-Tran/SonarNwork/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/Phieu-Tran/SonarNwork/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Phieu-Tran/SonarNwork/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Phieu-Tran/SonarNwork/releases/tag/v0.1.0
