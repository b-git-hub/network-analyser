# Changelog

Every release of Network Analyser, newest first. Versions are SemVer 0.y.z ([#32](https://github.com/b-git-hub/network-analyser/issues/32)): a breaking change bumps the minor, anything else bumps the patch. See [docs/releasing.md](docs/releasing.md) for what counts as breaking and how a release is made.

The release workflow publishes a version's entry as its release notes, so every entry follows this template, enforced by `tests/unit/test_release_gate.py` and by the release gate:

- `## [0.y.z] - YYYY-MM-DD` (or `## [Unreleased]` while it is being written).
- `### Breaking changes` first, then `### Allow-list and Device Role`. Write `None.` under either when there is nothing to say. A breaking change says what the operator must do after upgrading, including any migration step.
- Then any of `### Added`, `### Changed`, `### Fixed`, `### Security`.

The workflow adds the system requirements, the unsigned-build warning, the download check, the sizes and the install steps itself.

## [Unreleased]

### Breaking changes

None. This is the first release.

### Allow-list and Device Role

The first allow-list ([spec #37](https://github.com/b-git-hub/network-analyser/issues/37)). Give the tool's account a Device Role that permits these commands; `network-analyser role-snippet ios-xe|nx-os` prints it (#53):

- IOS/IOS-XE: `terminal length 0`, `terminal width 511`, `show version`, `show privilege` (#49); `show running-config view full`, the Backup, always the full view and never plain `show running-config` (#51); `show cdp neighbors detail`, `show lldp neighbors detail` (#50).
- NX-OS: `terminal length 0`, `terminal width 511`, `show version`, `show user-account <username>` (the account's own name; #49); `show running-config`, the Backup (#51); `show cdp neighbors detail | json`, `show lldp neighbors detail | json` (#50).

### Added

- Network Analyser v1 ([spec #37](https://github.com/b-git-hub/network-analyser/issues/37)): read-only discovery of Cisco IOS/IOS-XE and NX-OS devices over SSH, encrypted Backups of their running configuration, and a Topology diagram.
