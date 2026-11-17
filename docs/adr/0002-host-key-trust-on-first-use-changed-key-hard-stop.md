# Host keys and certificates: trust on first use, a changed key is a hard stop

The tool sends passwords over SSH and over HTTPS Basic auth, so whoever can pose as a device can collect them. It trusts an SSH host key, or a PAN-OS certificate fingerprint when the certificate does not chain to a trusted CA, the first time it sees one, and records it in a per-user Trust Store (`%LOCALAPPDATA%\NetworkAnalyser\trust\`) kept between Runs. A key or fingerprint that later differs is never logged into and never accepted automatically or mid-Run. The operator accepts it afterwards with `trust-key` / `trust-cert`, typing the new fingerprint they checked on the device console. For a known IP the tool asks only for the key type already stored, so offering a different type cannot get around the check. Strict mode (`--strict-host-keys`) refuses anything not already trusted.

Decided on [Connection safety policy](https://github.com/b-git-hub/network-analyser/issues/7).

## Consequences

- The first Run against any IP is unprotected. Keys trusted for the first time are listed in the run report so the operator can check them.
- Hardware swaps, regenerated keys and moved IPs all stop that device until the operator acts.
- Netmiko's default `ssh_strict=False` and the PAN-OS libraries' default of no certificate checks are overridden. Certificate checks are never switched off.

## Considered Options

- **Strict known_hosts only:** the safest option, but the first Run reaches nothing unless the operator pre-loads keys. Kept as an opt-in mode.
- **Record and report only:** accepts any key and protects nothing.
- **Prompt mid-Run on a changed key:** Runs are parallel and may be left alone, and a hurried "yes" defeats the check.
