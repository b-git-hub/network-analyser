# A Run refreshes Cisco's signed Advisories before any secret is typed

_Superseded by [ADR 0007](0007-cisco-lookups-at-run-end-after-secrets-wiped.md) on 2026-11-20: Cisco is now asked once at the end of a Run, after device secrets are wiped, and nothing is stored._

Analysis needs Cisco's Advisories, and the operator wants every Run to check against current data by default. So a Run now reaches the internet, the first time the tool talks to anything other than in-Scope devices. To keep that contact narrow, a Run refreshes its Advisory Store from Cisco's public CSAF directory after the operator confirms and **before the first secret prompt**, and closes every outbound connection before any password or the Backup Passphrase is typed. The tool is never online while it holds a secret. It sends nothing about the operator's devices, only fixed requests for public files, and it keeps only files whose OpenPGP signature verifies against a Cisco PSIRT key built into the tool.

Decided on [When Analysis runs and how it reaches Cisco](https://github.com/b-git-hub/network-analyser/issues/79).

## Consequences

- **One egress module.** `advisories` is the only module that opens an outbound HTTPS connection, imports the HTTP client or imports the OpenPGP library. It may not import `credentials`. `analysis` runs Checks on records and the loaded Advisory Store, and imports no network or device code. The import test enforces both.
- **Fence.** The tool connects only to a built-in host list (`www.cisco.com` today), only over HTTPS on port 443, and only to paths under `/.well-known/csaf/`. Certificates are checked against the Windows certificate store, and every redirect is refused. Proxies come from Windows' own setting or `--proxy`, never from environment variables, and proxies that need a sign-in are not supported.
- **Keys change only in a release.** Cisco rotates its signing key (the 2025–2026 key expires 2027-01-31). A new key is checked out of band and added in a `0.y.z` minor release, and is never fetched at run time. When no built-in key is valid, the refresh fails and says the tool needs updating.
- **A failed refresh never stops a Run.** The Run uses what the Advisory Store already holds, or skips the Advisory Check if the store is empty. The failure is listed under Needs-your-attention and the Run exits 1.
- **Opt-out.** `--advisories refresh|stored|off` (default `refresh`). `stored` makes no network connection.

## Considered Options

- **A separate `update-advisories` command, with `run` never going online:** the strongest isolation, but the operator wants current data on every Run without a second step.
- **Refreshing in the background during the crawl:** faster, but internet connections would be open while passwords are in memory.
- **Trusting HTTPS alone, or downloading Cisco's key at run time:** a TLS-inspecting proxy or a swapped key file could feed in altered Advisories and hide a Finding.
