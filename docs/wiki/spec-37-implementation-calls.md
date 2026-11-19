# Calls made while implementing spec #37

Decisions the coordinating session made on 2026-11-18 while the operator was AFK (see [operator-wants-cml-build](operator-wants-cml-build.md)), resolving gaps the [exploration notes](spec-37-notes/guardrails.md) found. Each is reversible and was raised on [spec #37](https://github.com/b-git-hub/network-analyser/issues/37) as the spec asks.

1. **No CI workflow.** Closed decisions #28 and #32 defer CI, and #47 allows no workflow on pushes or PRs. This supersedes the 2026-11-18 plan in [operator-wants-cml-build](operator-wants-cml-build.md) to build on every push. The operator gets the build by running `build.ps1` (#44) on their own PC, which is how #44 designs it.
2. **uv packaging.** The commands #32/#44/#47 specify are kept. `[tool.uv] package = false`, run as `python -m network_analyser`, `__version__` in code, and an arch test that it equals pyproject's version.
3. **Who may hold a secret.** Credential Set passwords live only in `credentials` and `device_gateway` (ADR 0003). The Backup Passphrase lives only in `backup_store` (#45, ADR 0004). The cli masked reader returns only a `Secret` object. An arch test enforces this.
4. **Running configs never ride in device records.** `visit()` takes a sink from `backup_store`; the config goes nowhere else (#51 wins over the spec's module table).
5. **Smaller defaults** for implementers to apply unless their ticket says otherwise: unknown run-file keys are rejected (fail closed). For prefixes /30 and shorter, `contains()` refuses the network and broadcast addresses; /31 and /32 allow every address. `show-backup` exits non-zero on a wrong passphrase. The `http://` ban allows only the exact SVG namespace string. The licence check carries explicit overrides for `scp` (LGPL) and `pyrage` (reported UNKNOWN).

6. **Sweep (#55), 2026-11-19.** Where the ticket left a choice, the conservative one was taken:
    - The probe sends no bytes. It reads the server identification string and closes before key exchange. A host that waits for a client string before sending its own is recorded as having no banner and is not logged into.
    - The 2 second budget covers the connect and the banner read together, not `--connect-timeout`.
    - Login from a Sweep uses the existing anchored patterns: `SSH-2.0-Cisco-*` for IOS/IOS-XE, and the provisional `SSH-2.0-OpenSSH_* FIPS` for NX-OS (lab checklist A2). `CISCO_WLC` is not a Seed.
    - The size check uses `ScopeRecord.address_count` (exclusions already removed; network and broadcast edges still counted). More than 65,536 is refused with exit 2 before any prompt continues. More than 4,096 warns, and exactly 4,096 or 65,536 does not refuse. Edges are not probed: `contains()` still skips them.
    - `--sweep-inflight` above 100 is refused by the parser. `sweep()` also clamps to 100, and treats a non-positive value as 1.
    - Operator Seeds are still logged into when their banner does not match (story 64). Only extra Seeds require a match. Other SSH hosts stay on the Sweep result and are never dialled for a password.
    - Each probe is an audit event `probe_attempted` (address, port, TCP result, whether a banner was read). The identification string is not in the audit log; it is kept, printable, on `CrawlResult.sweep` for the report.
    - No `--no-sweep` flag. A run file `sweep = true` cannot be turned off from the command line. That remains an operator decision (from #41).
    - The Sweep runs only after the operator confirms, inside the audit trail. It does not watch a stop token; that belongs to #56.
    - `socket` may be imported from `device_gateway/probe.py` as well as `ssh.py`, because the probe must not use Paramiko (Paramiko's handshake is the key exchange).
