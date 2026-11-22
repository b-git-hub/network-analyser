# Coding standards

Rules for every change to Network Analyser. Each rule is short and checkable; most are enforced by a test or a linter, named in brackets. Written 2026-11-18 for [spec #37](https://github.com/b-git-hub/network-analyser/issues/37), ticket [#38](https://github.com/b-git-hub/network-analyser/issues/38).

**Precedence:** the security rules in [CLAUDE.md](CLAUDE.md) > your ticket > spec #37 > this file > habit. Use the words in [GLOSSARY.md](GLOSSARY.md) in code, messages and tests, and flag any conflict.

## 1. Tooling

Run every check before you commit. All must pass:

```
uv sync --locked --no-build
uv run --locked python scripts/check.py
```

`scripts/check.py` runs `ruff format --check`, `ruff check` (rule set `ALL`), `mypy --strict` for this platform and again with `--platform win32`, and the whole pytest suite. Run the tool itself with `uv run --locked python -m network_analyser --help`. The six security tests alone: `uv run --locked pytest -m security`.

- Python is python.org CPython 3.14, exact patch in `.python-version`. uv never downloads or uses its own Python (`[tool.uv]` in `pyproject.toml`). Dependencies are hash-locked in `uv.lock`; a version bump is its own deliberate commit.
- The project is not a built package (`package = false`): there is no console script. The version lives in `network_analyser/_version.py` and must equal `pyproject.toml`'s `version` [tests/arch/test_project.py].
- No `# noqa` or `# type: ignore` without a code and a reason on the same line.
- There is no CI in v1 (decisions #28, #32, #47). The release workflow (`.github/workflows/release.yml`, tag-only) runs `build.ps1` itself, so both run the same checks. How to release: [docs/releasing.md](docs/releasing.md).
- `CHANGELOG.md` entries follow the template in [docs/releasing.md](docs/releasing.md): `### Breaking changes`, then `### Allow-list and Device Role`, `None.` when empty [tests/unit/test_release_gate.py].
- `build.ps1` (ticket #44) builds the Windows zip on Windows PowerShell 5.1: plain ASCII, no `&&` or `||` [tests/arch/test_build_script.py]; lint it with PSScriptAnalyzer's `PSUseCompatibleSyntax` for 5.1 after any change. Its logic lives in testable Python under `scripts/` (run as `python -m scripts.<name>`): the licence check and notices, the version resource, and the zip with its sums. A new runtime dependency must pass the licence check [tests/unit/test_third_party_notices.py]; a package whose wheel ships no licence text needs its text in `scripts/licence_texts/<name>-<version>.txt`, copied from its own hash-checked source release.

## 2. Layout and module boundaries ([ADR 0003](docs/adr/0003-modular-monolith-for-v1.md))

One package, `network_analyser/`, with the eleven modules from the spec plus two leaf modules, and from 0.2.0 the `advisories` module:

| Module | May import (package modules) |
|---|---|
| `records`, `_winsys` (leaves) | nothing |
| `scope`, `credentials`, `platforms`, `topology`, `analysis`, `diagram` | `records` |
| `trust_store` | `records`, `_winsys` |
| `backup_store` | `records`, `credentials`, `_winsys` |
| `run_output` | `records`, `credentials`, `_winsys` |
| `device_gateway` | `records`, `scope`, `trust_store`, `credentials`, `platforms` |
| `discovery` | `records`, `scope`, `credentials`, `device_gateway`, `platforms`, `backup_store`, `topology` |
| `advisories` (0.2.0, #95) | `records`, `credentials`, `_winsys` |
| `cli` (composition root) | everything |

[tests/arch/test_module_boundaries.py]. Libraries have one owner each:

- `netmiko`, `paramiko`: only `device_gateway`, and inside it only `device_gateway/ssh.py` [security test 3: tests/security/test_3_import_rule.py; tests/arch/test_module_boundaries.py]. `socket`: only `device_gateway`, in `ssh.py` (a full session) and `probe.py` (the Sweep's TCP 22 banner read, which closes before key exchange, #55), and `advisories/transport.py`. The rest of the gateway works on the plain `link.Dial` seam, which tests fake (tests/support/fake_device.py).
- `http.client`, `ssl`, `truststore`: only `advisories/transport.py` (and `truststore` nowhere else): the one outbound HTTPS path, fenced to Cisco ([ADR 0007](docs/adr/0007-cisco-lookups-at-run-end-after-secrets-wiped.md), [ADR 0009](docs/adr/0009-http-client-http-client-with-truststore.md)). Everything above it works on the plain `Transport` seam, which tests fake at `tests/support/fake_cisco.py`.
- `pyrage`: only `backup_store`. `textfsm`, `ntc_templates`: only `platforms`.
- `ctypes`, `msvcrt`, `winreg`: only `_winsys`. Every Windows-only call sits in `_winsys` behind a function that also runs (or says it can't) on Linux, so tests can inject a fake. Branch on the platform at module level (`if sys.platform == "win32": def f(): ... else: def f(): ...`), as `_winsys/elevation.py` does; a `sys.platform` check inside a function body trips mypy's `warn_unreachable` under `--platform win32`.
- `tomllib`: only `cli`. `logging`: only `cli/library_loggers.py`, which keeps the netmiko and paramiko loggers silent. Our own code never uses `logging`.
- Never: `getpass`, `pickle`, `shelve`, `marshal`, `subprocess`, `urllib`, `requests`, `http.client` (except `advisories/transport.py`), `ftplib`, `telnetlib`, `faulthandler.enable`, `paramiko.AutoAddPolicy`/`WarningPolicy` [ruff TID251 and the arch test].

Changing the import table or an owner is a design decision: say why in the commit message and update this table.

## 3. Data between modules

- Modules pass **plain-data records**: `@dataclass(frozen=True, slots=True)` in `records/` (or the owning module), holding only str, int, float, bool, None, tuples, frozensets, read-only mappings, `ipaddress` objects, timezone-aware UTC datetimes, enums and other records. Never a `Secret`, callable, socket, file handle, list, dict or live session [tests/arch/test_plain_records.py, for `records/`].
- **The running config never rides in a record.** `device_gateway.visit()` takes a sink from `backup_store` and writes the raw config straight to it; nothing else ever sees it.
- *Unknown* is its own value (`Unknown(reason)`), never an empty list or None.
- IP addresses are `ipaddress` objects. Every in-Scope decision calls `scope`'s `contains(ip)`.

## 4. Secrets

- Every Credential Set password and the Backup Passphrase is a `credentials.Secret` from the moment it is typed. Its `str`, `repr` and format show `held in memory`; it cannot be pickled, copied, hashed, compared with `==` (use `same_as`), truth-tested (use `is_empty`) or measured [tests/unit/test_secret.py].
- **Who may hold the value** (decided 2026-11-18): Credential Set passwords only in `credentials` and `device_gateway`; the Backup Passphrase only in `backup_store`. The Cisco API Key's client ID and secret, and the token from `id.cisco.com`, are `Secret`s too: `advisories` reveals them only to make Cisco's request, and `backup_store` unlocks the key file (ADR 0008; #95). `.reveal()` may be called only in those four modules, at the last moment, and its result is never stored [tests/arch/test_secret_rules.py]. `device_gateway` gets a set's password, still a `Secret`, only through `CredentialSets.password_for_login`, which nothing outside `credentials` and `device_gateway` may call [tests/arch/test_read_only.py] (#49). The `cli` masked reader returns a `Secret` and never keeps the plain value.
- Secrets never come from options, environment variables or files. Only `_winsys` reads the environment, and only `LOCALAPPDATA`, `USERDOMAIN` and `COMPUTERNAME` by literal name [arch test, ruff TID251]. The one file that reads them gets `"network_analyser/_winsys/<file>.py" = ["TID251"]` in `[tool.ruff.lint.per-file-ignores]`; no other file may. No option name may suggest a secret [tests/unit/test_cli.py].
- Usernames are not secret.

## 5. Output

- Only `cli` writes to the console [ruff T201]. Device text is escaped (control characters as `\xNN`) before it is printed.
- Everything `run` prints passes through the secret scan: `cli.console.scanned_console` puts a scanning stream in front of standard output and standard error, and each secret joins the `credentials.SecretScan` the moment it is typed (#48). The scan keeps only a keyed fingerprint and the length of each value, never the value itself, so the wipe before the Cisco step leaves nothing recoverable in it (#145). A match shows as `[blocked]`, with one warning and a hit count at the end, never naming the set. Text that must not be written with a part blocked (a path the tool needs again) is refused instead, through `SecretScan.holds_secret` [tests/security/test_5_canary.py].
- `audit.log` takes only the events in `records/events.py`, each with its fixed field list in `run_output.AUDIT_SCHEMA`; the writer refuses anything else, and any value that is not plain data. A ticket that emits a new kind of event adds both. No event carries device output: a parser problem is the command, the parser and a fixed reason; a caught exception is `records.events.error_event` (its type and a fixed message, never its text) [tests/unit/test_audit_log.py].
- Files are written only by named writer helpers, which pass text through the secret scan and write temp-then-rename. The rename goes through `_winsys.retry_rename`, which retries only a Windows `PermissionError` a bounded number of times and then raises, so another process holding the new file for a moment does not end a Run (#158). A plaintext file in the Run folder (`topology.json`, the diagrams, the Run report) is written with `run_output.write_scanned_text` or `write_scanned_json` (#52); scan each value before HTML, XML or JSON escaping, which could hide a secret from a scan of the finished text. A new writer adds its file to `WRITE_OWNERS` in tests/arch/test_secret_rules.py, with the reason in the commit. Never write plaintext config or device output.
- The tool never deletes a Run folder or a Backup (story 104). Removing a file or folder is allowed only in the files listed in `DELETE_OWNERS`, each for a named file of the tool's own [tests/arch/test_no_deletes.py].
- Paths under the Run folder go to file calls in their `_winsys.os_path` form (`\\?\` on Windows), so paths over 260 characters work (#42). Show and register the plain path.
- Names put on disk from operator or device text pass `records.safe_names` (letters, digits, `-`, `.`, `_`; no trailing `.`).
- Keep console messages ASCII, so they show on any Windows console code page.

## 6. Errors and exit codes

- Exit codes live in `cli/exit_codes.py` (`ExitCode`): 0 clean, 1 needs attention, 2 refused before any device was contacted, 3 stopped or cancelled, 4 internal error. Every command returns one.
- Exception text can quote device output or a secret. A caught exception is re-raised, chained, type-checked or mapped to a fixed message; its text, `args` and `str()` are never shown, logged or stored [tests/arch/test_secret_rules.py]. A mapper is registered in `EXCEPTION_SAFE_CALLS` by its full name (module path and function), so a function elsewhere that shares its name is not trusted. The top-level handler shows only the type and a `file:line` stack, in every thread [tests/unit/test_crash_handling.py]. `faulthandler` stays off.
- Ctrl+C before any device is contacted exits 3 with no traceback.

## 7. Tests

- Build with red-green TDD. Test behaviour through a module's public interface with plain data; no tests of private helpers.
- Layout: `tests/security/` holds only the six v1 security tests (spec #37), named `test_<n>_*.py` and marked `security`. `tests/arch/` holds static architecture rules. `tests/unit/` holds everything else.
- A static rule is also tested against a planted violation, so a rule that stops matching fails.
- Fixtures are synthetic: IPv4 only from RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), plus, only to prove a refusal, the blocks the Scope never touches (`records.NEVER_TARGETS`: 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4), hostnames like `sw-a`, secrets like `CANARY-pw-…`. The lab file's secrets are `CHANGE_ME` [tests/arch/test_fixture_hygiene.py]. Never commit captured device output, configs, `*.age`, `known_hosts` or Run folders.
- Tests never touch the network; a fixture in `tests/conftest.py` refuses every connection. Fake devices at the `device_gateway` seam, and a fake Cisco at the `advisories` transport seam (`tests/support/fake_cisco.py`).
- Anything that needs Windows is behind a `_winsys` function with an injected fake in tests, and is checked by hand on Windows (lab checklist).

## 8. Read-only and allow-list

- Commands reach a device only through `device_gateway`'s single allow-list gate, `DeviceSession.send(platform, command)` [security test 1]; the Netmiko connection refuses any write that is not a bare RETURN or a permitted line, so the library's own session set-up passes the same gate. The allow-list is literals in each `platforms/<platform>/commands.py`, never read from a file or the environment: exact strings, or templates whose parameters match a strict pattern that never matches a space.
- No Netmiko call that enters configuration or enable mode, saves or commits, no `ConnectHandler`/`SSHClient`/`AutoAddPolicy`, and no session log other than None [tests/arch/test_read_only.py].
- Adding a command to the allow-list is a breaking change (decision #32): bump the minor version, list the command under `### Breaking changes` and `### Allow-list and Device Role` in CHANGELOG.md (the release notes then remind the operator to re-apply the Device Role), keep security test 2 passing, and regenerate the lab's Device Role with `uv run --locked python -m scripts.lab_roles` [tests/unit/test_lab_role.py]. `role-snippet` builds the role from the allow-list itself (`platforms/*/role.py`); a template whose parameter is not the account's username has no role form yet, so the ticket adding one extends `platforms/roles.py` rather than widening the role.

## 9. Commits

One ticket per branch (`ticket/<n>-<slug>`). Commit messages say "Part of #<n>" and end with the attribution lines the session gives.
