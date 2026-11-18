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
- There is no CI in v1 (decisions #28, #32, #47). The release workflow and `build.ps1` run the same checks.

## 2. Layout and module boundaries ([ADR 0003](docs/adr/0003-modular-monolith-for-v1.md))

One package, `network_analyser/`, with the eleven modules from the spec plus two leaf modules:

| Module | May import (package modules) |
|---|---|
| `records`, `_winsys` (leaves) | nothing |
| `scope`, `credentials`, `trust_store`, `platforms`, `topology`, `diagram` | `records` |
| `backup_store` | `records`, `credentials` |
| `run_output` | `records`, `credentials`, `_winsys` |
| `device_gateway` | `records`, `scope`, `trust_store`, `credentials`, `platforms` |
| `discovery` | `records`, `scope`, `credentials`, `device_gateway`, `platforms`, `backup_store`, `topology` |
| `cli` (composition root) | everything |

[tests/arch/test_module_boundaries.py]. Libraries have one owner each:

- `netmiko`, `paramiko`, `socket`: only `device_gateway` [security test 3: tests/security/test_3_import_rule.py].
- `pyrage`: only `backup_store`. `textfsm`, `ntc_templates`: only `platforms`.
- `ctypes`, `msvcrt`, `winreg`: only `_winsys`. Every Windows-only call sits in `_winsys` behind a function that also runs (or says it can't) on Linux, so tests can inject a fake.
- `tomllib`: only `cli`. `logging`: only `cli/library_loggers.py`, which keeps the netmiko and paramiko loggers silent. Our own code never uses `logging`.
- Never: `getpass`, `pickle`, `shelve`, `marshal`, `subprocess`, `http`, `urllib`, `requests`, `ftplib`, `telnetlib`, `faulthandler.enable`, `paramiko.AutoAddPolicy`/`WarningPolicy` [ruff TID251 and the arch test].

Changing the import table or an owner is a design decision: say why in the commit message and update this table.

## 3. Data between modules

- Modules pass **plain-data records**: `@dataclass(frozen=True, slots=True)` in `records/` (or the owning module), holding only str, int, bool, None, tuples, frozensets, mappings, `ipaddress` objects, timezone-aware UTC datetimes, enums and other records. Never a `Secret`, callable, socket, file handle or live session.
- **The running config never rides in a record.** `device_gateway.visit()` takes a sink from `backup_store` and writes the raw config straight to it; nothing else ever sees it.
- *Unknown* is its own value (`Unknown(reason)`), never an empty list or None.
- IP addresses are `ipaddress` objects. Every in-Scope decision calls `scope`'s `contains(ip)`.

## 4. Secrets

- Every Credential Set password and the Backup Passphrase is a `credentials.Secret` from the moment it is typed. Its `str`, `repr` and format show `held in memory`; it cannot be pickled, copied, hashed, compared with `==` (use `same_as`), truth-tested (use `is_empty`) or measured [tests/unit/test_secret.py].
- **Who may hold the value** (decided 2026-11-18): Credential Set passwords only in `credentials` and `device_gateway`; the Backup Passphrase only in `backup_store`. `.reveal()` may be called only in those three modules, at the last moment, and its result is never stored [tests/arch/test_secret_rules.py]. The `cli` masked reader returns a `Secret` and never keeps the plain value.
- Secrets never come from options, environment variables or files. Only `_winsys` reads the environment, and only `LOCALAPPDATA`, `USERDOMAIN` and `COMPUTERNAME` by literal name [arch test, ruff TID251]. No option name may suggest a secret [tests/unit/test_cli.py].
- Usernames are not secret.

## 5. Output

- Only `cli` writes to the console [ruff T201]. Device text is escaped (control characters as `\xNN`) before it is printed.
- Files are written only by named writer helpers, which pass text through the secret scan and write temp-then-rename. A new writer adds its file to `WRITE_OWNERS` in tests/arch/test_secret_rules.py, with the reason in the commit. Never write plaintext config or device output.
- Keep console messages ASCII, so they show on any Windows console code page.

## 6. Errors and exit codes

- Exit codes live in `cli/exit_codes.py` (`ExitCode`): 0 clean, 1 needs attention, 2 refused before any device was contacted, 3 stopped or cancelled, 4 internal error. Every command returns one.
- Exception text can quote device output or a secret. A caught exception is re-raised, chained, type-checked or mapped to a fixed message; its text, `args` and `str()` are never shown, logged or stored [tests/arch/test_secret_rules.py]. The top-level handler shows only the type and a `file:line` stack, in every thread [tests/unit/test_crash_handling.py]. `faulthandler` stays off.
- Ctrl+C before any device is contacted exits 3 with no traceback.

## 7. Tests

- Build with red-green TDD. Test behaviour through a module's public interface with plain data; no tests of private helpers.
- Layout: `tests/security/` holds only the six v1 security tests (spec #37), named `test_<n>_*.py` and marked `security`. `tests/arch/` holds static architecture rules. `tests/unit/` holds everything else.
- A static rule is also tested against a planted violation, so a rule that stops matching fails.
- Fixtures are synthetic: IPv4 only from RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), plus, only to prove a refusal, the blocks the Scope never touches (`records.NEVER_TARGETS`: 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4), hostnames like `sw-a`, secrets like `CANARY-pw-…`. The lab file's secrets are `CHANGE_ME` [tests/arch/test_fixture_hygiene.py]. Never commit captured device output, configs, `*.age`, `known_hosts` or Run folders.
- Tests never touch the network; a fixture in `tests/conftest.py` refuses every connection. Fake devices at the `device_gateway` seam.
- Anything that needs Windows is behind a `_winsys` function with an injected fake in tests, and is checked by hand on Windows (lab checklist).

## 8. Read-only and allow-list

- Commands reach a device only through `device_gateway`'s single allow-list gate. The allow-list is literals in each `platforms` module, never read from a file or the environment.
- Adding a command to the allow-list is a breaking change (decision #32): bump the minor version, add a CHANGELOG line telling the operator to re-apply the Device Role, and keep security test 2 passing.

## 9. Commits

One ticket per branch (`ticket/<n>-<slug>`). Commit messages say "Part of #<n>" and end with the attribution lines the session gives.
