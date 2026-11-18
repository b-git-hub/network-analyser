> Exploration notes written 2026-11-18 at `b-git-hub/network-analyser@a069d68` by the spec #37 exploration agent. A snapshot, not maintained: tickets win over these notes. Later decisions: [spec-37-implementation-calls](../spec-37-implementation-calls.md).

# Guardrails for #38: make the secure path the only easy path

Legend: **[#38]** = #38's acceptance criteria already ask for it. **[extra]** = my recommendation, not in the ticket.
- #38 says "no tests beyond the six security tests are *required*". Extras are allowed, but keep them in `tests/arch/`, separate from `tests/security/` (the six that build.ps1 gates on).
- #38 is already in progress (`ticket/38-project-skeleton-cli`), so the extras can land as a follow-up commit or ticket.

## 1. Project and tooling
- **[#38]** Pin python.org CPython 3.14 in `.python-version` (`3.14.10` per #32). Set `requires-python = ">=3.14,<3.15"`. Hash-locked `uv.lock`.
- **[#38, must decide]** `uv sync --locked --no-build` **fails on a packaged project** (verified; environment.md §2). Recommended fix:
  - Set `[tool.uv] package = false`.
  - Use a flat `network_analyser/` package with `__main__.py`.
  - Put `__version__` in `network_analyser/_version.py`. #32's workflow checks `pyproject.toml`'s version against the tag, so add an arch test asserting `_version.__version__ == pyproject [project].version`. That keeps one truth, enforced. The other route is `--no-install-project` in both scripts.
  - **[extra]** `[tool.uv] no-build = true` so dev installs never build sdists either.
  - **[extra]** `required-version = ">=0.13"`: uv 0.11 can't fetch 3.14.10, and lock formats should match.
- **[extra] ruff** (lint + format), in `pyproject.toml`:
  - `select = ["E","F","W","I","B","UP","S","T20","TID","BLE","DTZ","PTH","ARG","RUF","PL","TRY"]`
  - `S` (bandit) catches `shell=True`, `yaml.load` and hard-coded passwords.
  - `T20` bans `print`, allowed only in `cli/console.py` via per-file-ignores.
  - `DTZ` forbids naive datetimes, which gives UTC everywhere (stories 156 and 161).
  - `BLE` stops bare `except Exception` swallowing.
  - `[tool.ruff.lint.flake8-tidy-imports.banned-api]` (TID251), with per-file-ignores only for the owning file:
    - `os.environ`, `os.getenv`, `os.putenv`: allowed only in `_winsys/paths.py` (`LOCALAPPDATA`, `USERDOMAIN`, `COMPUTERNAME`). This is the "secrets never from env" rule.
    - `getpass`: #29 chose our own reader.
    - `faulthandler`: stays off (#38, #6).
    - `logging.basicConfig`, `logging.FileHandler`, `logging.StreamHandler`, `logging.exception`, `traceback.print_exc`, `traceback.format_exc`, `traceback.format_exception`: these print exception text (#30 §12).
    - `pickle`, `marshal`, `shelve`, `telnetlib`, `ftplib`, `urllib.request`, `http.client`, `ssl._create_unverified_context`, `subprocess`: the last is allowed only in `_winsys` if ever needed.
    - `paramiko.AutoAddPolicy`, `paramiko.WarningPolicy`.
    - `tempfile.NamedTemporaryFile` (write helpers own temp files).
- **[extra] mypy `--strict`**, run twice: default platform, and `--platform win32` so the `msvcrt`/`winreg` branches are checked. Add `types-paramiko`, a local stub for pyrage, and `ignore_missing_imports` for `textfsm` and `ntc_templates` only.
- **[extra] pytest:** `--strict-markers`, `filterwarnings = ["error"]`, `testpaths = ["tests"]`, and an autouse `conftest.py` fixture that makes `socket.socket.connect` / `create_connection` raise. That proves no test reaches a network ("no device"). It needs no extra dependency.
- **[extra] One local check command**, `scripts/check.py` or a `[tool.uv]`-documented sequence: `ruff format --check`, `ruff check`, `mypy` ×2, `pytest`. build.ps1 (#44) and the merger brief call it.

## 2. Module boundaries (arch tests via AST scan; no imports executed)
- **[#38] Security test 3:** only `network_analyser/device_gateway/**` imports `netmiko` or `paramiko`. Catch `import x`, `from x import`, `importlib.import_module("x")` and `__import__`.
- **[extra]** Extend the same scanner, in `tests/arch/test_imports.py`, to the full internal DAG in architecture.md §2, plus third-party ownership:

| Import | Allowed only in |
|---|---|
| `netmiko`, `paramiko`, `socket` | `device_gateway` |
| `pyrage` | `backup_store` |
| `textfsm`, `ntc_templates` | `platforms` |
| `ctypes`, `msvcrt`, `winreg` | `_winsys` |
| `tomllib` | `cli` |
| `logging` | `cli/library_loggers.py` (the one place that caps netmiko/paramiko) |
| `http`, `urllib`, `requests`, `json` network APIs | nowhere |

- **[extra] Secret holders.** AST-scan for `.reveal(`. It may appear only in `device_gateway` (passwords) and `backup_store` (Backup Passphrase), plus `credentials` itself (`contains_secret`).
  - This encodes ADR 0003 "only credentials + device_gateway hold a password", and #45 for the passphrase.
  - The coordinator must confirm the passphrase exception (see the report).
- **[extra] Plain data.** Every class in `records/` is `@dataclass(frozen=True, slots=True)` whose field types are drawn from a permitted set: str, int, bool, float, None, tuple, frozenset, Mapping, IPv4Address/Network, datetime, Enum, other records, `Unknown`.
  - That excludes `Secret`, callables, sockets and file handles.
  - This stops a password or a live session crossing a boundary (ADR 0003 phase-2 readiness), and stops raw config sitting in `DeviceRecord` (#51).

## 3. Secrets
- **[extra, but needed by #45/#48] `credentials.Secret`:**
  - `__slots__`; `@final`; `__init_subclass__` raises.
  - `__repr__`, `__str__` and `__format__` return the fixed text `held in memory`.
  - `__reduce__` / `__getstate__` raise (no pickling or copying to disk).
  - No `__len__`: the report never shows length (#30 §3.8).
  - `__eq__` raises. Use `same_as(other)` instead, built on `hmac.compare_digest` (for "password == passphrase", story 27).
  - `__hash__ = None`.
  - `reveal() -> str` is the only way out.
  - Document that Python cannot zero strings; do not promise wiping.
- **[extra]** The masked reader (`cli/prompts.py`) builds a `Secret` from a local list, clears the list, and returns only the `Secret`. Its public type signature returns `Secret`, never `str`.
- **[#38]** `run --help` states that secrets are never options or env vars.
- **[extra]** An arch test walks the argparse parser and fails if any option dest or flag matches `pass|secret|key(?!s)|token`. `--known-hosts` is allowed explicitly.
- **[#48, lay the seam now] one output path:**
  - Console output goes through `cli/console.py` (`write_line(text)` → escape controls → `contains_secret` → stdout).
  - Files go through `run_output/writer.py` (`write_text_atomic(path, text)` → scan → temp → flush → `os.replace`).
  - **[extra]** An arch test bans `open(...,'w'|'a'|'x'…)`, `Path.write_text`, `Path.write_bytes` and `os.replace` outside the few owners: `run_output/writer.py`, `run_output/audit.py` (append), `backup_store/age_io.py` (ciphertext only), `trust_store.py`, `backup_store/register.py`, `run_output/lock.py`, `_winsys`. This is a cheap stand-in for the deferred `sys.addaudithook` file-write audit (#28).
- **[#38] Top-level handler:** type + `file:line` only, exit 4.
  - **[extra]** Also install it as `threading.excepthook` and `sys.unraisablehook`. Paramiko's transport thread would otherwise print traceback text.
  - **[extra]** Add a unit test that raises `RuntimeError("CANARY")` and asserts stderr lacks `CANARY`.
- **[extra] Exception text never echoed.** An AST test: in every `except … as e:` block, `e` may be used only in `raise … from e`, `type(e)`, `isinstance(e, …)`, or a `fixed_message(e)` lookup. Never in `str()`, f-strings, `.args`, `%`, `format` or `print`.
- **[extra] Library loggers** (#48 owns the behaviour; #38 can lay the function down): `netmiko` and `paramiko` loggers get `setLevel(WARNING)`, `propagate = False` and a single `NullHandler`. Without a handler, Python's `logging.lastResort` writes WARNING+ to stderr. Call it first thing in `main()`.

## 4. Read-only by construction (#49 builds it; #38 should reserve the shape)
- **[extra] Allow-list types:**
  - `platforms/allowlist.py` defines `Exact(str)` and `Template(fmt, {param: compiled regex with fullmatch})`.
  - Each Platform exposes `ALLOW_LIST: tuple[...]`, built at import from literals only.
  - No `open`, `importlib.resources`, env or file reading in `platforms/*/commands.py`. Enforce it with an AST test (story 56: the operator can't edit it).
- **[extra] One gate:** `device_gateway/gate.py: send(platform, command) -> GatedCommand`, which raises `CommandRefused`.
  - The Netmiko subclass overrides `write_channel` to accept only `RETURN` or `<gated command> + RETURN`.
  - It overrides `cleanup` to close without writing. Netmiko's default sends `exit`, and `end` if it thinks it is in config mode (verified in netmiko 4.8.0).
  - An arch test bans attribute access to `send_config_set`, `send_config_from_file`, `config_mode`, `enable`, `save_config`, `commit`, `send_multiline` and raw `.send(`/`.sendall(` on channels anywhere, and bans `write_channel` outside `device_gateway/ssh.py`.
- **[#49] Security test 1** then covers near-misses: `show version | redirect …`, `show running-config ; conf t`, trailing whitespace, newlines inside a parameter, case changes, VRF names failing the pattern.
- **[extra] Role-snippet parity** (#53, test 2) reads the same `ALLOW_LIST` objects. Never re-type commands in the generator.

## 5. Untrusted device text and outputs
- **[extra]** Escape helpers live in one place:
  - `escape_console` (C0/C1 → `\xNN`, story 81)
  - `html_escape`
  - `xml_escape`
  - `safe_names.sanitise(s, max_len)` (`[A-Za-z0-9._-]`)
- **[extra]** The report and diagram use a tiny template function that escapes every substituted value by default. Raw insertion needs an explicit `Trusted(...)` wrapper, and an AST test allows that wrapper only in `run_output/report.py` and `diagram/html.py`.
- **[extra] Fixture hygiene test** (CLAUDE.md "real device data never in repo"): scan `tests/` and `lab/` for IPv4 literals. Allowed:
  - RFC 5737 ranges
  - the refusal-test addresses (0.0.0.0, 127/8, 224/4, 255.255.255.255)
  - in `lab/`, whatever ranges #39 declares synthetic
- **[extra]** Fail on any `*.age`, `known_hosts`, `topology.json` or `audit.log` committed outside `tests/fixtures/synthetic/`. Add matching `.gitignore` entries.

## 6. CI: conflicts with decisions
- #28 and #32 defer CI to the proper-deployment phase. #47 says "there is no workflow on pushes or PRs".
- The wiki page `operator-wants-cml-build` plans a push-triggered Windows build that uploads an artifact. That **contradicts closed decisions**.
  - The coordinator should record the departure on a GitHub issue first; CLAUDE.md says to depart only by a recorded decision.
  - Or use `workflow_dispatch` only, which is not "on pushes".
- If it goes ahead, harden it:
  - `permissions: contents: read`
  - actions pinned by full SHA
  - `runs-on: windows-2025` (not `-latest`)
  - no repository secrets
  - the same `scripts/check` + build.ps1 path as the release
  - artifacts short-lived
- No CI workflow is recommended for #38 itself.

## 7. CODING_STANDARDS.md outline ([extra]; the implementer brief already points at it)
1. **Precedence:** CLAUDE.md security rules > ticket > spec > this file > habit. Use the glossary vocabulary (flag conflicts).
2. **Layout:** the module map and import DAG (link architecture). One CLI handler per `cli/cmd_<name>.py`. The Run-start pipeline is in `cli/run_start.py` as ordered step functions.
3. **Data:** frozen slotted dataclasses in `records/`; `Unknown(reason)` ≠ empty; UTC-aware datetimes only; IPs as `ipaddress` objects.
4. **Secrets:** the `Secret` API; where `.reveal()` may appear; no secrets in exceptions, logs, fixtures or commits; canary values for tests.
5. **Output:** console only via `cli/console.py`; files only via the writer helpers; temp-then-rename; every write scanned; never device output; escaping helpers.
6. **Errors:** fixed messages per exception type; never `str(e)`; ExitCode values; Ctrl+C and the stop token.
7. **Windows:** everything OS-specific behind `_winsys` with a fake; `sys.platform == "win32"` guards; the "Windows check" items go in the lab checklist.
8. **Tests:**
   - `tests/security/test_<n>_*.py` (the six, gated by build.ps1)
   - `tests/arch/` (boundaries)
   - `tests/unit/`
   - synthetic fixtures (RFC 5737), no network (socket guard), real pyrage only where the promise needs it
   - TDD (red-green-refactor) per the implementer brief
9. **Tooling:** the `scripts/check` command; ruff + mypy strict (both platforms) must pass before merge.
10. **Allow-list changes:** a new command is a breaking change (#32), so it needs a CHANGELOG "allow-list changed, re-apply the Device Role" line, and test 2 must still pass.
11. **Commits:** "Part of #NN", the attribution lines, one ticket per branch.
