> Exploration notes written 2026-11-18 at `b-git-hub/network-analyser@a069d68` by the spec #37 exploration agent. A snapshot, not maintained: tickets win over these notes. Later decisions: [spec-37-implementation-calls](../spec-37-implementation-calls.md).

# Architecture notes for spec #37 (exploration, 2026-11-18)

Sources: spec #37 ("Modules and their interfaces", "CLI surface", "Per-user data"), ADR 0002–0005, decision tickets #6 #7 #9 #10 #11 #12 #13 #22 #26 #27 #28 #30 #31 #32. **Tickets win over the spec, and the spec wins over these notes.** Anything marked *proposal* is my suggestion, not a decision. Where it matters, record your choice in CODING_STANDARDS.md or the wiki.

## 1. Modules (11, ADR 0003 / #9 / spec table)

| Module | Owns (short) | Built mainly by |
|---|---|---|
| `cli` | argparse for 6 commands + `--version`; prompts; masked reader (#43); crash-dump guard (#43); Run-start order (#45); progress live/log/quiet, Ctrl+C, final summary (#56); exit codes; top-level exception handler (#38) | #38 #41 #43 #45 #56, plus handlers from #49 #53 #57 #58 #63 |
| `scope` | parse/validate IPv4 entries + exclusions, merge, `contains(ip)`, refusing reserved/loopback/broadcast/multicast | #41 |
| `credentials` | Credential Sets + Backup Passphrase in memory; secret-safe `repr`/`str`; order, move-to-front, Platform limit, failure budget, probation, retirement; `contains_secret(text) -> (redacted, hits)` | #45 #48 #54 |
| `trust_store` | OpenSSH `known_hosts` keyed by IP+port; check → known/new/changed/not-trusted; key-type pinning; strict; read-only `--known-hosts`; `accept(ip, fp)` | #46 (+ `trust-key` wiring in #49) |
| `device_gateway` | **only** module that opens sockets and imports netmiko/paramiko. Scope check at socket open, Trust Store before password, IP only, one password attempt per connect, modern algorithms, `send(platform, command)` gate, config-mode drop, timeouts, one connection retry, output cap, escape stripping, Sweep `probe(ip)` | #49 #50 #51 #55 |
| `platforms/ios_xe`, `platforms/nxos` | ID patterns, compiled-in allow-list (exact strings or strict templates), parsers → plain records or *unknown*, `is_valid_backup`, interface short-name table, `role_snippet` | #49 #50 #51 #53 #59 #60 |
| `discovery` | Seeds, Sweep, FIFO crawl de-duplicated by IP, address choice, hint gating, pool (10 / max 50), alias + serial de-dup, Unvisited reasons, stopping | #49 (Seeds only) #50 #54 #55 #56 |
| `backup_store` | one locking worker + queue capped at `--parallel`; age passphrase via pyrage; temp-then-rename; `manifest.age`; check file; scrypt level from header; `show-backup`; `change-passphrase`; **Run register** | #42 (register) #45 (check file) #51 #57 #58 |
| `topology` | Links, Shared Segments, Bundles/vPC, VLAN Mismatch, L3/Subnets, MAC/ARP inference, Unvisited merging, evidence, conflicts, *unknown*, stable ids → `topology.json` | #52 #61 #62 |
| `diagram` | `diagram.html` (own plain JS, no libraries) + `diagram.drawio`, both from `topology.json` only | #63 #64 #65 |
| `run_output` | Run folder (naming, `\\?\` long paths, location notice, permissions warning), single-instance lock, `audit.log` (fixed schema), `run-report.html`, the one scanned writer | #42 #48 #66 |

### Proposed extra leaf modules (not in the spec's 11; *proposal*, #38 decides)
- `records` (stdlib only): the shared plain-data records below, `UNVISITED_REASONS` (the 13 strings, #50 "defined once"), `Unknown`, `ExitCode`. Without it, `topology` and `diagram` would have to import `device_gateway` to get the device record type, which breaks the import rule's intent.
- `_winsys` (or `oswin`): every Windows-only call behind one seam with a non-Windows fake. That covers `msvcrt`, `winreg`, `ctypes.windll`, the elevation check, `SetErrorMode`, DACL read, the lock file, sync-root/removable detection and `%LOCALAPPDATA%`. See environment.md.
- `safe_names`: the `[A-Za-z0-9._-]` sanitiser. `--label` (#42, max 32) and Backup names (#51, max 64) share the same allow-list (#26).

## 2. Import direction (who may import whom)

Spec: `cli → discovery → device_gateway → platforms`; `discovery → backup_store, topology`; `diagram` reads only the Topology file. #9 adds `device_gateway → scope, trust_store, credentials`. #30: `run_output` calls `credentials.contains_secret`.

Proposed allow-list of internal imports. Anything not listed is forbidden, and a test enforces it (see guardrails.md):

```
records, safe_names, _winsys : stdlib only
scope          → records
credentials    → records
trust_store    → records                      (paths passed in, never resolved here)
platforms.*    → records, safe_names?         (+ textfsm, ntc_templates)
device_gateway → records, scope, trust_store, credentials, platforms   (+ netmiko, paramiko: ONLY here)
backup_store   → records, safe_names, credentials (Secret type only)   (+ pyrage: ONLY here)
topology       → records
diagram        → records                      (reads topology.json via records' loader)
run_output     → records, safe_names, credentials (contains_secret only), _winsys
discovery      → records, scope, credentials, device_gateway, platforms (hint patterns), backup_store (lock queue)
cli            → anything
```

Where secrets may live:
- ADR 0003 says only `credentials` + `device_gateway` hold a **password**.
- #45 adds that `backup_store` holds the **Backup Passphrase**.
- The masked reader in `cli` necessarily sees the characters as they are typed.

Proposed rule:
- Credential Set password: `credentials`, and `device_gateway` at the paramiko call.
- Backup Passphrase: `credentials`, and `backup_store` at the pyrage call.
- `cli` masked reader: builds a `Secret` directly from a local char list and returns only the `Secret`.

## 3. Plain-data records (frozen dataclasses; no live sessions, ADR 0003)

| Record | Producer → consumer | Notes / decided on |
|---|---|---|
| `RunRequest` | cli → discovery | scope, seeds, label, parallel, failure_budget, sweep, sweep_inflight, timeouts, strict_host_keys, known_hosts path, progress mode; **`source` per setting** (flag / run file / prompt / default) for Ready-to-start (#41, #31) |
| `ScopeRecord` | scope → all | merged include ranges, exclusions, address count, warnings; `contains(ip)`. It is the *only* in-Scope check (#41) |
| `Secret` | credentials | no `__str__`/`__repr__` value, no `__eq__` leak, no pickling; `.reveal()` only for gateway/backup_store (guardrails.md) |
| `CredentialSetView` | credentials → cli, report, audit | number, username, Platform limit, successes, failures, retired. **No password, not even its length** (#30 §3.8) |
| `Event` subclasses | device_gateway, discovery, backup_store, cli → run_output audit + progress | one dataclass per audit event type with fixed fields (#48, #30 §7). Passed down as an `emit(event)` callable, because device_gateway emits per command on worker threads |
| `ProbeResult` | device_gateway → discovery | ip, open?, SSH identification string (sanitised), failure kind (#55) |
| `DeviceRecord` | device_gateway → discovery → topology/report | ip logged into, aliases, SSH ID string, host-key result + fingerprints, username used, landing privilege, Platform, hostname, model, version, serial(s), stack members, `results: {command: parsed records \| Unknown(reason)}`, outcome, Unvisited reason or partial flag + reason, timings. Shape fixed by #49 and extended by #50/#51/#52; collected-record contract from #52, filled by #59/#60 |
| `BackupRequest` | device_gateway → backup_store queue | identity (hostname, serial(s), Platform, command, capture time) + raw config. **Must not ride inside `DeviceRecord`**: #51 says "raw config goes straight from device_gateway to backup_store and to nothing else". *Proposal:* `visit(..., backup_sink)` |
| `BackupRecord` | backup_store → report/audit | path, ciphertext SHA-256, scrypt level (from header `-> scrypt <salt> <logN>`), lock seconds, status / not-taken reason |
| `NeighbourRecord` | platforms parsers → discovery/topology | local port (short + reported), remote port, addresses (mgmt first), Platform hint string, LLDP chassis ID, source CDP/LLDP, CDP native VLAN |
| `UnvisitedRecord` | discovery/topology | reason (one of 13), label, advertised Platform, IPs, chassis ID, reported-by |
| `Topology` | topology → `topology.json` → diagram/report | see §4 |
| `RunSummary` | cli → run_output report | everything §157–158 needs. Built from records only, never raw output |
| `Unknown(reason)` | anywhere | distinct from empty/absent. *Unknown* must never be read as "none" (#11, story 126) |

## 4. File formats

| File | Where | Format | Decided on |
|---|---|---|---|
| Run file | operator's choice, `--from` | TOML (`tomllib`). Keys: `label, scope, exclude, seeds, parallel, failure_budget, sweep`. Any password/passphrase-like key → refuse (exit 2). `runs_dir` → refuse. Unknown keys: unspecified; *proposal:* refuse (strict, exit 2) | #31, #41 |
| Trust Store | `%LOCALAPPDATA%\NetworkAnalyser\trust\known_hosts` | OpenSSH known_hosts, keyed IP+port (*proposal:* always `[ip]:port`, unhashed). Atomic write. Written only after a password was actually sent | ADR 0002, #7 §3, #46 |
| Check file | per-user folder (name not decided; *proposal* `passphrase-check.age`) | age passphrase file holding a fixed known phrase | ADR 0004, #12, #45 |
| Previous check file, change-pending marker | per-user folder (*proposal* `passphrase-check.previous.age`, `change-pending.json`) | marker holds start time + files done, no secrets | #22, #58 |
| Run register | per-user folder (*proposal* `run-register.txt`, one absolute path per line, append-only) | "plain list of Run folders, no secrets"; `--run-folder` updates it | #22, #26, #42 |
| Lock file | per-user folder (*proposal* `instance.lock`) | held open exclusively (`msvcrt.locking` / `fcntl` fake) | #26, #42 |
| Run folder | `%LOCALAPPDATA%\NetworkAnalyser\runs\<UTC>[_<label>]`, e.g. `20261118T101530Z_dc1-core`; `-2`, `-3`… on clash; created exclusively; never deleted | layout below | #26, #42 |
| `audit.log` | Run folder | JSON Lines, flushed per line, UTC ms timestamps, `severity` ∈ info/warning/error, fixed fields per event type, unknown fields refused, no device output, no rotation | #30 §6–8, #48 |
| `topology.json` | Run folder | plaintext, redacted, secret-scanned; single-int `format_version` (bump only when an older `render` would misread; `render` ignores unknown fields and refuses newer); stable ids for every device + finding; no username | spec, #11, #26, #52 |
| `diagram.html` | Run folder | self-contained, no `http(s)://`, no `<script src>`, no `fetch`; `#device=<id>`, `#finding=<id>`; temp-then-rename | #13, #63, #64 |
| `diagram.drawio` | Run folder | Physical + Routing pages, same positions; details in shape data; XML-escaped; no external URL | #13, #65 |
| `run-report.html` | Run folder | static, **no `<script>` at all**, CSP `<meta>`, all device strings escaped, UTC times, `<details>` for long tables; written once (also after Ctrl+C; best-effort "ended: crashed") | #30, #66 |
| Backups | `Run folder\backups\<hostname>__<serial>.cfg.age` | standard age, scrypt recipient, plaintext = exact running config; names `[A-Za-z0-9._-]`, ≤64, fallback serial-only then index | ADR 0004, #12, #51 |
| `manifest.age` | `backups\` | age-encrypted. Per Backup: hostname, serial, Platform, command, capture time, tool version, plaintext + ciphertext SHA-256 (inner format undecided; *proposal* JSON) | #12, #51 |
| `relock-<UTC>.txt` | Run folder | plaintext, per-file fingerprint before/after | #22, #58 |
| Release | GitHub Release | `network-analyser-<version>-win-x64.zip`, `SHA256SUMS.txt` (every file in the build folder + the zip), notes from `CHANGELOG.md`; version in `pyproject.toml` must equal the tag | #32, #44, #47 |

Install location (no installer): `%LOCALAPPDATA%\Programs\NetworkAnalyser\<version>\` (#47).

## 5. CLI (frozen surface, spec "CLI surface")

- `run`:
  - `--scope/--exclude/--seed` (each repeatable), `--from FILE`
  - `--sweep`, `--sweep-inflight N` (≤100)
  - `--parallel N` (default 10, max 50; help warns that more than 10 loads AAA)
  - `--failure-budget N` (default 3, max 5, lower only)
  - `--strict-host-keys`, `--known-hosts FILE`
  - `--connect-timeout 10`, `--login-timeout 20`, `--command-timeout 60`, `--backup-timeout 300`, `--device-timeout 900` (seconds)
  - `--runs-dir DIR` (flag only), `--label` (≤32, safe chars), `--progress live|log|quiet`
  - Help text says secrets are never options or env vars (story 30).
- `render RUN_FOLDER`; `show-backup [BACKUP_FILE]` (no file → list a Run's Backups, #57); `trust-key IP --fingerprint SHA256:…`; `role-snippet {ios-xe,nx-os} [--username NAME] [--tacacs]`; `change-passphrase [--run-folder DIR …]`; `--version` (SemVer 0.y.z).
- Exit codes, for every command: 0 clean · 1 needs attention · 2 refused before any device contacted · 3 stopped/cancelled · 4 internal error (story 90). Unbuilt commands exit 4 with a fixed "not built yet" line (#38).

**Run-start order** (spec, #31, ADR 0004): lock + folder-writable checks → Scope & Seeds → crash-dump check (`SetErrorMode(SEM_NOGPFAULTERRORBOX)`; read HKLM WER `LocalDumps` + AeDebug, never write) → Backup Passphrase (≥15 chars; first Run typed twice and creates the check file; later Runs get 3 tries) → Credential Sets (≤5; username, password once, Platform-limit menu, "add another?"; empty password refused; password == passphrase → stop) → Ready-to-start + `Start the Run? [Y/n]` → Run folder created and registered at once → crawl. A Run is refused while a change-pending marker exists.

## 6. Cross-cutting rules implementers trip on
- **Untrusted device text** (#28, #30, #31):
  - HTML-escape it in every page; XML-escape it in drawio.
  - Sanitise it before it becomes a filename.
  - Escape C0/C1 controls before console or file output (`\x1b` printed literally).
  - Cap output size.
- **Never kept or logged:** device output, including a line that failed to parse. Parser problems are logged as command + parser + reason only (#30 §8).
- **Library loggers:** `netmiko`/`paramiko` capped at WARNING, with `NullHandler` and `propagate=False`. Without a handler, Python's *lastResort* prints WARNING+ to stderr. The stdlib `logging` module is never used for our own files. `faulthandler` stays off.
- **Exceptions are mapped, not echoed:** each library exception type → fixed message. The top-level handler prints the type and `file:line` frames only. Also set `threading.excepthook` and `sys.unraisablehook` (the paramiko transport thread would otherwise print traceback text).
- **Netmiko gotchas (verified in netmiko 4.8.0 source):**
  - `CiscoBaseConnection.cleanup()` writes `exit`, and `exit_config_mode` writes `end`.
  - `find_prompt` / `check_config_mode` write a bare RETURN.
  - Session prep writes `terminal width 511` + `terminal length 0`.
  - All of these go through `write_channel`, so the robust gate is an override of `write_channel` (only RETURN, or an allow-listed string + RETURN), plus `cleanup` overridden to just close the transport.
  - Netmiko's DEBUG logger logs every `read_channel` (#30), so it must stay capped.
- **Paramiko specifics:**
  - Pass `look_for_keys=False`, `allow_agent=False`, `key_filename=None`, `pkey=None` (#6).
  - Pin the key type for a known IP by disabling other host-key algorithms via `disabled_algorithms={"keys": [...]}` (ADR 0002).
  - The client ID string is the class attr `Transport._CLIENT_ID` (default `paramiko_5.1.0`). Set it to `NetworkAnalyser_<version>` (story 48).
  - The host key is checked before auth, via the `MissingHostKeyPolicy` / `BadHostKeyException` path.
- **pyrage holds the GIL** for each lock: about 2.5 s here, measured. A ticking thread got 1 tick in that time. Progress cannot redraw *during* a lock, so to meet story 80 print or update "locking Backup n…" *before* handing the config to the worker.
- **No `http://` anywhere in `diagram.html`** (security test 4). So never use `createElementNS("http://www.w3.org/2000/svg", …)`. Write inline `<svg>` markup / `innerHTML` strings instead, as the prototype on `claude/wayfinder-e3uvd6` does. Avoid the identifier `fetch` too.
- **Fixtures:** IPs from RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); hostnames like `sw-a`; canary secrets like `CANARY-pw-7f3a`. Never real data (CLAUDE.md, #28).

## 7. Prototypes (reference behaviour, not code to merge)
- Credential prompt: branch `ccr-ca84f00b-wqls0w`, `prototypes/credentials/credential_prompt_prototype.py`. Its msvcrt loop swallows `\x00`/`\xe0` prefixes and raises on `\x03`.
- Run console: branch `claude/awesome-cerf-14lk78`, `prototypes/run-console/run_console_prototype.py`.
- Diagram: branch `claude/wayfinder-e3uvd6`, `prototypes/diagram/topology-diagram.prototype.html`.

Shallow clones of all three are in `/tmp/claude-0/-home-user-network-analyser/7e9dc9da-55e5-5512-b270-d983f4f0e97f/scratchpad/proto/`.
