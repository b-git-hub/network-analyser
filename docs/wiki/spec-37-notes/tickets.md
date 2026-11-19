> Exploration notes written 2026-11-18 at `b-git-hub/network-analyser@a069d68` by the spec #37 exploration agent. A snapshot, not maintained: tickets win over these notes. Later decisions: [spec-37-implementation-calls](../spec-37-implementation-calls.md).

# Tickets #38–#66: what each delivers, its files, blockers and collisions

Paths assume a `network_analyser/` package with one file per CLI command handler (`cli/cmd_<name>.py`) and a Run-start pipeline file (`cli/run_start.py`), as recommended in guardrails.md. Blockers are the GitHub "blocked by" edges. Collisions name the other tickets that edit the same files.

**Hotspots to sequence:**

| File | Tickets that edit it |
|---|---|
| `cli/run_start.py` | #41 #42 #43 #45 #48 #49 #50 #55 #56 |
| `records/device.py` (DeviceRecord / collected records) | #49 #50 #51 #52 #59 #60 |
| `records/events.py` | #48 defines all events; #49 #50 #51 #54 #55 #56 emit (if #48 defines every type up front, later tickets only *use* it) |
| `platforms/*/commands.py` (allow-lists) | #49 #50 #51 #59 #60, read by #53 |
| `topology/build.py` + `topology.json` schema | #52 #61 #62 |
| `diagram/` | #63 #64 #65 |
| `tests/security/test_5_canary.py` | #48 #52 #66 |
| `tests/security/test_4_no_network.py` | #63 #66 (#64 keeps it passing) |
| `CHANGELOG.md` | everyone; *proposal*: only the merger touches it |
| `docs/lab-checklist.md` | #39, then additions from #43 #49 #50 #51 #53 #54 #55 #59 #60 |

---

**#38 Project skeleton and CLI surface.**
- **Delivers:** uv project pinned to python.org 3.14 (`.python-version` 3.14.10 per #32), hash-locked deps, 11 module stubs, the full argparse surface, `--version`, ExitCode, the top-level handler (type + `file:line` only), the elevation warning, and **security test 3** (import rule).
- **Files:** pyproject.toml, uv.lock, .python-version, `network_analyser/**` stubs, `cli/__init__.py`, `tests/security/test_3_import_rule.py`.
- **Blockers:** none.
- **Collides with:** everyone downstream; it is the base. **Already in progress** (worktree `ticket/38-project-skeleton-cli`), so guardrails.md items may need a follow-up commit. Note: `uv sync --locked --no-build` fails on a packaged project (environment.md §2).

**#39 CML lab file and lab checklist.**
- **Delivers:** CML YAML lab (≥2 IOS-XE, ≥2 NX-OS, CDP/LLDP, a VLAN-Mismatch trunk, a port-channel, OSPF, a shared subnet; every password `CHANGE_ME`), and `docs/lab-checklist.md` with result/date columns plus a walkthrough.
- **Files:** `lab/*.yaml`, `docs/lab-checklist.md`.
- **Blockers:** none.
- **Collides with:** later tickets that append lab checks (doc-only, easy merges).

**#40 Settle doc conflicts.** Merged at `4bad923` (wiki log). Done.

**#41 Scope, Seeds and run file.**
- **Delivers:** `scope` (CIDR, `a-b`, single IPs, exclusions; refused in full on any bad entry; merge with a warning; count; `contains`, which refuses 0/8, 127/8, multicast, broadcast), the prompt entry loop with `!` for exclusions, TOML run file with flag precedence and setting sources, refusal of secret keys and `runs_dir`. Exit 2.
- **Files:** `scope.py`, `cli/run_file.py`, `cli/run_start.py`, `cli/cmd_run.py`, `records/run_request.py`.
- **Blockers:** #38.
- **Collides with:** #42 #43 #45 (`run_start.py`, `cmd_run.py`).
- **Ambiguities:** "broadcast" (255.255.255.255 only, or also the directed broadcast of each CIDR entry?); unknown run-file keys. *Proposal:* refuse 0.0.0.0/8, 127/8, 224/4, 240/4, 255.255.255.255, and refuse unknown keys.

**#42 Run folder, per-user data folder, Run register.**
- **Delivers:** per-user path resolution, the exclusive lock file, Run folder naming and exclusive create with `-2`, `-3`…, the label allow-list, the writable check before any prompt, the location notice (UNC / sync root / removable), the DACL "others can modify" warning, `\\?\` long paths, the register entry at creation, and no deletes.
- **Files:** `run_output/folder.py`, `run_output/lock.py`, `_winsys/*`, `safe_names.py`, `backup_store/register.py`, `cli/run_start.py`.
- **Blockers:** #38.
- **Collides with:** #41 #45 (`run_start`), #51 (`safe_names`), #58 (register).
- **Windows-only checks:** permissions and long paths; fake them on Linux.
- **Watch:** the "can write" probe must not leave a Run folder behind, because the tool never deletes one. Probe with a temp file in the parent, or create the folder only after confirm, as #45 says.

**#43 Masked prompt and crash-dump guard.**
- **Delivers:** our own msvcrt loop: `*` per char, Backspace, swallowing `\x00`/`\xe0`+code, Ctrl+C → exit 3 with no traceback, echoed fallback when input is not a TTY. Also `SetErrorMode`, the WER LocalDumps/AeDebug read, and the `YES` confirm.
- **Files:** `cli/prompts.py`, `cli/crashdump.py`, `_winsys/console.py`, `_winsys/wer.py`.
- **Blockers:** #38.
- **Collides with:** #45 (consumer), #57/#58 (reuse).
- **Watch:** the reader returns a `Secret`, never a `str` (guardrails.md).

**#44 build.ps1.**
- **Delivers:** a PowerShell 5.1 script:
  - exact python.org patch check
  - `uv sync --locked --no-build`
  - runs the security tests
  - licence check + `THIRD-PARTY-NOTICES.txt`
  - PyInstaller `--onedir --noupx` with Paramiko as plain files
  - version resource
  - zip + SHA256SUMS
  - prints commit and version
  - size/start-time warnings
- **Files:** `build.ps1`, `packaging/*.spec` or args, `packaging/version_info.txt` template, licence allow-list config.
- **Blockers:** #38.
- **Collides with:** #47; pyproject dev deps (pip-licenses).
- **Watch:**
  - `scp` (netmiko dependency) is **LGPL** too. Keep it as plain files like Paramiko.
  - pyrage's metadata licence is `UNKNOWN`, so it needs an explicit override (MIT upstream).
  - Collect data for ntc_templates and the diagram JS/CSS assets.
  - It cannot run here: pwsh 7 + PSScriptAnalyzer can lint it for 5.1 syntax (environment.md).

**#45 Backup Passphrase and Credential Sets at Run start.**
- **Delivers:** the full Run-start order to the confirm. First-Run warning, passphrase typed twice, check file created; later Runs get 3 tries. Passphrase ≥15 chars. Refused while the marker exists. ≤5 sets, each with a Platform-limit menu; empty password refused; password == passphrase → stop. Set summary + budget; Ready-to-start with sources; `[Y/n]`, where n or Ctrl+C → 3. Folder created and registered.
- **Files:** `credentials/secret.py`, `credentials/sets.py`, `backup_store/check_file.py`, `cli/run_start.py`, `cli/ready.py`.
- **Blockers:** #41 #42 #43.
- **Collides with:** #48 (credentials), #54 (`credentials/sets.py`), #58 (check file).
- **Watch:** the check file needs pyrage, so tests cost about 2.5 s per lock/unlock.

**#46 Trust Store.**
- **Delivers:** known_hosts check → known / new / changed / not-trusted; key-type pinning; old and new SHA-256 fingerprints; `accept(ip, fp)`; strict mode; read-only `--known-hosts`; write only when the caller says a password was sent; atomic writes.
- **Files:** `trust_store.py`.
- **Blockers:** #42.
- **Collides with:** none (`trust-key` wiring is in #49).
- **Watch:** no paramiko import here (the import rule). Parse and fingerprint keys from bytes with `base64` + `hashlib` only (SHA-256 of the key blob, base64 without padding, `SHA256:` prefix).

**#47 Tag-triggered release workflow.**
- **Delivers:** a `.github/workflows/release.yml` that runs only on a `v0.y.z` tag on `windows-2025`, with the same gates as build.ps1. Publishes the Latest Release with the zip and `SHA256SUMS.txt`, and puts the SHA in the run summary. Also a tagging procedure doc, a release-notes template, install docs, CHANGELOG.
- **Files:** `.github/workflows/release.yml`, `docs/releasing.md`, `CHANGELOG.md`.
- **Blockers:** #44.
- **Collides with:** #44 (best if the workflow just calls build.ps1).
- **Conflict:** it says "no workflow on pushes or PRs". The wiki's planned push-build for the CML prototype contradicts this (see guardrails.md §CI).

**#48 Audit log and redaction layer.**
- **Delivers:** the audit JSONL writer with the fixed schema for **every** event type from story 162. `credentials.contains_secret` (exact, case-sensitive → `[blocked]` + hit count). The scanned console writer. Library loggers capped. Exception → fixed message map. An audit write failure → graceful stop. **Security test 5** (repr/str, console, audit, library loggers).
- **Files:** `run_output/audit.py`, `run_output/writer.py`, `credentials/scan.py`, `records/events.py`, `cli/console.py`, `tests/security/test_5_canary.py`.
- **Blockers:** #42 #45.
- **Collides with:** #45 (credentials), all emitters, #52 #66 (extend test 5).
- **Advice:** define all event dataclasses now so later tickets only emit.

**#49 Tracer bullet: Seeds → identify.**
- **Delivers:** `device_gateway`:
  - Scope check at socket open, IP only
  - Trust Store before password
  - one attempt per connect, no keys/agent
  - modern algorithms + `SSH algorithms too old`
  - client ID `SSH-2.0-NetworkAnalyser_<v>`
  - session log off, output cap, escape stripping
  - the `send()` gate incl. Netmiko session setup
  - config-mode drop
  - identification (ID string hint, `CISCO_WLC` rejected, prompt, `terminal length 0`, `show version`; ASA/IOS-XR rejected)
  - landing privilege, serials, hostname, model, version
  - audit events, basic summary, `trust-key`
  - **security test 1**
- **Fixes the `DeviceRecord` shape.** Minimal allow-list: `terminal length 0`, `terminal width 511`, `show version`, plus the privilege command (provisional, lab check).
- **Files:** `device_gateway/{gate,ssh,visit}.py`, `platforms/{allowlist,hints}.py`, `platforms/*/{commands,identify}.py`, `records/device.py`, `discovery/__init__.py` (Seeds only), `cli/cmd_trust_key.py`, `cli/run_start.py`, `tests/security/test_1_allowlist_gate.py`.
- **Blockers:** #46 #48.
- **Collides with:** #50 #51 #52 #53 (`records/device.py`, `commands.py`).
- **Watch:** override netmiko `write_channel` and `cleanup` (architecture.md §6). Only unit tests are possible; there is no SSH server (deferred by #28).

**#50 Crawl CDP/LLDP in parallel.**
- **Delivers:** FIFO crawl de-duplicated by IP, no hop limit; hint gating (supported / known-unsupported / ID-string gate); Seeds always logged into; address choice (mgmt first, ≤3, next only after a *connection* failure); outside/IPv6-only/excluded reasons; ARP/MAC never used as targets. Pool 10/50, one session per device, timeouts, one 30 s retry, a command timeout → partial. Identity order: Trust Store → host-key alias → serial. Stack = one device, vPC = two. The 13 reasons defined once.
- **Files:** `discovery/*`, `platforms/hints.py`, `platforms/*/commands.py` + parsers for CDP/LLDP detail, `records/{device,neighbour,reasons}.py`, `device_gateway/visit.py`.
- **Blockers:** #49.
- **Collides with:** #51 #52 (`records/device.py`), #54 #55 #56 (`discovery`), #59 #60 (CDP/LLDP parsers they "extend").

**#51 Capture and lock Backups.**
- **Delivers:** `show running-config view full` (IOS-XE) and the NX-OS running-config command, with the acceptance check (no error; framing: IOS-XE header + `end`, NX-OS `version` line; plus a `hostname` line). One locking worker, queue capped at `--parallel`. pyrage passphrase lock, ciphertext temp → flush → rename. Names sanitised with fallbacks. `manifest.age`. Scrypt level from the header, total lock time, a flag below 2^18. Audit per Backup. Partial configs never written; captured ones still locked after Ctrl+C.
- **Files:** `backup_store/{lock,age_io,manifest,naming}.py`, `platforms/*/{commands,backup_check}.py`, `device_gateway/visit.py`, `discovery/*`.
- **Blockers:** #49.
- **Collides with:** #50 (`visit`/`discovery`), #52 (`DeviceRecord`), #57 #58 (`backup_store`), #42 (`safe_names`).
- **Watch:** raw config via a sink, never in `DeviceRecord`. Real-pyrage tests take about 2.5 s per lock.

**#52 Topology core + topology.json.**
- **Delivers:** the collected-record contract (every field can be *unknown*). Links from CDP/LLDP (confirmed / one-sided, CDP+LLDP merged), Shared Segments, Bundles + flagged members, vPC peer-link/keepalive, stack member numbers, Unvisited merge (IP or chassis ID only, folded into Visited). Evidence + conflicts, skipped-check list, short names + reported names, stable ids, `format_version`, no username. Written at Run end (also after Ctrl+C) through the scanned writer. Test 5 extended.
- **Files:** `topology/*`, `records/{collected,topology}.py`, `cli/run_start.py` (end-of-Run write), `tests/security/test_5_canary.py`.
- **Blockers:** #49.
- **Collides with:** #59 #60 (`records/collected.py`), #61 #62 (`topology/build.py`, schema), #63 (schema consumer).
- **Watch:** settle the stable-id scheme here. It is shared by the diagram and the report.

**#53 role-snippet.**
- **Delivers:** generators that read the allow-list. IOS-XE: CLI view + `aaa new-model` note; custom-privilege fallback that puts `show` back at level 1; never a writable `file privilege`. NX-OS: one custom role = allow-list + `terminal length 0` / `terminal width 511`, no `network-operator` / `rule permit read`. `--tacacs` (ISE shell profile + command set, `shell:roles`; a RADIUS note); `--username`; dedicated-account advice. **Security test 2.**
- **Files:** `platforms/*/role.py`, `cli/cmd_role_snippet.py`, `tests/security/test_2_role_snippet.py`.
- **Blockers:** #49.
- **Collides with:** low. Its test re-runs whenever #50/#51/#59/#60 add allow-list entries.
- **Watch:** templated (per-VRF) entries need a role rule form. Decide how a template maps to a role rule (NX-OS regex rules vs IOS view `parser view` commands).

**#54 Credential order, budget, probation.**
- **Delivers:** order + move-to-front; Platform-limited sets; once per device; budget 3 (≤5); probation (one in flight across the pool); retirement announced with number + username; all retired → `not attempted (Credential Sets retired)` and stop; `authentication failed (every eligible set tried)`; audit by username; per-set results.
- **Files:** `credentials/sets.py`, `discovery/pool.py`, `device_gateway/visit.py` (credential lease API).
- **Blockers:** #50.
- **Collides with:** #45 (`credentials`), #55 #56 (`discovery`).
- **Watch:** thread-safe lease/release API; the gateway gets a password only through a lease.

**#55 Opt-in Sweep.**
- **Delivers:** a TCP 22 probe via `device_gateway` (Scope checked at the socket): no ICMP, ≤100 in flight (`--sweep-inflight` lowers only), 2 s timeout, ascending order, closes before KEX. Login only on `Cisco-*` or the NX-OS pattern (provisional `OpenSSH_* FIPS`). Refused above 65,536 addresses, warning above 4,096. Audit; results kept for the report.
- **Files:** `device_gateway/probe.py`, `discovery/sweep.py`, `platforms/hints.py`, `cli/run_start.py`.
- **Blockers:** #50.
- **Collides with:** #54 #56 (`discovery`).

**#56 Live progress, Ctrl+C, final summary.**
- **Delivers:** live panel / log / quiet modes (log is automatic when output is redirected); counts, never a percentage; no frozen look during locks; escaped device text; console through the scan. 1st Ctrl+C: graceful stop, queued devices → `not attempted (Run stopped)`. 2nd: close at once, partial devices. Stopped Runs still write their outputs. Final summary with `!!` items and next steps, full paths printed, exit codes 0/1/3.
- **Files:** `cli/{progress,summary,signals}.py`, `discovery/*` (stop flags), `cli/run_start.py`.
- **Blockers:** #50.
- **Collides with:** #54 #55 (`discovery`), #66 (summary data shared with the report).
- **Watch:** Windows Ctrl+C semantics (SIGINT on the main thread; `KeyboardInterrupt` lands in the main thread while workers block). Test via an injected stop token.

**#57 show-backup.**
- **Delivers:** masked passphrase + crash-dump check, print to the console only (escaped); no file → list a Run's Backups. Works while a change is pending and says when a file is under the other passphrase. Fixed messages on wrong passphrase / damaged file; no traceback.
- **Files:** `backup_store/show.py`, `cli/cmd_show_backup.py`.
- **Blockers:** #51.
- **Collides with:** #58 (`backup_store`, the pending-state logic).
- **Ambiguity:** "the right exit code" for a wrong passphrase. *Proposal:* 2.

**#58 change-passphrase.**
- **Delivers:** find files via the register + `--run-folder`; summary + 3 s/file estimate + confirm; same prompts; new passphrase typed twice, ≥15 chars, different from the current one. Per file: unlock → lock → verify → temp → rename. Marker + previous check file; resume. Undecryptable files skipped and listed; manifest-mismatch files flagged. `relock-<UTC>.txt`; the fixed end warning; documented manual reset; holds the lock. **Security test 6.**
- **Files:** `backup_store/{relock,register,check_file}.py`, `cli/cmd_change_passphrase.py`, `tests/security/test_6_change_passphrase.py`, docs.
- **Blockers:** #51.
- **Collides with:** #57, #45 (check file), #42 (register).

**#59 IOS/IOS-XE collection + parsers.**
- **Delivers:** allow-list entries + parsers (TextFSM/ntc-templates) for: CDP/LLDP detail, interfaces/switchport/trunk, VLANs, port-channel, `show ip interface`, VRFs, ARP, MAC, OSPF/EIGRP/BGP, static routes, HSRP/VRRP/GLBP. A denied command → *unknown*, never fatal. The short-name table. Stack member numbers. Synthetic fixtures only.
- **Files:** `platforms/ios_xe/{commands,parsers,shortnames}.py`, `tests/unit/platforms/ios_xe/*`.
- **Blockers:** #52.
- **Collides with:** #60 (`records/collected.py`, maybe `platforms/allowlist.py`), #50 (CDP/LLDP parsers).

**#60 NX-OS collection + parsers.** The same list as #59 for NX-OS, using `| json`, plus vPC and marking the `management` VRF.
- **Files:** `platforms/nxos/*`.
- **Blockers:** #52.
- **Collides with:** #59, as above.
- **Watch:** NX-OS `| json` strings and RBAC matching are provisional (lab check).

**#61 VLAN Mismatches.**
- **Delivers:** effective VLANs (allowed ∩ present in the VLAN database); 4 kinds; both ends Visited with data collected (CDP native VLAN counts even from an Unvisited Device); missing data → *unknown* + skipped reason; computed per Bundle, not per member; evidence + stable id.
- **Files:** `topology/vlan.py`, `topology/build.py`, `records/topology.py`.
- **Blockers:** #52.
- **Collides with:** #62 (`build.py`, Topology record, maybe `format_version`).

**#62 L3 Adjacency, Subnets, MAC/ARP inference.**
- **Delivers:** shared-subnet adjacency (same prefix + VRF; secondaries count; not /32s, FHRP VIPs, unnumbered, or management VRFs); OSPF/EIGRP/BGP adjacency; ≥3 devices on a prefix → Subnet node; MAC/ARP inference only for unknown L3 next hops, on the single edge port; `seen only in routing or ARP data (not crawled)`; evidence + ids.
- **Files:** `topology/{l3,inference}.py`, `topology/build.py`, `records/topology.py`.
- **Blockers:** #52.
- **Collides with:** #61.

**#63 render + diagram.html (Map / Physical).**
- **Delivers:** self-contained HTML (own JS, no network) with escaped strings, written temp → rename. Tiered layout by hop distance from the most central device + its vPC peer, 24 per row, fixed positions. Interface labels; line styles; Bundles; Shared-Segment "?"; Unvisited area; details panel; `#device=`. `render RUN_FOLDER` reads older format versions and refuses newer; it never regenerates the report. Rendered at Run end. **Security test 4 (diagram half).**
- **Files:** `diagram/{__init__,html,layout}.py`, `diagram/assets/*.js|css`, `cli/cmd_render.py`, `tests/security/test_4_no_network.py`.
- **Blockers:** #52.
- **Collides with:** #64 #65 (`diagram`), #66 (test 4).

**#64 Routing/VLAN views, markers, Findings tab.**
- **Files:** `diagram/assets/*`, `diagram/html.py`.
- **Blockers:** #61 #62 #63.
- **Collides with:** #65 (`diagram/__init__` / layout).

**#65 diagram.drawio.**
- **Delivers:** Physical + Routing pages at the same positions; matching line styles; details in shape data (no username); XML-escaped; scanned; temp → rename; no URLs (do not emit `xmlns="http…"`); redrawn by `render`.
- **Files:** `diagram/drawio.py`, `diagram/__init__.py`.
- **Blockers:** #63.
- **Collides with:** #64 (`diagram/__init__`, shared layout).
- **Note:** the Routing page needs L3 data from #62, but #62 is not a blocker. Either sequence #65 after #62, or render the Routing page from whatever L3 data exists.

**#66 run-report.html.**
- **Delivers:** static page, no `<script>`, CSP meta, escaped, UTC. Sections Summary → Needs attention → new host keys → Visited → Unvisited by reason → Topology findings → Sweep → Credential Sets. Links to `diagram.html#device=` / `#finding=`. Written once, also after Ctrl+C; best-effort "ended: crashed"; never touched by render. **Test 4 (report half) + test 5 extended.**
- **Files:** `run_output/report.py`, `records/run_summary.py`, `cli/run_start.py` + top-level handler (crash report), tests 4/5.
- **Blockers:** #51 #52 #56.
- **Collides with:** #56 (summary data), #63 (test 4), #48/#52 (test 5).
- **Note:** it also needs Sweep results (#55) and Credential Set results (#54), which are not blockers. Render those sections only if the data exists, or sequence #66 after #54 and #55.

## Suggested merge waves
1. #38, #39, #40 (done)
2. #41, #43, #44 in parallel; #42 after #41 or merge carefully (`run_start`)
3. #45, #46, #47
4. #48
5. #49
6. #50, #51, #52, #53. #52 and #53 are fairly independent of #50 and #51; #50 and #51 both touch `visit` and `discovery`, so merge them one after the other.
7. #54, #55, #56 (all `discovery`; serialise merges); #57, #58 (serialise); #59 and #60 in parallel; #61 and #62 in parallel (serialise the `build.py` merge); #63
8. #64, #65, #66
