# Spec #37 follow-ups carried between tickets

Work that a finished ticket surfaced for a later ticket. The coordinator copies each item into that later ticket's implementer prompt and strikes it here, dated, once merged.

- 2026-11-18, from #39 (merged at `2c4c9e3`): when #53 (`role-snippet`) lands, replace the lab file's provisional hand-written `netanalyser` Device Role with `role-snippet` output. Target: #53.
- 2026-11-18, from #39: the fixture-hygiene test (planned in [guardrails](spec-37-notes/guardrails.md)) should also scan `lab/`, allowing the three RFC 5737 ranges and requiring every secret to be `CHANGE_ME`. Target: #38 if still open, otherwise the next ticket that touches tests.
~~- 2026-11-18, from #39: the lab checklist reads "nothing captured is committed" as allowing SSH identification strings and command syntax to be quoted in results. Awaiting the operator's confirmation.~~ Resolved 2026-11-18: the operator confirmed that reading is fine.
- 2026-11-18, from #38 (merged at `fc2a616`): writer modules must add their files to `WRITE_OWNERS` in `tests/arch/test_secret_rules.py` (it starts empty). Targets: #42, #46, #48, #51.
- 2026-11-18, from #38: `Secret` refuses `==`, truth tests, `len`, hashing, copying and pickling. Use `same_as()` / `is_empty()`; records must never hold a `Secret`. Targets: #45 and anything handling secrets.
- 2026-11-18, from #38: security test 5 needs the `credentials`/`run_output` secret scan to also catch the Backup Passphrase, which lives only in `backup_store`; settle how the scan learns it (e.g. backup_store registers a redaction token). Targets: #45, #48.
- 2026-11-18, from #38: guardrails not yet built: a plain-data field check over `records/`, and bans on config-mode Netmiko calls. Targets: #49 (gateway), #52 (records).
- 2026-11-18, from #38: `--device-timeout` is in minutes, following #31's prototype help. Awaiting the operator's confirmation (a later change would break compatibility).
- 2026-11-18, #38 retro: `EXCEPTION_SAFE_CALLS` in `tests/arch/test_secret_rules.py` matches bare function names, so a netmiko exception mapper fails until registered, and any function named `fixed_message` anywhere passes. Register mappers by qualified name (module path + function). Targets: #49, #50.
- 2026-11-18, #38 retro (deferred): a `.githooks/pre-commit` running `scripts/check.py` as a local stand-in for deferred CI. Weigh Windows PowerShell friction first; not scheduled.
- 2026-11-18, from #43 (merged at `9b7dcc5`): the masked reader swallows `à` and the next key (msvcrt prefix clash). Opened as [#68](https://github.com/b-git-hub/network-analyser/issues/68), sub-issue of #43, awaiting the operator's call. Also: EOF at a prompt now cancels like Ctrl+C (exit 3); on Linux the crash-dump guard always asks for `YES`.
- 2026-11-18, from #41 (merged at `4bf7aa7`): a run label from the run file is only checked to be text; #42 should apply its label allow-list to it (sent to #42's implementer). Target: #42.
- 2026-11-18, from #41: #45's Ready-to-start block should read `RunRequest`'s per-setting sources and replace #41's interim summary lines. Target: #45.
- 2026-11-18, from #41: no `--no-sweep` flag, so a run file's `sweep = true` can't be overridden on the command line; link-local (169.254/16) is not refused by `contains()`. Both await the operator. Target: #55 if a flag is wanted.
- 2026-11-18, from #42 (merged at `f5617ad`): #45 must call `cli.run_folder.create_and_register` after the confirm (nothing calls it yet), and refuse a run label that matches a typed secret. Target: #45.
- 2026-11-18, from #42: `RunsParentCheck.notices` (location notice, permissions warning) must be folded into the Run report. Targets: #45, #66.
- 2026-11-18, from #42: pass the Run register's text through the secret scan once it exists. Target: #48.
- 2026-11-18, from #42: Backup file names should reuse `records.safe_names`. Target: #51.
- 2026-11-18, from #42: `show-backup` should read the Run register and handle `--run-folder`. Target: #57 (the report said #58; the register lookup belongs to whichever of #57/#58 lists Backups).
- 2026-11-18, from #42: the only delete in the code is the writability probe folder; `tests/arch/test_no_deletes.py` enforces that. Data-folder file names chosen by #42: `run-register.txt`, `instance.lock`, `passphrase-check.age`, `change-pending.json`, `trust/known_hosts`. Targets: #46 (Trust Store uses `trust/known_hosts`), #58.
- 2026-11-18, from #44 (merged at `ad98071`): cffi 2.1.1 is MIT-0, not literally on the allowed licence list; it passes through a version-pinned override. Awaiting the operator's confirmation. pyrage and pyserial pass through documented overrides too.
- 2026-11-18, from #44: the release workflow should call `build.ps1` (or reuse `scripts/third_party_notices.py`, `version_resource.py`, `package_build.py`) rather than duplicate its gates. Target: #47.
- 2026-11-18, from #44: diagram assets under `network_analyser/` are bundled automatically by `collect_data_files("network_analyser")` in `network_analyser.spec`. Target: #63.
- 2026-11-18, from #44: build.ps1 ran end to end under pwsh 7.4 on Linux (with 13 platform swaps), but the Windows-only steps (py launcher and registry lookup, Authenticode checks, AMD64 check, exe version resource, running under Windows PowerShell 5.1) were only reviewed. Lab checklist row G13 asks the operator to record them.
- 2026-11-18, from #46 (merged at `2c3a5a9`): the gateway must call `trust_store.key_types()` to restrict the host-key algorithms it asks for, `check()` before sending any password, and `password_sent()` only after a password was really sent. Target: #49.
- 2026-11-18, from #46: the `trust-key` command should take the single-instance lock, and the CLI must map `FileNotFoundError` and `PreloadIsTrustStoreError` from `trust_store.load` to exit 2. Target: whichever ticket wires `trust-key` (#49 if none other does).
- 2026-11-18, from #46: no code checks that the Windows `trust\` folder is readable only by the operator (decided on #7). Opened as [#69](https://github.com/b-git-hub/network-analyser/issues/69), sub-issue of #46; built inside spec #37.
- 2026-11-18, from #46: choices awaiting the operator: OpenSSH-style parsing (hashed names, wildcards, `@revoked` counts as changed), and a key trusted in either the Trust Store or `--known-hosts` counts.
- 2026-11-18, from #45 (merged at `3586eab`): the secret scan learns the Backup Passphrase through a method on `BackupPassphrase` (in `backup_store`) that adds its `Secret` to the scan object in `credentials`, so the value never passes through records or the cli. #45 wired the passphrase into nothing yet. Target: #48.
- 2026-11-18, from #45: how `device_gateway` gets a Credential Set's password is open (it is private to `credentials` for now); choose a narrow handover that keeps it inside `credentials` + `device_gateway`. Targets: #49, #54.
- 2026-11-18, from #45: the passphrase must reach the locking worker. Target: #51.
- 2026-11-18, from #45: fold `check.notices` and `sets.views()` into the Run report. Target: #66.
- 2026-11-18, from #45: choices awaiting the operator: the first Run's passphrase entry also gets 3 tries; a non-y/n answer is asked again; "label matches a secret" means equal, not contains; usernames are stripped and escaped, not refused.
