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
