# Spec #37 follow-ups carried between tickets

Work that a finished ticket surfaced for a later ticket. The coordinator copies each item into that later ticket's implementer prompt and strikes it here, dated, once merged.

- 2026-11-18, from #39 (merged at `2c4c9e3`): when #53 (`role-snippet`) lands, replace the lab file's provisional hand-written `netanalyser` Device Role with `role-snippet` output. Target: #53.
- 2026-11-18, from #39: the fixture-hygiene test (planned in [guardrails](spec-37-notes/guardrails.md)) should also scan `lab/`, allowing the three RFC 5737 ranges and requiring every secret to be `CHANGE_ME`. Target: #38 if still open, otherwise the next ticket that touches tests.
~~- 2026-11-18, from #39: the lab checklist reads "nothing captured is committed" as allowing SSH identification strings and command syntax to be quoted in results. Awaiting the operator's confirmation.~~ Resolved 2026-11-18: the operator confirmed that reading is fine.
