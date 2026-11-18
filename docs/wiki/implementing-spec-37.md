# Implementing spec #37

How [spec #37](https://github.com/b-git-hub/network-analyser/issues/37) (Network Analyser v1) is being built. Decision on delivery: [delivery-one-draft-pr](delivery-one-draft-pr.md).

## Method (2026-11-18)
- Follows the mattpocock `implement-spec` procedure: the 29 tickets #38–#66 form a task graph (GitHub "blocked by" edges); the coordinator keeps a frontier of ready tickets and runs one fresh implementer subagent per ticket in its own git worktree, building with `tdd`.
- A merger subagent merges each finished ticket branch into the integration branch, one at a time, and pushes.
- Every implementer follows [implementer-brief](implementer-brief.md).
- (Added 2026-11-18 after the #38 retro, which found about 45 of its 149 calls wasted.) Dispatch a ticket only after the wiki pages its brief names are committed on the integration tip. Implementer prompts add nothing that a closed decision ticket already settles; the #38 prompt asked for CI and a src layout that #28/#32 had ruled out.
- About one in five implementer sessions gets a retro; findings go into this wiki and into repo guardrails.

## Task graph (from ticket bodies, 2026-11-18)
- Roots: #38 skeleton, #39 CML lab, #40 doc conflicts.
- #38 → #41, #42, #43, #44. #42 → #46. #44 → #47. #41+#42+#43 → #45. #42+#45 → #48. #46+#48 → #49 (tracer bullet).
- #49 → #50, #51, #52, #53. #50 → #54, #55, #56. #51 → #57, #58. #52 → #59, #60, #61, #62, #63.
- #61+#62+#63 → #64. #63 → #65. #51+#52+#56 → #66.

## Log
- 2026-11-18: started #39 and #40 (no code dependencies); exploration agent writing module map, ticket collision map, environment limits and guardrail recommendations for #38.
- 2026-11-18: merged #40 at `4bad923`; docs-only (GLOSSARY.md, ADR 0003), no conflicts, no tests or linters defined yet.
- 2026-11-18: operator went AFK asking for a CML-testable build; started #38 before exploration notes landed so the frontier keeps moving.
- 2026-11-18: merged #39 at `2c4c9e3`; lab file and checklist only, no conflicts; yamllint not installed, so the YAML was only checked to parse (all secrets in it are CHANGE_ME placeholders).
- 2026-11-18: merged #38 at `fc2a616`; no conflicts; first merge with tests and linters: `uv run --locked python scripts/check.py` (ruff format, ruff lint, mypy strict for Linux and win32, pytest) all green, 128 tests passed.
- 2026-11-18: 12:40–15:30 UTC the 5-hour usage limit stopped implementers #41–#44 mid-ticket; resumed at 15:37 with SendMessage. See [usage-limits](usage-limits.md).
- 2026-11-18: merged #43 at `9b7dcc5`; no conflicts, check.py all green, 160 tests passed.
- 2026-11-18: merged #41 at `4bf7aa7`; no conflicts despite #43 landing in cli/ first, check.py all green, 258 tests passed.
- 2026-11-18: merged #42 at `f5617ad`; no conflicts, check.py all green, 346 tests passed.
- 2026-11-18: wave 2 started: #45 and #46 (after #41, #42, #43 merged); #44 still running.
- 2026-11-18: merged #44 at `ad98071`; no conflicts, check.py all green, 372 tests passed; adds default `build` dependency group (PyInstaller).
- 2026-11-18: merged #46 at `2c3a5a9`; no conflicts, check.py all green, 403 tests passed.
- 2026-11-18: merged #45 at `3586eab`; no conflicts, check.py all green, 459 tests passed.
- 2026-11-18: merged #69 at `671ed95`; no conflicts, check.py all green, 475 tests passed.
- 2026-11-18: merged #47 at `b428a5e`; no conflicts, check.py all green, 498 tests passed; adds release workflow, release_gate.py and CHANGELOG.md (no tags pushed).
- 2026-11-18: the 5-hour usage limit hit again at about 16:30 UTC, stopping #48's implementer and #47's merger (which had already merged and pushed `b428a5e`). At 20:31 UTC the operator-requested reminder fired; #48 resumed with SendMessage; checks re-run on the tip (498 passed).
- 2026-11-18: merged #48 at `a1d294e`; no conflicts, check.py all green, 561 tests passed; adds audit log, secret scan and redaction layer.
- 2026-11-18: merged #49 at `994678340c2f`; no conflicts, check.py all green, 827 tests passed; adds SSH seed login, Platform identification, allow-list gate and trust-key command.
