# Review fixes for 0.2.0 / 0.3.0 (parent #129), 2026-11-22

Coordination page for the chief-of-staff session that started on 2026-11-22. The base is
`b-git-hub/network-analyser@6ce2cf9` (integration branch `build/review-fixes-0.3.1`,
refreshed from `main`; PRs #152, #161 and #163 had already merged). The parent ticket is
[#129](https://github.com/b-git-hub/network-analyser/issues/129); it remains the list of
children and their acceptance criteria. This page records the session's working order,
which tickets collide, and the dated state. It is not a replacement for a ticket.

## Where things are

- **Integration branch:** `build/review-fixes-0.3.1`, at `6ce2cf9` when this page was written.
  Ticket branches start from it and PR into it. `main` is never pushed to.
- **Ticket branches:** `ticket-<n>-<slug>`, one per ticket, one worktree each under
  `C:\Users\bmcb5\na-worktrees\`.
- **Implementer brief:** [review-fixes-implementer-brief-2026-11-22](review-fixes-implementer-brief-2026-11-22.md).
- **Merger brief:** [review-fixes-merger-brief-2026-11-22](review-fixes-merger-brief-2026-11-22.md).
- **Cisco reply shapes:** `docs/wiki/issue-148-handoff-2026-11-22.md` exists only on branch
  `ticket-148-shape-check` (read it with
  `git show origin/ticket-148-shape-check:docs/wiki/issue-148-handoff-2026-11-22.md`). It is
  cited by #165 and #166; do not copy reply values into any file.
- **Known gate baseline:** [review-fixes-gate-baseline-2026-11-22](review-fixes-gate-baseline-2026-11-22.md).

## State at start, 2026-11-22

Closed children: #130, #131, #132, #133, #134, #135, #137, #138, #141, #148, #162.
#142 is **partly delivered**: the type 5 IOS-XE decision is in code, `docs/config-facts.md`
and an `[Unreleased]` changelog entry. Four items remain, two code-only (legacy PAD/BOOTP
defaults; IOS-XE default vty transport) and two that need lab checks (CoPP on a blank reply,
K5; `% Invalid input`, K7 and L1).

Open children at `6ce2cf9`: #136, #139, #140, #142, #143, #144, #145, #146, #147, #149,
#150, #151, #153, #154, #155, #156, #157, #158, #159, #160, #164, #165, #166. #167 was
opened on 2026-11-22 for a parallel-gate temp-dir race found during Wave A.

Operator decisions already recorded: #142 type 5 on IOS-XE (2026-11-21, take the
recommendation); #145 make behaviour match ADR 0007, choosing option 3 or option 1 after
checking the condition (2026-11-21).

## Working order chosen on 2026-11-22

This is a **collision plan**, not a claim that every later ticket is blocked. Tickets that
share files are merged in the order shown. "Wave" means the work can start; merges stay
serial.

**Wave A (disjoint files, run in parallel):** #139, #140, #143, #144, #147, #158, #159, #166,
plus #167 (gate temp-dir race found during Wave A). Until #167 lands, every gate sets
`PYTEST_DEBUG_TEMPROOT` to a worktree-local path; see the gate baseline page.

**Wave B (start when the named file-owner has merged):**

- #136 and #146 after #139 (all touch `run_output/report.py` / `diagram/findings_report.py`).
  Merge order: #139, then #136, then #146.
- #151 and #157 after #147 (all touch `analysis/releases.py`). Merge order as listed.
- #149 after #166 (`tests/support/fake_cisco.py`).
- #153 after #166 (EoX/Suggestion reply handling), #154 after #153, #156 after #154
  (all reach `advisories/lookup.py` / `cli/run_analysis.py`).
- #160 after #144 (`tests/security/test_6_change_passphrase.py`).
- #155 after #143 (`cli/run_end.py`).
- #142 (remaining code items) after #159 (NX-OS/platform facts) and #149 (test fakes).
- #145 after #143 (`cmd_run.py`, Run-end scan lifecycle).

**Wave C:** #150 after everything it touches (it is a low-severity grab bag across proxy,
Cisco key, lifecycle, findings and trust folder); #165 after the operator's probe run and
match-rule decision; #164 is operator-only; the release ticket (patch bump + changelog) is
last on the integration branch.

## Operator-only work

- #164: remaining reply-shape probe runs (classic IOS, NX-OS, `NO_DATA_FOUND`), using the
  script on `ticket-148-shape-check`.
- #165: one probe run with a real release and OS, then the match-rule decision.
- #142: lab checks K5, K7 and L1 for the two items left.
- #132: proxy hand-check against a real proxy.
- #134: CML NX-OS 10.4(3) by-hand check.
- Final: approve and merge the single integration PR to `main`; version bump/changelog are
  on the integration branch, not in `main` before that PR.

## Log

- 2026-11-22: integration branch refreshed to `6ce2cf9`; coordination, implementer, merger
  and gate-baseline pages created. Wave A worktrees opened.
- 2026-11-22: a baseline gate run crashed at pytest session finish on the shared
  `pytest-current` link when several gates ran at once. #167 opened and Wave A agents told to
  set `PYTEST_DEBUG_TEMPROOT` per worktree.
- 2026-11-22: merged #139 at `a308ac2`; gate: ruff/format/mypy pass, pytest 2978 passed, 1
  skipped, 21 failed (all Windows baseline; #158 and #160 passed); baseline page's
  `test_an_account_that_can_only_read_the_folder_refuses_too` corrected to `test_another_...`.
- 2026-11-22: merged #167 at `bf22e2b`; gate: ruff/format/mypy pass, pytest 2980 passed, 1
  skipped, 21 failed (baseline), run plain with no `PYTEST_DEBUG_TEMPROOT`; the
  parallel-temp workaround is no longer needed from this merge commit.
- 2026-11-22: merged #144 at `51479c7`; gate: ruff/format/mypy pass, pytest 2983 passed, 1
  skipped, 21 failed (baseline); `change-passphrase` now leaves the change pending when
  `cisco-key.age` was not re-locked.
- 2026-11-22: merged #158 at `ab31b6b`; gate: ruff/format/mypy pass, pytest 2990 passed, 1
  skipped, 21 failed (baseline); all temp-then-rename writers now share
  `_winsys/rename.retry_rename`, so the intermittent is covered (ticket closed).
- 2026-11-22: merged #140 at `4c691c4`; gate: ruff/format/mypy pass, pytest 2997 passed, 1
  skipped, 21 failed (baseline); every Cisco insecure-list entry now names a shipped Check id,
  enforced by a test that refuses stale ids.
- 2026-11-22: merged #166 at `3449b7b`; gate: ruff/format/mypy pass, pytest 3005 passed, 1
  skipped, 21 failed (baseline); per-PID EoX/Suggestion error shapes are read as Cisco sends
  them, and `tests/support/fake_cisco.py` now carries those shapes, so #149 and #153 build on
  them.
- 2026-11-22: **#176 blocked, not merged.** PR #176 (`ticket-147-train-coverage`, ticket #147)
  is `CONFLICTING` on `CHANGELOG.md` only: #147 adds one Changed and one Fixed bullet under
  `[Unreleased]`, and #139 (merged at `a308ac2`) added a bullet at the same anchor at the top
  of `### Fixed`. The ticket branch forks at `5a77989`, before #139. No merge was attempted,
  nothing was forced or rewritten, and no gate was run. The coordinator decides whether the
  #147 owner rebases forward onto the current integration tip and re-runs the gate.
- 2026-11-22: **#175 blocked, not merged.** PR #175 (`ticket-143-run-end-durability`, ticket
  #143) is `CONFLICTING` on `docs/wiki/review-fixes-0.3.1-2026-11-22.md` only, the Log tail:
  both sides append dated lines after the #158 entry, so #143's line (added after the branch
  merged `dbbe12f`) collides with the #140, #166 and #176 lines that landed on the integration
  branch since its merge base `538604e`. `git merge-tree` names no other conflicting file. No
  merge was attempted, nothing was forced or rewritten, and no gate was run; PR #177 (ticket
  #160, `MERGEABLE`) was left unmerged because it is second in this batch's order. The
  coordinator decides whether the #143 owner rebases forward onto `e625f25` and re-runs the
  gate.
- 2026-11-22: merged #160 at `25f2f55`; gate: ruff/format/mypy pass, pytest 3005 passed, 1
  skipped, 21 failed (baseline); security test 6's autouse fixture fakes the crash-dump
  registry, so its result no longer depends on this PC's `LocalDumps`/`AeDebug` settings, and
  it passed inside the full run (ticket closed). #158's intermittent also passed.
- 2026-11-22: merged #147 at `36b09ef`; gate: ruff/format/mypy pass, pytest 3031 passed, 1
  skipped, 21 failed (baseline); the Train classifier covers every published Train from 16.6
  by rule and a controller-managed IOS XE SD-WAN device is never matched as IOS-XE. The
  earlier `CHANGELOG.md` conflict was resolved by #147's owner on the branch (merge forward
  at `d5d7001`) before this merge; nothing was resolved by the merger.
- 2026-11-22: **#175 blocked again, not merged.** PR #175 (`ticket-143-run-end-durability`,
  ticket #143, head `2dc5a2b`) is `CONFLICTING` on `docs/wiki/review-fixes-0.3.1-2026-11-22.md`
  only: both sides append dated lines after the same Log tail, and the integration branch has
  gained the #140, #166, #176 and #147 entries since its base. `git merge-tree` names no other
  conflicting file. No merge was attempted, nothing was forced or rewritten, and no gate was
  run. #143's owner needs to rebase forward onto this tip and re-run the gate.
