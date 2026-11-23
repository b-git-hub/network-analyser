# #129 review-fix build: final state, 2026-11-22

Final state of the #129 review-fix build on 2026-11-22. Every claim is true at
`b-git-hub/network-analyser@a6d7d19` on `build/review-fixes-0.3.1`, the head of PR #195. The
operator owns the merge, the tag, the GitHub Release and `build.ps1`; none of those were done by
this session.

**Superseded for #142 and #165 on 2026-11-23** by
[the closeout page](review-fixes-closeout-2026-11-23.md); everything else here still stands.

## Integration branch and PR

- **Branch:** `build/review-fixes-0.3.1`, latest sha `a6d7d19`, 106 commits ahead of
  `origin/main` when checked on 2026-11-22. `a6d7d19` adds only the merge-log file;
  `0176c82` before it merged #194 for #187, the release ticket.
- **PR:** [b-git-hub/network-analyser#195](https://github.com/b-git-hub/network-analyser/pull/195),
  base `main`, head `build/review-fixes-0.3.1`, `OPEN`, `MERGEABLE`, 100 commits (checked
  2026-11-22). It is the single integration PR for the whole build.
- Ticket branches were `ticket-<n>-<slug>`, one per ticket, each PR'd into the integration
  branch. `main` was never pushed to.

## Gates

Measured at `0176c82`; `a6d7d19` is docs-only, so the counts still hold.

- `uv run --locked python scripts/check.py`: ruff format, ruff lint and both mypy runs pass;
  pytest ends `21 failed, 3219 passed, 1 skipped in 107.67s`. The 21 failures are exactly the
  known Windows ACL, `socketpair` and package-build node ids in the
  [gate baseline](review-fixes-gate-baseline-2026-11-22.md), and both intermittents (#158, #160)
  passed.
- Security: `250 passed` (`pytest -m security`, 2991 deselected).
- Release gate: `uv run --locked python -m scripts.release_gate check --tag v0.3.1` reports
  `Release gate passed for v0.3.1 (CHANGELOG.md entry dated 2026-11-22).`
- `scripts.lab_roles --check`: exit 0, no rewrite (see the
  [0.3.1 release page](release-0.3.1-2026-11-22.md)).

## Delivered on this branch

Every ticket below has one file under [review-fixes-log](review-fixes-log/README.md) naming its
merge sha and one notable fact. Closed before this build, in the base: #130, #131, #132, #133,
#134, #135, #137, #138, #141, #148, #162 (per the
[coordination page](review-fixes-0.3.1-2026-11-22.md)).

Merged 2026-11-22, oldest first: #139 `a308ac2`, #167 `bf22e2b`, #144 `51479c7`, #158 `ab31b6b`,
#140 `4c691c4`, #166 `3449b7b`, #160 `25f2f55`, #147 `36b09ef`, #143 `f2037f6`, #159 `b594764`,
#136 `29a017d`, #153 `bf0279c`, #151 `68f3a73`, #145 `81158d2`, #154 `ba5df92`, #157 `e42f1b4`,
#142 `eb134b8` (partial), #156 `a33227a`, #155 `6234c0a`, #165 `cd08bed` (partial),
#149 `9dce106`, #146 `b143141`, #150 `c03aff1`.

The release is #187 in PR #194, merged `0176c82`: version 0.3.1, the changelog entry, breaking
changes `None.`, no allow-list or Device Role change.

## Partly delivered, still open

- **#142** (partial, `eb134b8`): all four remaining code items landed — legacy PAD/BOOTP
  default-on for IOS/IOS-XE, IOS-XE Telnet vty transport confirmed and documented, a blank CoPP
  reply read as no policy, and `% Invalid input` reworded to name both causes. The lab checks
  **K5, K7, L1 and L7** remain operator verification, so the ticket stays open.
- **#165** (partial, `cd08bed`): Cisco's query form, separate EoX sources and the safe fallback
  landed. The operator probe with a real release and OS, the **match-rule decision** and the
  **NX-OS OSType** item remain.

## Operator-only

- **#164:** the remaining reply-shape probe runs (classic IOS, NX-OS, `NO_DATA_FOUND`), with the
  script on `ticket-148-shape-check`.
- **#132** (closed in code): proxy hand-check against a real proxy.
- **#134** (closed in code): CML NX-OS 10.4(3) by-hand check.
- **#150** (closed): the `_winsys` registry read stays a by-hand check, like every other
  registry check.

## Follow-ups opened

- [#192](https://github.com/b-git-hub/network-analyser/issues/192): parse WinINET `AutoDetect`
  (WPAD) is unwritten — the binary `DefaultConnectionSettings` needs a Windows parser and a
  hand-check; #150 documents it as ignored in `_winsys/proxy.py`.
- [#193](https://github.com/b-git-hub/network-analyser/issues/193): direct `pytest` runs still
  race on the shared `pytest-current` temp link; #167 fixed only `scripts/check.py`. See the
  [retro](review-fixes-retro-2026-11-22.md).

## What the operator owns

Merge PR #195, then on merged `main` run `build.ps1`, tag `v0.3.1` and publish the GitHub
Release per [docs/releasing.md](../releasing.md), and run the open CML/live checks above. No
merge, tag, release, `main` push or close of #129 happened in this session.

## Links

- [Coordination page](review-fixes-0.3.1-2026-11-22.md)
- [Retro](review-fixes-retro-2026-11-22.md)
- [Gate baseline](review-fixes-gate-baseline-2026-11-22.md)
- [0.3.1 release page](release-0.3.1-2026-11-22.md)
- [Merge log](review-fixes-log/README.md)
