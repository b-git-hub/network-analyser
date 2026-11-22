# Merger brief: review fixes 0.2.0 / 0.3.0, 2026-11-22

A merger merges one gated ticket PR into `build/review-fixes-0.3.1`. One merger runs at a
time. The operator, not the merger, merges anything into `main`.

Read, from the integration worktree (`C:\Users\bmcb5\na-worktrees\coord`):
`CLAUDE.md` (Git workflow), the ticket, and
[review-fixes-0.3.1-2026-11-22](review-fixes-0.3.1-2026-11-22.md) (merge order).

## Procedure

1. Confirm the PR targets `build/review-fixes-0.3.1`, its ticket is open, and its body
   records a passing gate. Run `gh pr view <pr> --json mergeable,mergeStateStatus,baseRefName`.
2. Merge with `gh pr merge <pr> --merge` (a merge commit; no squash, no rebase). If GitHub
   reports a conflict, stop and report which files collide; do not force, rebase or rewrite
   a ticket branch. The coordinator decides whether the ticket is rebased forward by its
   owner.
3. Fetch and check out the new integration tip in the integration worktree
   (`git fetch origin`, `git merge --ff-only origin/build/review-fixes-0.3.1`). If the
   worktree has uncommitted changes, stop and report.
4. Run the full gate: `uv run --locked python scripts/check.py`. Pass means ruff, format and
   mypy pass, and pytest's failures stay within the known baseline plus any known
   intermittent ticket (#158, #160) that is still open. A new failure: report it, do not
   paper over it. Fix forward only if the merge itself broke a mechanical thing (import
   ordering, generated lab role).
5. Close the ticket with
   `gh issue close <n> --comment "Delivered on build/review-fixes-0.3.1 at <merge sha>"`.
   If the ticket is explicitly partial (for example #142), do not close it; comment what
   landed.
6. Record the merge in a NEW file under `docs/wiki/review-fixes-log/`, named
   `YYYY-MM-DD-<ticket>-<short-sha>.md`, containing one dated line
   ("2026-MM-DD: merged #<n> at `<sha>`; gate: <counts>; <one notable fact>"). Do not append to
   the old Log tail in the coordination page: one shared tail conflicts on every later ticket.
   Commit the new file on the integration branch and push. Do not push `main`.
7. Report in five lines or fewer: merge sha, gate counts, ticket closed or left open,
   anything fixed or refused.
