# Merger brief

Written 2026-11-18 by the session building spec #37. A merger subagent merges one finished ticket branch into the integration branch.

1. Work in the main checkout `/home/user/network-analyser`, on `claude/lucid-shannon-8xewst`. Check `git status` is clean first; if not, stop and report.
2. `git merge --no-ff ticket/<n>-<slug>` with a message "Merge ticket #<n>: <title>" plus "Part of #<n>" and the attribution lines from [implementer-brief](implementer-brief.md).
3. On conflict: resolve only if it is mechanical (both sides' intent is clear from the two tickets); otherwise `git merge --abort` and report.
4. Run the full test suite and every linter the repo defines (see CODING_STANDARDS.md / pyproject.toml once they exist). If anything fails, fix only what the merge broke; if a ticket's own work is broken, `git reset --hard ORIG_HEAD` and report.
5. Append one dated line to the Log in [implementing-spec-37](implementing-spec-37.md) ("2026-MM-DD: merged #<n> at `<sha>`; <one notable fact, if any>"), commit it, then `git push origin claude/lucid-shannon-8xewst` (retry network errors up to 4 times with backoff).
6. Report in ≤5 lines: merge sha, test/lint status, anything you fixed or refused.

Run git commands one per Bash call; chained `git ... && ...` commands may be refused.
