# Retro: the #129 review-fix build, 2026-11-22

A dated record of what went wrong while running the review-fix build as parallel worktrees, and
what was changed. Commits are in `b-git-hub/network-analyser`.

## What went wrong

- **Parallel pytest runs raced on the shared temp link.** Eight gates at once crashed in
  `pytest_sessionfinish` with `PermissionError [WinError 5]` on
  `%TEMP%\pytest-of-<user>\pytest-current`, with no summary. First workaround was an env var;
  it failed until the directory was pre-created (`FileNotFoundError` at every setup). Fixed by
  #167 at `bf22e2b`: `scripts/check.py` creates a private `mkdtemp` root per invocation. Direct
  `pytest` / `pytest -m security` is still outside that fix and needs the env var.
- **Appending merge notes to one Log tail conflicted on every later merge.** #143 needed three
  forward merges for the same page. Fixed at `50aec9a`: merges write one file under
  `docs/wiki/review-fixes-log/`; a new file cannot conflict.
- **The integration branch moved under long tickets.** #155 merged the base forward five times;
  #142 and #153 had to absorb a moved tip before their PR could merge. The pattern that worked:
  implementers merge the tip once immediately before reporting; mergers run one at a time and
  stop on a conflict instead of hand-resolving another ticket's branch.
- **Shell friction.** `gh issue view <n> --comments` sometimes printed nothing; agents switched
  to `--json`. Inline `--jq` expressions were mangled by PowerShell quoting. A successful
  `git push` sometimes wrote to stderr and read as failure.
- **Attribution lines.** Several sessions had none in their system reminder, so commits carried
  just `Part of #<n>`. Consistent with the brief's rule not to copy another session's lines.

## What was changed

- `docs/wiki/review-fixes-implementer-brief-2026-11-22.md` and the merger brief gained the
  temp-root rule, the one-file merge log and the shell notes.
- `docs/wiki/review-fixes-gate-baseline-2026-11-22.md` pins the 21 Windows failures and the two
  intermittents.
- #167 is the code fix for the gate race; #187 is the release ticket; #164/#165 are the live
  Cisco checks and #132/#134/#142's lab items stay operator-only.

## What to try next build

- Give every worktree its own temp root by default (extend #167 to a pytest plugin or a
  `conftest.py` hook, not just `check.py`).
- Keep merge records out of any shared append-only page.
- Create the release ticket at the start, not after the feature queue, so its changelog scope is
  known while tickets are still writing entries.
- Record each implementer's report in a GitHub comment as well as returning it, so a later
  session can read the rationale without the coordinator's transcript.
