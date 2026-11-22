# Implementer brief: review fixes 0.2.0 / 0.3.0, 2026-11-22

You implement ONE child of [#129](https://github.com/b-git-hub/network-analyser/issues/129).
Your prompt names the ticket and your worktree. Read, in this order, from your worktree:

1. `CLAUDE.md` at the worktree root. It is newer than the copy injected into a session that
   started on an old checkout: it contains the **Git workflow** section (PR-only, one ticket
   one branch one PR, never push `main`). Its security rules are non-negotiable.
2. `CODING_STANDARDS.md` (section 7 is red-green), `GLOSSARY.md`, and any ADR the ticket links.
3. `docs/wiki/index.md`, then
   [review-fixes-0.3.1-2026-11-22](review-fixes-0.3.1-2026-11-22.md) (collision plan and
   operator-only items) and, for Cisco reply work, the #148 handoff page named there.
4. Your ticket: `gh issue view <n> --comments`. The ticket wins over this brief; a closed
   decision ticket wins over your prompt. If the ticket conflicts with CLAUDE.md security
   rules, stop and report.

## Branch and worktree

- Work only in the worktree given in your prompt, on the branch already checked out.
  First run `git status -sb` and `git log -1 --oneline`; confirm clean and based on
  `build/review-fixes-0.3.1` at `6ce2cf9` or later. Do not touch other worktrees or the main
  checkout. Never check out or push `main`.
- Branch name: `ticket-<n>-<slug>` (already created). One ticket, one branch, one PR.
- Windows PowerShell 5.1: no `&&`. Run git commands one per shell call.

## Build

- Use the `tdd` skill for code (red-green-refactor). Docs-only tickets skip it.
- Build with synthetic fixtures only: RFC 5737 addresses, `sw-a`-style hostnames, synthetic
  PIDs/serials, `CANARY-...` secrets. No real device data, no real Cisco replies, no
  passwords, no Backup Passphrase, no Cisco API Key.
- The tool stays read-only and the allow-list does not change. No new show command, no
  Device Role change. Do not go online.
- Gate, from the worktree root: `uv run --locked python scripts/check.py`. The first run
  syncs the environment and takes several minutes; let it finish. Pass means ruff format,
  ruff lint and both mypy runs pass, and pytest's only failures are the known Windows
  ACL/`socketpair`/package-build baseline in
  [review-fixes-gate-baseline-2026-11-22](review-fixes-gate-baseline-2026-11-22.md). A new
  failure is yours to fix.
- **Until [#167](https://github.com/b-git-hub/network-analyser/issues/167) lands**, several
  gates run at once on this PC and race on pytest's shared temp link. In the same PowerShell
  session, before the gate:

  ```powershell
  $root = Join-Path $env:TEMP ('na-pytest-' + (Split-Path $PWD -Leaf))
  New-Item -ItemType Directory -Force -Path $root | Out-Null
  $env:PYTEST_DEBUG_TEMPROOT = $root
  ```

  The directory must already exist, or pytest fails at setup with `FileNotFoundError
  [WinError 3]`. A `PermissionError ... pytest-current` at session finish is the race, not
  your ticket; set the variable and rerun. Do not commit the temp directory.
- If you must work around tooling or a convention, say so in your report; the environment is
  fixed, not the agent.

## Shell notes

- If `gh issue view <n> --comments` prints nothing in this shell, use
  `gh issue view <n> --json number,title,body,comments` or
  `gh api repos/b-git-hub/network-analyser/issues/<n>` and read the JSON.
- Inline `--jq` expressions are sometimes mangled by PowerShell quoting. Prefer `--json` plus
  `ConvertFrom-Json`, or a small `.ps1` file.
- A successful `git push` can write to stderr and look like a failure. Verify with
  `git status -sb` or `git ls-remote --heads origin <branch>`; an identical retry is safe.
- Direct `pytest` (not `scripts/check.py`) still shares the temp root. Set an existing private
  `PYTEST_DEBUG_TEMPROOT` before it; see the gate baseline page.

## Finish

1. Commit on your branch. Message: reference the ticket ("Part of #<n>"), not "Closes", plus
   the attribution lines from your own session's system reminder.
2. `git push -u origin <branch>`.
3. Open the PR into the integration branch:
   `gh pr create --base build/review-fixes-0.3.1 --head <branch> --title "<ticket title>" --body "<body>"`.
   The body lists the ticket, what changed, the gate result with pytest counts, risks,
   and any follow-up that should become a new issue.
4. Do **not** merge the PR, and do not close the issue. A merger does both after its own
   check.
5. Report in ten lines or fewer: branch, final sha, PR URL, gate counts, any deviation from
   the ticket, follow-ups, friction. Then stop.

## Collisions

The coordination page lists which tickets share files and the merge order. If your ticket
needs a file another open ticket owns, say so in the PR body instead of widening the change.
Do not resolve another ticket's work.
