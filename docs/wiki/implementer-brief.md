# Implementer brief (spec #37)

Written 2026-11-18 by the session building spec #37. Later edits are dated below the brief.


You implement ONE ticket of spec https://github.com/b-git-hub/network-analyser/issues/37. Read, in order:
1. /home/user/network-analyser/CLAUDE.md (security rules are non-negotiable), GLOSSARY.md, docs/adr/.
2. Your ticket on GitHub (GitHub MCP tools via ToolSearch: `mcp__github__issue_read`, owner b-git-hub, repo network-analyser), and any decision ticket/ADR it links that you need.
3. docs/wiki/index.md and the pages it points to, especially [spec-37-implementation-calls](spec-37-implementation-calls.md) and the snapshots in [spec-37-notes/](spec-37-notes/).
4. CODING_STANDARDS.md in the repo, once it exists. It wins over your habits.

## Branch rules
- Integration branch: `claude/lucid-shannon-8xewst`. Your worktree is fresh and usually starts behind its tip, so make your first Bash call, alone: `git reset --hard claude/lucid-shannon-8xewst`. (Added 2026-11-18 after the #38 retro.)
- Work on a local branch named `ticket/<number>-<slug>`. Do NOT push anything. Do NOT open PRs, close or comment on issues.
- Build with the Skill tool `tdd` (red-green-refactor) for any code. Docs-only tickets skip tdd.
- Tests must use synthetic, sanitised fixtures only: no real hostnames, IPs (use RFC 5737 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and RFC 3849 docs ranges), configs or secrets.
- Run git commands one per Bash call; chained `git ... && ...` commands may be refused in worktrees.
- Checks: from your worktree root run `uv sync --locked --no-build`, then `uv run --locked python scripts/check.py` (all must pass). `uv` on PATH is a shim, see [cloud-container-checks](cloud-container-checks.md). Create or overwrite files with the Write tool, never with heredocs in Bash; use Bash only to run things.
- In a Bash call whose text mentions git anywhere (a `git` command, `.gitignore`, `github.com`), use no `$` expansion (`$?`, `$VAR`, `$(...)`, loop variables): the worktree guard refuses it. Run git alone and read the exit code from the result. (Root cause found by the #38 retro, 2026-11-18.)
- Read [spec-37-follow-ups](spec-37-follow-ups.md) for items targeted at your ticket.
- Before reporting done: commit, then `git merge claude/lucid-shannon-8xewst` (the tip may have moved), resolve conflicts, re-run the full test suite and linters, commit.
- Commit messages end with the attribution lines from your own session's system reminder (they name the model that actually ran you; don't copy another agent's). Changed 2026-11-18 after a Sonnet merger noticed the hard-coded Opus line.
  Reference the ticket ("Part of #NN"); do not write "Closes".

## If something is wrong
- If the ticket, spec, notes and your prompt disagree, the ticket wins (and closed decision tickets win over your prompt); if the ticket itself conflicts with CLAUDE.md security rules, stop and report rather than guess.
- If you need something the environment can't give (Windows-only APIs, devices, pwsh), fake it behind a seam and say so in your report.
- If you had to work around tooling or a convention, say so: I fix the environment, not you.

## Report (≤10 lines)
Branch name, final commit sha, test/lint status, any deviation from the ticket, any follow-up work that should become a new issue, and any friction in the environment.
