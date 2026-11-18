# Implementer brief (spec #37)

Written 2026-11-18 by the session building spec #37. Later edits are dated below the brief.


You implement ONE ticket of spec https://github.com/b-git-hub/network-analyser/issues/37. Read, in order:
1. /home/user/network-analyser/CLAUDE.md (security rules are non-negotiable), GLOSSARY.md, docs/adr/.
2. Your ticket on GitHub (GitHub MCP tools via ToolSearch: `mcp__github__issue_read`, owner b-git-hub, repo network-analyser), and any decision ticket/ADR it links that you need.
3. docs/wiki/index.md and the pages it points to, especially [spec-37-implementation-calls](spec-37-implementation-calls.md) and the snapshots in [spec-37-notes/](spec-37-notes/).
4. CODING_STANDARDS.md in the repo, once it exists. It wins over your habits.

## Branch rules
- Integration branch: `claude/lucid-shannon-8xewst`. Your worktree must start from its tip: `git fetch` is not needed (it is local); check `git merge-base --is-ancestor claude/lucid-shannon-8xewst HEAD`, and if false, `git reset --hard claude/lucid-shannon-8xewst`.
- Work on a local branch named `ticket/<number>-<slug>`. Do NOT push anything. Do NOT open PRs, close or comment on issues.
- Build with the Skill tool `tdd` (red-green-refactor) for any code. Docs-only tickets skip tdd.
- Tests must use synthetic, sanitised fixtures only: no real hostnames, IPs (use RFC 5737 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and RFC 3849 docs ranges), configs or secrets.
- Run git commands one per Bash call; chained `git ... && ...` commands may be refused in worktrees.
- Before reporting done: commit, then `git merge claude/lucid-shannon-8xewst` (the tip may have moved), resolve conflicts, re-run the full test suite and linters, commit.
- Commit messages end with:
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01MMsPzUaM28kjg5PjA69jtp
  Reference the ticket ("Part of #NN"); do not write "Closes".

## If something is wrong
- If the ticket, spec and notes disagree, the ticket wins; if the ticket itself conflicts with CLAUDE.md security rules, stop and report rather than guess.
- If you need something the environment can't give (Windows-only APIs, devices, pwsh), fake it behind a seam and say so in your report.
- If you had to work around tooling or a convention, say so: I fix the environment, not you.

## Report (≤10 lines)
Branch name, final commit sha, test/lint status, any deviation from the ticket, any follow-up work that should become a new issue, and any friction in the environment.
