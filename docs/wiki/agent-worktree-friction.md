# Agent worktree friction

Observed while building spec #37 (see [implementing-spec-37](implementing-spec-37.md)).

- 2026-11-18, ticket #40's implementer: the worktree that `isolation: worktree` created was **not** based on the integration branch tip. The [implementer-brief](implementer-brief.md)'s ancestor check plus `git reset --hard claude/lucid-shannon-8xewst` caught it. Keep that check in the brief.
- 2026-11-18, same report: inside the worktree, Bash calls that chained `git` with `&&` or `;` were refused, so git commands had to run one per call. The briefs now say so up front.
- 2026-11-18: worktrees live in `.claude/worktrees/` inside the main checkout and showed up as untracked files; `.gitignore` ignores that folder since commit after `f7e95a2`.
- 2026-11-18, ticket #38's implementer: the worktree again started behind the integration tip; the reset fixed it. Bash calls containing `cd`, heredocs, or even text like `.gitignore` were sometimes refused as "too complex"; it used the Write tool and helper scripts instead. Briefs now suggest writing helper scripts to the scratchpad for multi-step shell work.
- 2026-11-18: uv/Python mismatch in the container, see [cloud-container-checks](cloud-container-checks.md).
