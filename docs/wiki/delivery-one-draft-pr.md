# Spec #37 ships as one draft PR

On 2026-11-18 the operator decided that all of [spec #37](https://github.com/b-git-hub/network-analyser/issues/37)'s tickets (#38–#66) are built on one integration branch, `claude/lucid-shannon-8xewst`, and reach `main` through a single draft PR that closes the spec and every ticket. Tickets close when the operator merges it. This matches how earlier work closed (PRs #34–#36).

The integration branch is the only branch the building session may push to; ticket branches (`ticket/<n>-<slug>`) stay local to the session's worktrees.

See [implementing-spec-37](implementing-spec-37.md).
