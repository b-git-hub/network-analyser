# Wiki index

A dated, historical record kept by the coordinating (chief-of-staff) session and its subagents. Pages never describe "how things are now": every claim carries a date or a commit. Sources (issues, PRs, commits) are cited, never copied. See [conventions](conventions.md) before writing.

## Process
- [conventions](conventions.md): how this wiki is written and kept.
- [spec-37-handoff-2026-11-19](spec-37-handoff-2026-11-19.md): handoff state on 2026-11-19; superseded the same day: spec #37 merged in PR #67 and the operator reported it built and tested (2026-11-20).
- [implementing-spec-37](implementing-spec-37.md): how spec #37 is being built (branches, subagents, merge order), with a dated log.
- [implementer-brief](implementer-brief.md): the standing brief every ticket implementer follows.
- [spec-37-follow-ups](spec-37-follow-ups.md): work one ticket surfaced for a later one.
- [merger-brief](merger-brief.md): how a finished ticket branch is merged into the integration branch.
- [cloud-container-checks](cloud-container-checks.md): how to run the project's checks in a Linux cloud container (uv 0.13.9 shim).
- [usage-limits](usage-limits.md): 2026-11-18 rate limit stopped four implementers; how they were resumed and what to change.
- [agent-worktree-friction](agent-worktree-friction.md): known quirks of agent worktrees and how briefs work around them.
- [parallel-map-sessions](parallel-map-sessions.md): sessions working one map in parallel; re-read the map before recording a decision (2026-11-20).

## Decisions
- [spec-37-implementation-calls](spec-37-implementation-calls.md): 2026-11-18 calls on CI, uv packaging, secret holders and config sinks while building spec #37; 2026-11-19 calls on `diagram.drawio` (#65) and `run-report.html` (#66).
- [operator-wants-cml-build](operator-wants-cml-build.md): 2026-11-18 standing instruction to finish a CML-testable Windows build unattended.
- [delivery-one-draft-pr](delivery-one-draft-pr.md): spec #37 ships as one draft PR from the integration branch.

## Reference snapshots
- [spec-37-notes/architecture](spec-37-notes/architecture.md): module map, records, file formats, CLI (2026-11-18).
- [spec-37-notes/tickets](spec-37-notes/tickets.md): per-ticket files, blockers and collisions (2026-11-18).
- [spec-37-notes/environment](spec-37-notes/environment.md): what the Linux cloud container can and cannot verify (2026-11-18).
- [spec-37-notes/guardrails](spec-37-notes/guardrails.md): pit-of-success recommendations for #38 (2026-11-18).
