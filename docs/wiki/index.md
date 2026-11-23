# Wiki index

A dated, historical record kept by the coordinating (chief-of-staff) session and its subagents. Pages never describe "how things are now": every claim carries a date or a commit. Sources (issues, PRs, commits) are cited, never copied. See [conventions](conventions.md) before writing.

## Process
- [conventions](conventions.md): how this wiki is written and kept.
- [spec-37-handoff-2026-11-19](spec-37-handoff-2026-11-19.md): handoff state on 2026-11-19; superseded the same day: spec #37 merged in PR #67 and the operator reported it built and tested (2026-11-20).
- [implementing-spec-37](implementing-spec-37.md): how spec #37 is being built (branches, subagents, merge order), with a dated log.
- [implementer-brief](implementer-brief.md): the standing brief every ticket implementer follows.
- [spec-37-follow-ups](spec-37-follow-ups.md): work one ticket surfaced for a later one.
- [merger-brief](merger-brief.md): how a finished ticket branch is merged into the integration branch.
- [review-fixes-0.3.1-2026-11-22](review-fixes-0.3.1-2026-11-22.md): coordination page for #129 on 2026-11-22: base, collision plan, operator-only work, dated log.
- [review-fixes-implementer-brief-2026-11-22](review-fixes-implementer-brief-2026-11-22.md): the brief every #129 implementer follows on 2026-11-22.
- [review-fixes-merger-brief-2026-11-22](review-fixes-merger-brief-2026-11-22.md): how a #129 ticket PR is merged into `build/review-fixes-0.3.1`.
- [review-fixes-gate-baseline-2026-11-22](review-fixes-gate-baseline-2026-11-22.md): the 21 known Windows failures and the two intermittents at `6ce2cf9`.
- [pytest-temp-roots](pytest-temp-roots.md): how each pytest run, gate (#167) or direct (#193), gets a private temp root, and the false friends around it; 2026-11-23.
- [review-fixes-retro-2026-11-22](review-fixes-retro-2026-11-22.md): what went wrong in the #129 parallel build and the fixes (gate race, Log-tail conflicts, shell friction).
- [review-fixes-status-2026-11-22](review-fixes-status-2026-11-22.md): final state of the #129 build: `build/review-fixes-0.3.1` at `a6d7d19`, PR #195, gate counts, partial and operator-only tickets.
- [cloud-container-checks](cloud-container-checks.md): how to run the project's checks in a Linux cloud container (uv 0.13.9 shim).
- [usage-limits](usage-limits.md): 2026-11-18 rate limit stopped four implementers; how they were resumed and what to change.
- [agent-worktree-friction](agent-worktree-friction.md): known quirks of agent worktrees and how briefs work around them.

## Decisions
- [spec-37-implementation-calls](spec-37-implementation-calls.md): 2026-11-18 calls on CI, uv packaging, secret holders and config sinks while building spec #37; 2026-11-19 calls on `diagram.drawio` (#65) and `run-report.html` (#66).
- [run-end-online-wiring-2026-11-21](run-end-online-wiring-2026-11-21.md): 2026-11-21 order, secret wipe, NX-OS question handling, outages and Audit event shape for #104.
- [run-report-analysis-2026-11-21](run-report-analysis-2026-11-21.md): 2026-11-21 Run report summary, Needs attention, Critical/High table and Cisco notes for #110.
- [operator-wants-cml-build](operator-wants-cml-build.md): 2026-11-18 standing instruction to finish a CML-testable Windows build unattended.
- [delivery-one-draft-pr](delivery-one-draft-pr.md): spec #37 ships as one draft PR from the integration branch.

## Releases
- [release-0.3.1-2026-11-22](release-0.3.1-2026-11-22.md): release 0.3.1 (2026-11-22): the #129 review fixes, version and changelog, the no-breaking-change decision, and the gates it passed.
- [release-0.3.0-2026-11-21](release-0.3.0-2026-11-21.md): release 0.3.0 (2026-11-21): version, changelog, glossary and ADR amendments, and the gates it passed.
- [release-0.2.0-2026-11-21](release-0.2.0-2026-11-21.md): release 0.2.0 (2026-11-21): version, changelog, lab Device Role and checklist, and the gates it passed.

## Reference snapshots
- [config-facts](../config-facts.md): the secret-free config-fact vocabulary and the Checks that read it, for #96 and #100 (2026-11-21).
- [spec-37-notes/architecture](spec-37-notes/architecture.md): module map, records, file formats, CLI (2026-11-18).
- [spec-37-notes/tickets](spec-37-notes/tickets.md): per-ticket files, blockers and collisions (2026-11-18).
- [spec-37-notes/environment](spec-37-notes/environment.md): what the Linux cloud container can and cannot verify (2026-11-18).
- [spec-37-notes/guardrails](spec-37-notes/guardrails.md): pit-of-success recommendations for #38 (2026-11-18).
