# Spec #37 handoff, 2026-11-19

> **Superseded 2026-11-20:** spec #37 is finished. [PR #67](https://github.com/b-git-hub/network-analyser/pull/67) merged to `main` on 2026-11-19 (`c28bb92`) and closed #37 and every spec ticket. The operator reported on 2026-11-20 that the build was done and tested. The rest of this page is the historical handoff state.

On 2026-11-19 at about 08:00 UTC the operator asked the building session to wrap up so another agent could finish spec #37. State at handoff, as of `b-git-hub/network-analyser@60edae7` plus this page's commit on `claude/lucid-shannon-8xewst`:

## Merged (20 of 29 spec tickets, plus #69)
#38–#53, #57, #58, #60, #63, and the extra security fix [#69](https://github.com/b-git-hub/network-analyser/issues/69). All checks pass (1362 tests). Draft PR: [#67](https://github.com/b-git-hub/network-analyser/pull/67).

## Unfinished work pushed as WIP branches (operator approved pushing them)
Committed as-is when the agents were stopped. Not reviewed; checks may fail. Each needs the integration tip merged in, then finishing with `tdd`.
- `wip/ticket-54` (`464c07d`): #54 Credential Set order, failure budget and probation. Stopped while writing visit tests.
- `wip/ticket-56` (`20312b5`): #56 Live progress, Ctrl+C and final summary. Stopped while writing crawl-stop tests (red first).
- `wip/ticket-59` (`27b7470`): #59 IOS/IOS-XE collection and parsers, the largest (22 files). It predates #60's `platforms.collect` seam, so it must be reshaped to plug into it. Its last note: lenient templates read junk as an empty table; it was making each table's header line required before an empty result counts as "none".

## Not started
- #65 `diagram.drawio` export (unblocked; an agent was started but had written nothing).
- #61 VLAN Mismatches and #62 L3 Adjacency, Subnets and MAC/ARP inference (unblocked; best after #59 so both Platforms' collection exists).
- #55 Opt-in Sweep (unblocked).
- #66 `run-report.html` (waits on #56).
- #64 Diagram: Routing and VLAN views, markers and Findings tab (waits on #61, #62).
- Then: code review of the integration branch, one fix pass, mark PR #67 ready.

## How to continue
1. Read [implementing-spec-37](implementing-spec-37.md) (method, task graph, log), [implementer-brief](implementer-brief.md), [merger-brief](merger-brief.md).
2. Read [spec-37-follow-ups](spec-37-follow-ups.md): each item names its target ticket; many target the unfinished ones.
3. Read [spec-37-implementation-calls](spec-37-implementation-calls.md) and the open operator questions (follow-ups marked "awaiting the operator").
4. In a fresh container, set up the checks first: [cloud-container-checks](cloud-container-checks.md) (uv 0.13.9 and CPython 3.14.10; the shim this session used is gone).
5. Expect the 5-hour usage limit to stop agents: see [usage-limits](usage-limits.md). Resume stopped agents rather than restarting them; plain `send_later` reminders can be held for hours while a limit is in force.
6. Fetch a WIP branch with `git fetch origin wip/ticket-<n>` and continue on `ticket/<n>-<slug>`.

## Open issues outside the spec
- [#68](https://github.com/b-git-hub/network-analyser/issues/68): masked reader drops `à` (operator decision needed).
