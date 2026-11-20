# Choosing models for subagents

On 2026-11-20 the operator asked for coordinators to use cheaper models where they fit, to save cost. The rules live in `CLAUDE.md` ("Choosing models for subagents"). This page records why they are what they are.

## Evidence from building spec #37 (2026-11-18 to 2026-11-19)
- **Opus** ran every implementer (tickets #38–#69), the exploration agent, the #38 retro, and the first three mergers. Each implementer took 60–180 tool calls and 200–470k tokens. Their most valuable output was judgement the tickets did not spell out: #69 (trust-folder ACL gap), #68 (the `à` bug), `show running-config view full`, planted-violation checks of the security tests, a crash at every write in #58, refusing weak SSH ciphers. See [spec-37-follow-ups](spec-37-follow-ups.md).
- **Sonnet** ran about 17 mergers from #43 on, all clean (merged, checked, pushed, logged). One noticed the brief's hard-coded attribution line was wrong.
- **Not tested:** Sonnet or Haiku as an implementer. The Sonnet tier for non-security tickets is a reasoned guess, not a measurement.
- The usage limit stopped work three times with four or five Opus agents running, and a Sonnet merger was stopped by the same limit. That points to one shared budget, but this is not confirmed. See [usage-limits](usage-limits.md).

## Why the split is by risk, not by planning versus coding
The guardrails (strict ruff and mypy, arch tests, security tests, `CODING_STANDARDS.md`) catch most mistakes in well-specified code, so a cheaper model fits there. They cannot catch a security behaviour that no test describes yet. In the security-core modules, finding that gap is the job, so those tickets stay on Opus.

## Wayfinder research tickets (2026-11-20)
The operator confirmed that `wayfinder:research` tickets run on Opus. They end in a decision that later work builds on (ADRs, the spec), so weighing sources and spotting conflicts is the job. An Opus research agent may hand pure page fetching and summarising to Sonnet helpers, but it reads the primary sources behind any claim the decision rests on.

## How to revise
- First trial suggested: give #65 (`diagram.drawio`) to Sonnet, run `code-review`, and compare against an Opus ticket of similar size. Record the result here, dated.
- Move a role down a tier only with evidence like that. Move a role up after a failure, and say which ticket failed.
