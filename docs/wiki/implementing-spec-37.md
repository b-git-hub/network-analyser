# Implementing spec #37

How [spec #37](https://github.com/b-git-hub/network-analyser/issues/37) (Network Analyser v1) is being built. Decision on delivery: [delivery-one-draft-pr](delivery-one-draft-pr.md).

## Method (2026-11-18)
- Follows the mattpocock `implement-spec` procedure: the 29 tickets #38–#66 form a task graph (GitHub "blocked by" edges); the coordinator keeps a frontier of ready tickets and runs one fresh implementer subagent per ticket in its own git worktree, building with `tdd`.
- A merger subagent merges each finished ticket branch into the integration branch, one at a time, and pushes.
- Every implementer follows [implementer-brief](implementer-brief.md).
- About one in five implementer sessions gets a retro; findings go into this wiki and into repo guardrails.

## Task graph (from ticket bodies, 2026-11-18)
- Roots: #38 skeleton, #39 CML lab, #40 doc conflicts.
- #38 → #41, #42, #43, #44. #42 → #46. #44 → #47. #41+#42+#43 → #45. #42+#45 → #48. #46+#48 → #49 (tracer bullet).
- #49 → #50, #51, #52, #53. #50 → #54, #55, #56. #51 → #57, #58. #52 → #59, #60, #61, #62, #63.
- #61+#62+#63 → #64. #63 → #65. #51+#52+#56 → #66.

## Log
- 2026-11-18: started #39 and #40 (no code dependencies); exploration agent writing module map, ticket collision map, environment limits and guardrail recommendations for #38.
- 2026-11-18: merged #40 at `4bad923`; docs-only (GLOSSARY.md, ADR 0003), no conflicts, no tests or linters defined yet.
