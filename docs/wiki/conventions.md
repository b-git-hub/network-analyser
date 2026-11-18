# Wiki conventions

On 2026-11-18 the operator chose `docs/wiki/` in the repo as the wiki's home (asked in the session that built spec #37), over the GitHub repo wiki or an uncommitted scratchpad.

- `index.md` lists every page with a one-line summary, grouped by category.
- One page per thing: a decision, a recurring problem, a subsystem, a preference. Link related pages.
- Date every claim. Claims about code cite the commit they were true at, e.g. "As of `b-git-hub/network-analyser@abc1234`, ...". Never "currently" without a date.
- When something changes, add a new dated claim and mark the old one superseded; don't rewrite it.
- Never copy issue/PR bodies in; link them.
- Same rules as the repo: no real device data, no secrets, no personal details.
- Lint now and then: contradictions, orphan pages, missing links, claims newer sources have overtaken.
