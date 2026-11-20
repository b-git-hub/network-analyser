# Parallel sessions on one map

Wayfinder maps are worked by several sessions at once. A decision closed in one session can change what another is deciding.

- 2026-11-20: while [How Findings are presented](https://github.com/b-git-hub/network-analyser/issues/82) was being prototyped, [Which configuration, lifecycle and consistency Checks ship](https://github.com/b-git-hub/network-analyser/issues/81) closed in another session. It settled a four-level scale with no Info, and moved Advisories from CSAF to openVuln with Cisco's SIR. The operator had just picked Info for "VLAN on one end only", which conflicted. The session caught this only because it re-read the map before recording. It asked again, and the operator chose Low, shown softer.
- Lesson: re-read the map, and any closed sibling ticket the decision depends on, **after** the human answers and **before** posting the resolution. Raise any conflict with the human; don't silently pick one side.
- Prototypes from prototype tickets live only on their session branch. The PR that merges that branch removes the prototype from the tree, so main keeps only the decision. The prototype stays in history at the commit the ticket links to. For #82 that commit is `5c223e1`.
