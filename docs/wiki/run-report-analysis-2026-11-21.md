# Run report and Analysis (#110), 2026-11-21

Built on 2026-11-21 on branch `ticket-110-run-report`, at the commit ending `(#110)`.
Code: `run_output/report.py`. No report input was added to `RunReport`; the page reads the
Findings and `cisco_lookups` the Run already puts on the Topology.

## What the page shows

- **Summary:** Visited, Unvisited, the total Findings, then one count per level, worst
  first. It counts every Finding the Run holds, v1's Topology Findings included.
- **Needs attention:** the existing notices and `RunReport.attention` lines first, then one
  line per "could not check" Advisory Finding and one per "Device Role out of date" Finding,
  then the secret-scan warning, then, always last, `N Critical Findings from M Checks — see
  the Findings report`. The Critical line is present on a clean Run too, so the section never
  says "Nothing needs your attention" once Analysis has run.
- **Findings:** the Finding and Check counts, then the Critical and High Checks, one row per
  level and Check (a Check whose Findings differ in level appears under each), worst level
  first and then the most devices hit. The table stops at 10 rows and says how many it left
  out. It links `findings.html`; no per-Finding text is repeated from that report.
- **Cisco notes:** "Medium and Low Advisories are not listed." and "openVuln covers NX-OS
  only from July 2019." always; "Cisco's data was fetched over TLS and not
  signature-checked." only when `cisco_lookups.ran`.

## Calls made where the ticket left room

1. **The "could not check" and Device Role lines come from the Findings, by stable Check id**
   (`advisory-could-not-check`, `config-device-role-out-of-date`), not from
   `analysis.advice`. Analysis skips those Checks when a Cisco source is wholly unavailable,
   so a source outage stays the Run-end's one line per source and never becomes one line per
   device (story 118). A lookups-off Run therefore adds neither kind of line.
2. **The Critical line is always present**, as in the #82 prototype, including
   `0 Critical Findings from 0 Checks — see the Findings report`.
3. **v1's "In full" and "Noisy kinds" lists are gone**; they were the per-Finding dump story
   101 moves to `findings.html`. The other v1 tables under the heading — Unknown checks,
   Unrecognised interface names, Next hops with no Link — stay, wrapped in a "Topology
   details" disclosure, because `findings.html` does not carry them.
4. **The heading is now "Findings"**, not "Topology findings", because it covers Analysis
   Findings too.
5. **Advisory rows show the Check's name** (the Advisory title), matching the table's
   "Check" column; the Advisory id stays on the Findings page. The device count is distinct
   devices named at that level, so a Link Finding counts its two ends.
