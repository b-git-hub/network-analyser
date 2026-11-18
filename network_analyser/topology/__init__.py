"""The `topology` module: builds the Topology from collected device records.

Owns Links, Bundles, Shared Segments, L3 Adjacency, Subnets, VLAN Mismatches, Unvisited
Device merging and evidence. `build(records)` returns a Topology record, saved as the
redacted `topology.json`: the one plain-data seam later test suites build on.
"""
