"""The `topology` module: builds the Topology from collected device records.

Owns Links, Bundles, Shared Segments, L3 Adjacency, Subnets, VLAN Mismatches, Unvisited
Device merging and evidence. It works only from plain records, so the whole module runs and is
tested from hand-written synthetic records with no device:

- `build(records)` returns a `records.topology.Topology` (#52);
- `to_document(topology)` returns it as plain JSON data, the content of `topology.json`,
  carrying `FORMAT_VERSION`. The cli writes it through the secret scan (`run_output`).

The schema is in docs/topology-json.md.
"""

from network_analyser.topology.build import build
from network_analyser.topology.document import FORMAT_VERSION, to_document

__all__ = ["FORMAT_VERSION", "build", "to_document"]
