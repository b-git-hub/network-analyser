"""The `analysis` module: every Check, run on plain records at the Run's end (#94).

It is pure. It imports only `records`, never an HTTP client, an SSH library or
`device_gateway`, so it runs offline and is tested from hand-written synthetic records with
no device. A Run hands it an `AnalysisInput` and it returns `AnalysisResults`: every Finding,
one advice record per Visited Device and the per-Check ran/skipped list.

- `analyse(data)` is the one deep call: every shipped Check runs on every Visited Device.
- `lookup_questions(data)` is the companion call: the de-duplicated, pattern-valid PIDs and
  OS type + release strings the online step may send, with no device record in them.

Records are in `records.analysis` (inputs and lookup questions) and `records.topology`
(the results, because they are the `topology.json` schema).
"""

from network_analyser.analysis.core import analyse
from network_analyser.analysis.questions import lookup_questions

__all__ = ["analyse", "lookup_questions"]
