"""What a crawl hands back: every device it dialled, and every address it chose not to (#50).

`discovery.crawl` returns a `CrawlResult`. A device the tool dialled is a `DeviceRecord`
(Visited, partial or Unvisited), with any other IPs it was found at in its `aliases`. An
advertised IPv4 address the crawl chose not to dial (outside the Scope, excluded, advertised
as an unsupported Platform, or queued when the Run stopped) is an Unvisited `DeviceRecord`
with that reason and nothing else: `topology.build` merges it with the advertisements of
that address (docs/topology-json.md). An IPv6-only Neighbour has no IPv4 address to record,
so it reaches the Topology through its advertisements alone.
"""

from dataclasses import dataclass

from network_analyser.records.device import DeviceRecord
from network_analyser.records.sweep import SweepResult


@dataclass(frozen=True, slots=True)
class CrawlResult:
    """Everything a crawl found.

    Attributes:
        devices: every device dialled, in the order its visit finished, aliases folded in.
        unvisited: one Unvisited record per advertised address never dialled, with its reason.
        stopped: why the crawl stopped early, as fixed text; None when it ran to the end.
        sweep: the Sweep's probes and the extra Seeds they earned; None when the Run did
            not sweep. Kept for the report (#66).
    """

    devices: tuple[DeviceRecord, ...]
    unvisited: tuple[DeviceRecord, ...] = ()
    stopped: str | None = None
    sweep: SweepResult | None = None
