"""Visit the Seeds, one after another (ticket #49: no crawl yet).

The pool, the crawl queue and Neighbour gating come with #50. Each Seed is visited once, in
the order the operator gave. `visit` is `device_gateway.visit` with the Run's Scope, Trust
Store and Credential Sets bound by `cli`, the composition root, so the gateway checks the
Scope again before any socket opens.
"""

from collections.abc import Callable, Iterable
from ipaddress import IPv4Address

from network_analyser.records.device import DeviceRecord

type Visit = Callable[[IPv4Address], DeviceRecord]


def visit_seeds(seeds: Iterable[IPv4Address], visit: Visit) -> tuple[DeviceRecord, ...]:
    """Visit each Seed once, in order; return one record per Seed."""
    return tuple(visit(seed) for seed in dict.fromkeys(seeds))
