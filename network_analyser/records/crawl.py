"""What a crawl hands back: every device it dialled, and every one it only heard of (#50).

`discovery.crawl` returns a `CrawlResult`. A device the tool dialled is a `DeviceRecord`
(Visited, partial or Unvisited), with any other IPs it was found at folded into its
`aliases`. A device the tool learned of but never dialled (outside the Scope, excluded,
IPv6 only, advertised as an unsupported Platform, or queued when the Run stopped) is an
`UnvisitedDevice`, with each Neighbour advertisement that told of it.
"""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.neighbour import NeighbourRecord


@dataclass(frozen=True, slots=True)
class Sighting:
    """One Visited Device's advertisement of a Neighbour.

    Attributes:
        reported_by: the Visited Device whose CDP or LLDP table showed it.
        neighbour: what the table said.
    """

    reported_by: IPv4Address
    neighbour: NeighbourRecord


@dataclass(frozen=True, slots=True)
class UnvisitedDevice:
    """An Unvisited Device the tool never opened a connection to.

    Attributes:
        reason: one of the fixed Unvisited reasons.
        addresses: every address it was advertised with, management ones first.
        sightings: each advertisement of it; empty for a Seed never dialled.
    """

    reason: UnvisitedReason
    addresses: tuple[IPv4Address | IPv6Address, ...]
    sightings: tuple[Sighting, ...]


@dataclass(frozen=True, slots=True)
class CrawlResult:
    """Everything a crawl found.

    Attributes:
        devices: every device dialled, in the order its visit finished, aliases folded in.
        unvisited: every device known only from advertisements, or never dialled.
        stopped: why the crawl stopped early, as fixed text; None when it ran to the end.
    """

    devices: tuple[DeviceRecord, ...]
    unvisited: tuple[UnvisitedDevice, ...] = ()
    stopped: str | None = None
