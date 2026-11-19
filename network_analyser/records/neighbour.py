"""What a Visited Device's CDP or LLDP table says about one Neighbour (ticket #50).

`platforms` parses each table into these records; `discovery` gates and queues the Neighbours
from them, and `topology` builds Links from them. Every text value is device text: made
printable and capped by the parser, and never used for identity (story 74): the Device ID and
System Name are labels only.
"""

from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address, IPv6Address

from network_analyser.records.unknown import Unknown


@unique
class NeighbourProtocol(Enum):
    """The discovery protocol a Neighbour was advertised by."""

    CDP = "CDP"
    LLDP = "LLDP"


@dataclass(frozen=True, slots=True)
class NeighbourRecord:
    """One Neighbour, as one Visited Device's CDP or LLDP table showed it.

    Attributes:
        protocol: CDP or LLDP.
        local_port: the Visited Device's own interface, as reported.
        remote_port: the Neighbour's interface (CDP Port ID, LLDP Port id), as reported.
        management_addresses: the management addresses advertised, in the order shown.
        other_addresses: every other address advertised (CDP entry or interface
            addresses), in the order shown, without the management ones.
        device_id: the CDP Device ID or LLDP System Name: a label, never identity.
        platform: the CDP Platform; None for LLDP or when not advertised.
        description: the CDP Version or LLDP System Description, first line only; None
            when not advertised.
        capabilities: the capabilities advertised (CDP words, LLDP enabled codes).
        chassis_id: the LLDP Chassis id; None for CDP or when not advertised.
    """

    protocol: NeighbourProtocol
    local_port: str | Unknown
    remote_port: str | Unknown
    management_addresses: tuple[IPv4Address | IPv6Address, ...]
    other_addresses: tuple[IPv4Address | IPv6Address, ...]
    device_id: str | None
    platform: str | None
    description: str | None
    capabilities: tuple[str, ...]
    chassis_id: str | None

    @property
    def addresses(self) -> tuple[IPv4Address | IPv6Address, ...]:
        """Every address advertised: the management ones first (story 65)."""
        return (*self.management_addresses, *self.other_addresses)
