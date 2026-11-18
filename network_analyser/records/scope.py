"""The Scope record: the checked fence, and the single in-Scope check (spec #37, #10, #41).

`scope.parse()` builds it from the operator's entries. Every module that asks "may this
address be touched?" calls `ScopeRecord.contains(ip)`, and nothing else (CODING_STANDARDS.md,
"Data between modules").
"""

from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address, IPv4Network, IPv6Address, summarize_address_range
from typing import override

# Addresses that are never a login target, whatever the Scope says (story 41): "this
# network" (0.0.0.0/8), loopback, multicast, and the reserved block that holds the limited
# broadcast 255.255.255.255.
NEVER_TARGETS: tuple[IPv4Network, ...] = (
    IPv4Network("0.0.0.0/8"),
    IPv4Network("127.0.0.0/8"),
    IPv4Network("224.0.0.0/4"),
    IPv4Network("240.0.0.0/4"),
)


@dataclass(frozen=True, slots=True, order=True)
class AddressRange:
    """An inclusive run of IPv4 addresses, from `first` to `last`."""

    first: IPv4Address
    last: IPv4Address

    @property
    def size(self) -> int:
        """How many addresses the range holds."""
        return int(self.last) - int(self.first) + 1

    def __contains__(self, address: object) -> bool:
        """Say whether an IPv4 address lies inside the range."""
        return isinstance(address, IPv4Address) and self.first <= address <= self.last

    def overlaps(self, other: AddressRange) -> bool:
        """Say whether the two ranges share at least one address."""
        return self.first <= other.last and other.first <= self.last

    @override
    def __str__(self) -> str:
        """Show one address, a CIDR when the range is exactly one, or else `first-last`."""
        if self.first == self.last:
            return str(self.first)
        networks = list(summarize_address_range(self.first, self.last))
        if len(networks) == 1:
            return str(networks[0])
        return f"{self.first}-{self.last}"


@unique
class Placement(Enum):
    """Where an address stands against the Scope. Only INSIDE may be touched."""

    INSIDE = "inside the Scope"
    OUTSIDE = "outside the Scope"
    EXCLUDED = "excluded by the operator"
    NEVER_A_TARGET = (
        "never a login target (0.0.0.0/8, loopback, multicast, reserved or broadcast, "
        "or the network or broadcast address of a Scope CIDR)"
    )


@dataclass(frozen=True, slots=True)
class ScopeRecord:
    """The merged, checked Scope. Build it with `scope.parse()`, never by hand.

    Attributes:
        ranges: the merged include ranges, in ascending order.
        exclusions: the merged exclusions, in ascending order.
        edges: the network and broadcast addresses of every include CIDR of /30 or
            shorter; never a target (decided 2026-11-18, spec-37-implementation-calls).
        address_count: addresses in the ranges, less those excluded.
        warnings: notes for the operator, such as overlapping entries that were merged.
    """

    ranges: tuple[AddressRange, ...]
    exclusions: tuple[AddressRange, ...]
    edges: frozenset[IPv4Address]
    address_count: int
    warnings: tuple[str, ...]

    def placement(self, ip: IPv4Address | IPv6Address) -> Placement:
        """Say where an address stands against the Scope, and so why it may not be touched."""
        if not isinstance(ip, IPv4Address) or any(ip in n for n in NEVER_TARGETS):
            return Placement.NEVER_A_TARGET if isinstance(ip, IPv4Address) else Placement.OUTSIDE
        if not any(ip in r for r in self.ranges):
            return Placement.OUTSIDE
        if any(ip in r for r in self.exclusions):
            return Placement.EXCLUDED
        if ip in self.edges:
            return Placement.NEVER_A_TARGET
        return Placement.INSIDE

    def contains(self, ip: IPv4Address | IPv6Address) -> bool:
        """The single in-Scope check: say whether the tool may touch this address."""
        return self.placement(ip) is Placement.INSIDE
