"""Shared-subnet and routing-protocol L3 Adjacency, and Subnets (#62; stories 136, 137, 139).

A prefix in one VRF on exactly two devices is one L3 Adjacency. On three or more it is one
Subnet, not a set of pairs. One device, a /32, an FHRP virtual IP, an unnumbered interface,
a management VRF, or an interface that is not up contributes nothing. Unknown data stays
unknown: a missing table is not read as "none" and is not read as "no virtual IPs" either,
so addresses are left in place when HSRP could not be read.

OSPF counts only in FULL, BGP only when Established. A listed EIGRP neighbour counts even
when its state was not reported, because that table lists current neighbours and NX-OS
records no state; a state of `down` does not count.

An in-Scope routing neighbour or static next hop that no Visited Device and no CDP/LLDP
advertisement already accounts for becomes an Unvisited Device, reason `seen only in
routing or ARP data (not crawled)`. It is not a login target. With no Scope, or outside it,
that device is not invented and gets no adjacency.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from network_analyser.records.collected import (
    MANAGEMENT_VRFS,
    Interface,
    InterfaceIp,
    Reading,
    RoutingNeighbour,
    RoutingProtocol,
)
from network_analyser.records.device import UnvisitedReason
from network_analyser.records.interface_names import InterfaceName
from network_analyser.records.scope import ScopeRecord
from network_analyser.records.topology import (
    AdjacencyEnd,
    AdjacencyKind,
    Evidence,
    EvidenceSource,
    L3Adjacency,
    Report,
    Subnet,
    SubnetAttachment,
    UnvisitedDevice,
)
from network_analyser.records.unknown import Unknown
from network_analyser.topology import ids
from network_analyser.topology.devices import NO_NAME, NO_PLATFORM, Known

_PAIR = 2
"""Two devices share a prefix as an L3 Adjacency; three or more make a Subnet (story 137)."""
_HOST_PREFIX = 32
"""A /32 is a host route and never a shared subnet (story 136)."""


@dataclass(frozen=True, slots=True)
class NextHop:
    """One L3 next hop that inference may try to place, already resolved to a device.

    Attributes:
        reporter: the Visited Device that has the route or neighbour.
        vrf: the VRF it was learned in.
        ip: the next-hop address.
        far: the id of the device that address belongs to.
        evidence: the routing reports that named it.
    """

    reporter: str
    vrf: str
    ip: IPv4Address
    far: str
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True, slots=True)
class Layer3:
    """What the L3 rules add to a Topology."""

    adjacencies: tuple[L3Adjacency, ...]
    subnets: tuple[Subnet, ...]
    unvisited: tuple[UnvisitedDevice, ...]
    next_hops: tuple[NextHop, ...]


@dataclass(frozen=True, slots=True)
class _Member:
    """One live interface address that may join a shared prefix."""

    device: str
    interface: InterfaceName
    address: IPv4Interface
    vrf: str
    prefix: IPv4Network
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class _Mention:
    """One routing neighbour or static next hop, as one device reported it."""

    reporter: str
    vrf: str
    ip: IPv4Address
    interface: InterfaceName | None
    evidence: Evidence
    protocol: RoutingProtocol | None
    up: bool


def layer3(
    devices: Sequence[Known],
    owners: dict[IPv4Address, str],
    unvisited: Sequence[UnvisitedDevice],
    scope: ScopeRecord | None,
) -> Layer3:
    """Return the L3 Adjacencies, Subnets, routing-only devices and next hops."""
    shared, subnets = _prefixes(_members(devices))
    mentions = _mentions(devices)
    known = _known_ips(unvisited)
    extra = _routing_only(mentions, owners, known, scope)
    resolved = _resolver(owners, known, extra)
    protocol = _protocols(mentions, resolved)
    return Layer3(
        adjacencies=tuple(sorted((*shared, *protocol), key=lambda item: item.id)),
        subnets=tuple(sorted(subnets, key=lambda item: item.id)),
        unvisited=tuple(sorted(extra, key=lambda item: item.id)),
        next_hops=_hops(mentions, resolved),
    )


def _members(devices: Sequence[Known]) -> list[_Member]:
    found: list[_Member] = []
    for device in devices:
        reading = device.collected.interfaces
        if not isinstance(reading, Reading):
            continue
        evidence = _evidence(device.id, reading, EvidenceSource.INTERFACE)
        blocked = _management(device)
        virtual = _virtual_ips(device)
        for interface in reading.value:
            settings = _usable(interface, blocked)
            if settings is None:
                continue
            found.extend(
                _Member(device.id, interface.name, address, settings.vrf, address.network, evidence)
                for address in settings.addresses
                if address.network.prefixlen != _HOST_PREFIX and address.ip not in virtual
            )
    return found


def _usable(interface: Interface, blocked: frozenset[str]) -> InterfaceIp | None:
    """The interface's addressing, when it is up and allowed to form a shared subnet."""
    settings = interface.ip
    if interface.admin_up is not True or interface.line_up is not True:
        return None
    if not isinstance(settings, InterfaceIp) or settings.unnumbered or settings.vrf in blocked:
        return None
    return settings


def _management(device: Known) -> frozenset[str]:
    """VRFs that never form a shared subnet: the two named ones, plus any marked management."""
    reading = device.collected.vrfs
    marked = (
        {item.name for item in reading.value if item.management}
        if isinstance(reading, Reading)
        else set()
    )
    return MANAGEMENT_VRFS | frozenset(marked)


def _virtual_ips(device: Known) -> frozenset[IPv4Address]:
    """Virtual IPs HSRP, VRRP or GLBP positively listed. Unknown FHRP strips nothing."""
    reading = device.collected.fhrp
    if not isinstance(reading, Reading):
        return frozenset()
    return frozenset(group.virtual_ip for group in reading.value)


def _prefixes(members: Sequence[_Member]) -> tuple[list[L3Adjacency], list[Subnet]]:
    groups: dict[tuple[str, IPv4Network], list[_Member]] = {}
    for member in members:
        groups.setdefault((member.vrf, member.prefix), []).append(member)
    adjacencies: list[L3Adjacency] = []
    subnets: list[Subnet] = []
    for (vrf, prefix), group in groups.items():
        devices = sorted({member.device for member in group})
        if len(devices) < _PAIR:
            continue
        evidence = _unique(member.evidence for member in group)
        if len(devices) == _PAIR:
            adjacencies.append(_shared(vrf, prefix, devices, group, evidence))
        else:
            subnets.append(_subnet(vrf, prefix, group, evidence))
    return adjacencies, subnets


def _shared(
    vrf: str,
    prefix: IPv4Network,
    devices: list[str],
    group: Sequence[_Member],
    evidence: tuple[Evidence, ...],
) -> L3Adjacency:
    left, right = devices[0], devices[1]
    return L3Adjacency(
        id=ids.hashed("adj", [AdjacencyKind.SHARED_SUBNET.value, vrf, left, right, str(prefix)]),
        ends=(_end(left, group), _end(right, group)),
        vrf=vrf,
        kind=AdjacencyKind.SHARED_SUBNET,
        prefix=prefix,
        evidence=evidence,
        conflicts=(),
    )


def _end(device: str, group: Sequence[_Member]) -> AdjacencyEnd:
    names = {member.interface for member in group if member.device == device}
    return AdjacencyEnd(device, tuple(sorted(names, key=lambda name: name.short)))


def _subnet(
    vrf: str, prefix: IPv4Network, group: Sequence[_Member], evidence: tuple[Evidence, ...]
) -> Subnet:
    attachments = tuple(
        sorted(
            (SubnetAttachment(member.device, member.interface, member.address) for member in group),
            key=lambda item: (item.device, item.interface.short, str(item.address)),
        )
    )
    return Subnet(
        id=ids.hashed("subnet", [vrf, str(prefix)]),
        vrf=vrf,
        prefix=prefix,
        attachments=attachments,
        evidence=evidence,
        conflicts=(),
    )


def _mentions(devices: Sequence[Known]) -> list[_Mention]:
    found: list[_Mention] = []
    for device in devices:
        found.extend(_neighbours(device))
        found.extend(_statics(device))
    return found


def _neighbours(device: Known) -> list[_Mention]:
    reading = device.collected.routing_neighbours
    if not isinstance(reading, Reading):
        return []
    evidence = _evidence(device.id, reading, EvidenceSource.ROUTING)
    return [
        _Mention(
            device.id,
            neighbour.vrf,
            neighbour.ip,
            neighbour.interface,
            evidence,
            neighbour.protocol,
            _up(neighbour),
        )
        for neighbour in reading.value
    ]


def _statics(device: Known) -> list[_Mention]:
    reading = device.collected.static_routes
    if not isinstance(reading, Reading):
        return []
    evidence = _evidence(device.id, reading, EvidenceSource.ROUTING)
    return [
        _Mention(
            device.id,
            route.vrf,
            route.next_hop,
            route.interface,
            evidence,
            protocol=None,
            up=True,
        )
        for route in reading.value
        if route.next_hop is not None
    ]


def _up(neighbour: RoutingNeighbour) -> bool:
    """Whether the neighbour is a current adjacency, not merely configured or half-up."""
    state = neighbour.state
    if neighbour.protocol is RoutingProtocol.OSPF:
        return isinstance(state, str) and state.upper().startswith("FULL")
    if neighbour.protocol is RoutingProtocol.BGP:
        return isinstance(state, str) and state.lower() == "established"
    return not (isinstance(state, str) and state.lower() == "down")


def _known_ips(unvisited: Sequence[UnvisitedDevice]) -> dict[IPv4Address, str]:
    found: dict[IPv4Address, str] = {}
    for device in unvisited:
        for address in device.advertised_ips:
            found.setdefault(address, device.id)
    return found


def _routing_only(
    mentions: Sequence[_Mention],
    owners: dict[IPv4Address, str],
    known: dict[IPv4Address, str],
    scope: ScopeRecord | None,
) -> list[UnvisitedDevice]:
    """Devices named only by routing, when the address is inside the Scope."""
    if scope is None:
        return []
    by_ip: dict[IPv4Address, list[_Mention]] = {}
    for mention in mentions:
        address = mention.ip
        if address in owners or address in known or not scope.contains(address):
            continue
        by_ip.setdefault(address, []).append(mention)
    return [_unvisited(address, group) for address, group in by_ip.items()]


def _unvisited(address: IPv4Address, group: Sequence[_Mention]) -> UnvisitedDevice:
    return UnvisitedDevice(
        id=ids.hashed("unv", [f"ip:{address}"]),
        reason=UnvisitedReason.ROUTING_OR_ARP_ONLY,
        label=Unknown(NO_NAME),
        advertised_platform=Unknown(NO_PLATFORM),
        advertised_ips=(address,),
        advertised_ipv6=(),
        chassis_id=None,
        reported_by=_reports(group),
    )


def _reports(group: Sequence[_Mention]) -> tuple[Report, ...]:
    unique: dict[tuple[str, str, str], Report] = {}
    for mention in group:
        port = mention.interface.short if mention.interface is not None else ""
        key = (mention.reporter, port, mention.evidence.command)
        unique.setdefault(key, Report(mention.reporter, mention.interface, mention.evidence))
    return tuple(sorted(unique.values(), key=_report_order))


def _report_order(report: Report) -> tuple[str, str, str]:
    port = report.interface.short if report.interface is not None else ""
    return (report.device, port, report.evidence.source.value)


def _resolver(
    owners: dict[IPv4Address, str],
    known: dict[IPv4Address, str],
    extra: Sequence[UnvisitedDevice],
) -> dict[IPv4Address, str]:
    """Every address the L3 rules can point at, visited devices first."""
    resolved = dict(owners)
    for address, owner in known.items():
        resolved.setdefault(address, owner)
    for added in extra:
        for address in added.advertised_ips:
            resolved.setdefault(address, added.id)
    return resolved


def _protocols(mentions: Sequence[_Mention], resolved: dict[IPv4Address, str]) -> list[L3Adjacency]:
    groups: dict[tuple[AdjacencyKind, str, str, str], list[_Mention]] = {}
    for mention in mentions:
        kind = _kind(mention)
        far = resolved.get(mention.ip)
        if kind is None or far is None or far == mention.reporter:
            continue
        pair = tuple(sorted((mention.reporter, far)))
        groups.setdefault((kind, mention.vrf, pair[0], pair[1]), []).append(mention)
    return [_protocol(key, group) for key, group in groups.items()]


def _kind(mention: _Mention) -> AdjacencyKind | None:
    if mention.protocol is None or not mention.up:
        return None
    return {
        RoutingProtocol.OSPF: AdjacencyKind.OSPF,
        RoutingProtocol.EIGRP: AdjacencyKind.EIGRP,
        RoutingProtocol.BGP: AdjacencyKind.BGP,
    }[mention.protocol]


def _protocol(key: tuple[AdjacencyKind, str, str, str], group: Sequence[_Mention]) -> L3Adjacency:
    kind, vrf, left, right = key
    ends = (
        AdjacencyEnd(left, _interfaces(left, group)),
        AdjacencyEnd(right, _interfaces(right, group)),
    )
    return L3Adjacency(
        id=ids.hashed("adj", [kind.value, vrf, left, right]),
        ends=ends,
        vrf=vrf,
        kind=kind,
        prefix=None,
        evidence=_unique(mention.evidence for mention in group),
        conflicts=(),
    )


def _interfaces(device: str, group: Sequence[_Mention]) -> tuple[InterfaceName, ...]:
    names = {
        mention.interface
        for mention in group
        if mention.reporter == device and mention.interface is not None
    }
    return tuple(sorted(names, key=lambda name: name.short))


def _hops(mentions: Sequence[_Mention], resolved: dict[IPv4Address, str]) -> tuple[NextHop, ...]:
    """Up neighbours and static next hops, one per reporter, VRF and address."""
    groups: dict[tuple[str, str, IPv4Address], list[_Mention]] = {}
    for mention in mentions:
        if mention.protocol is not None and not mention.up:
            continue
        far = resolved.get(mention.ip)
        if far is None or far == mention.reporter:
            continue
        groups.setdefault((mention.reporter, mention.vrf, mention.ip), []).append(mention)
    return tuple(
        NextHop(reporter, vrf, address, resolved[address], _unique(m.evidence for m in group))
        for (reporter, vrf, address), group in groups.items()
    )


def _evidence(device: str, reading: Reading[object], source: EvidenceSource) -> Evidence:
    return Evidence(device, "; ".join(reading.commands), source)


def _unique(items: Iterable[Evidence]) -> tuple[Evidence, ...]:
    return tuple(
        sorted(set(items), key=lambda item: (item.device, item.source.value, item.command))
    )
