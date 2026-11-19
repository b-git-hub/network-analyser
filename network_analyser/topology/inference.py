"""Inferred Links for L3 next hops CDP and LLDP do not already place (#62, story 130).

ARP gives the next hop's MAC. The MAC table gives the one port that MAC is learned on.
The Link is placed only when that port is a single edge port: not an uplink already in a
Link or Shared Segment, and not an SVI, loopback, tunnel, management port or nve. Anything
else stays unplaced. Unknown ARP or an unknown MAC table stays unknown and places nothing.

Two or more such next hops learned on the same edge port join one Shared Segment, the same
record a port that hears two CDP neighbours already uses. ARP and MAC are evidence. They
are never scan targets, and an ARP entry that is not a next hop creates nothing.
"""

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from network_analyser.records.collected import Reading
from network_analyser.records.interface_names import InterfaceName
from network_analyser.records.topology import (
    Evidence,
    EvidenceSource,
    Finding,
    FindingKind,
    Link,
    LinkEnd,
    LinkStatus,
    SegmentPort,
    SharedSegment,
)
from network_analyser.records.unknown import Unknown
from network_analyser.topology import ids
from network_analyser.topology.devices import Known
from network_analyser.topology.l3 import NextHop

FAR_PORT: Final = "far port not learned"
"""Why an inferred Link's far interface is unknown: MAC and ARP do not name it."""

_NOT_EDGE: Final = re.compile(r"^(?:Vl|Lo|Tu|mgmt|nve)\d")
_MAC: Final = re.compile(r"^[0-9a-f]{12}$")

type Names = Callable[[str], str]


@dataclass(frozen=True, slots=True)
class Inference:
    """The Links, Shared Segments and findings MAC/ARP inference adds."""

    links: tuple[Link, ...]
    segments: tuple[SharedSegment, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class _Placement:
    """A next hop learned on one edge port of one device."""

    local: str
    port: InterfaceName
    far: str
    evidence: tuple[Evidence, ...]


def infer(
    devices: Sequence[Known],
    links: Sequence[Link],
    segments: Sequence[SharedSegment],
    hops: Sequence[NextHop],
    names: Names,
) -> Inference:
    """Place inferred Links and Shared Segments for next hops not already connected."""
    by_id = {device.id: device for device in devices}
    internal = {device.id: _internal(device, links, segments) for device in devices}
    placements: list[_Placement] = []
    findings: list[Finding] = []
    for hop in hops:
        if _connected(hop.reporter, hop.far, links, segments):
            continue
        device = by_id.get(hop.reporter)
        if device is None:
            continue
        placed = _place(device, hop, internal.get(hop.reporter, frozenset()), names)
        if isinstance(placed, Finding):
            findings.append(placed)
        elif placed is not None:
            placements.append(placed)
    made_links, made_segments, disagreements = _assemble(placements, names)
    return Inference(
        links=tuple(sorted(made_links, key=lambda link: link.id)),
        segments=tuple(sorted(made_segments, key=lambda segment: segment.id)),
        findings=tuple(sorted((*findings, *disagreements), key=lambda finding: finding.id)),
    )


def _place(
    device: Known, hop: NextHop, internal: frozenset[str], names: Names
) -> _Placement | Finding | None:
    macs = _arp_macs(device, hop)
    if macs is None:
        return None
    if len(macs) != 1:
        return _conflict(device, hop, names, "more than one MAC") if len(macs) > 1 else None
    ports = _learned_ports(device, next(iter(macs)))
    if ports is None:
        return None
    edge = {
        short: name
        for short, name in ports.items()
        if short not in internal and _NOT_EDGE.match(short) is None
    }
    if any(short in internal for short in ports) or not edge:
        return None
    if len(edge) > 1:
        return _conflict(device, hop, names, f"learned on {len(edge)} edge ports")
    evidence = _unique(
        (
            *hop.evidence,
            _table(device, "arp", EvidenceSource.ARP),
            _table(device, "mac", EvidenceSource.MAC),
        )
    )
    return _Placement(device.id, next(iter(edge.values())), hop.far, evidence)


def _arp_macs(device: Known, hop: NextHop) -> set[str] | None:
    """MACs ARP gives for this next hop, or None when the ARP table was not collected."""
    reading = device.collected.arp
    if not isinstance(reading, Reading):
        return None
    return {
        normal
        for entry in reading.value
        if entry.vrf == hop.vrf
        and entry.ip == hop.ip
        and (normal := _normal(entry.mac)) is not None
    }


def _learned_ports(device: Known, mac: str) -> dict[str, InterfaceName] | None:
    """Dynamic MAC-table ports for `mac`, or None when the table was not collected."""
    reading = device.collected.mac
    if not isinstance(reading, Reading):
        return None
    found: dict[str, InterfaceName] = {}
    for entry in reading.value:
        if entry.dynamic and _normal(entry.mac) == mac:
            found.setdefault(entry.port.short, entry.port)
    return found


def _conflict(device: Known, hop: NextHop, names: Names, why: str) -> Finding:
    subject = [FindingKind.CONFLICTING_EVIDENCE.value, device.id, hop.far, str(hop.ip), why]
    return Finding(
        id=ids.hashed("finding", subject),
        kind=FindingKind.CONFLICTING_EVIDENCE,
        summary=(
            f"MAC/ARP evidence for {hop.ip} on {names(device.id)} disagrees ({why}), "
            "so no inferred Link was placed"
        ),
        devices=tuple(sorted({device.id, hop.far})),
        items=(),
        evidence=hop.evidence,
    )


def _assemble(
    placements: Sequence[_Placement], names: Names
) -> tuple[list[Link], list[SharedSegment], list[Finding]]:
    """One far device on a port is a Link; several are one Shared Segment."""
    kept, findings = _one_port_each(placements, names)
    by_port: dict[tuple[str, str], list[_Placement]] = {}
    for place in kept:
        by_port.setdefault((place.local, place.port.short), []).append(place)
    links: list[Link] = []
    segments: list[SharedSegment] = []
    for group in by_port.values():
        if len({place.far for place in group}) == 1:
            links.append(_link(_merged(group)))
        else:
            segments.append(_segment(group))
    return links, segments, findings


def _one_port_each(
    placements: Sequence[_Placement], names: Names
) -> tuple[list[_Placement], list[Finding]]:
    """Keep a device pair only when every report of it uses the same port."""
    by_pair: dict[tuple[str, str], list[_Placement]] = {}
    for place in placements:
        by_pair.setdefault((place.local, place.far), []).append(place)
    kept: list[_Placement] = []
    findings: list[Finding] = []
    for (local, far), group in by_pair.items():
        if len({place.port.short for place in group}) == 1:
            kept.append(_merged(group))
            continue
        findings.append(
            Finding(
                id=ids.hashed("finding", [FindingKind.CONFLICTING_EVIDENCE.value, local, far]),
                kind=FindingKind.CONFLICTING_EVIDENCE,
                summary=(
                    f"MAC/ARP evidence places {names(far)} on more than one port of "
                    f"{names(local)}, so no inferred Link was placed"
                ),
                devices=tuple(sorted({local, far})),
                items=(),
                evidence=_unique(item for place in group for item in place.evidence),
            )
        )
    return kept, findings


def _merged(group: Sequence[_Placement]) -> _Placement:
    first = group[0]
    return _Placement(
        first.local,
        first.port,
        first.far,
        _unique(item for place in group for item in place.evidence),
    )


def _link(place: _Placement) -> Link:
    local = LinkEnd(place.local, place.port)
    far = LinkEnd(place.far, Unknown(FAR_PORT))
    ends = (local, far) if _before(local, far) else (far, local)
    return Link(
        id=ids.hashed("link", [f"{end.device}:{_short(end.interface)}" for end in ends]),
        ends=ends,
        status=LinkStatus.INFERRED,
        evidence=place.evidence,
        role=None,
        bundle=None,
        conflicts=(),
    )


def _segment(group: Sequence[_Placement]) -> SharedSegment:
    first = group[0]
    ports = [SegmentPort(first.local, first.port)]
    ports.extend(
        SegmentPort(far, Unknown(FAR_PORT)) for far in sorted({place.far for place in group})
    )
    ordered = tuple(sorted(ports, key=lambda port: (port.device, _short(port.interface))))
    return SharedSegment(
        id=ids.hashed("seg", [f"{port.device}:{_short(port.interface)}" for port in ordered]),
        ports=ordered,
        evidence=_unique(item for place in group for item in place.evidence),
    )


def _connected(
    local: str, far: str, links: Sequence[Link], segments: Sequence[SharedSegment]
) -> bool:
    """Whether CDP or LLDP already connects these two devices."""
    for link in links:
        if {end.device for end in link.ends} == {local, far}:
            return True
    return any(
        local in devices and far in devices
        for devices in ({port.device for port in segment.ports} for segment in segments)
    )


def _internal(
    device: Known, links: Sequence[Link], segments: Sequence[SharedSegment]
) -> frozenset[str]:
    """Ports that already face known infrastructure, plus members of such a port-channel."""
    ports: set[str] = set()
    for link in links:
        ports.update(
            end.interface.short
            for end in link.ends
            if end.device == device.id and not isinstance(end.interface, Unknown)
        )
    for segment in segments:
        ports.update(
            port.interface.short
            for port in segment.ports
            if port.device == device.id and not isinstance(port.interface, Unknown)
        )
    members = {
        interface.name.short
        for interface in device.interfaces
        if isinstance(interface.bundle, str) and interface.bundle in ports
    }
    return frozenset(ports | members)


def _table(device: Known, part: str, source: EvidenceSource) -> Evidence:
    reading = getattr(device.collected, part)
    commands = reading.commands if isinstance(reading, Reading) else ()
    return Evidence(device.id, "; ".join(commands), source)


def _normal(value: str) -> str | None:
    digits = "".join(character for character in value.lower() if character in "0123456789abcdef")
    return digits if _MAC.fullmatch(digits) else None


def _unique(items: Iterable[Evidence]) -> tuple[Evidence, ...]:
    return tuple(
        sorted(set(items), key=lambda item: (item.device, item.source.value, item.command))
    )


def _before(left: LinkEnd, right: LinkEnd) -> bool:
    return (left.device, _short(left.interface)) <= (right.device, _short(right.interface))


def _short(name: InterfaceName | Unknown) -> str:
    return "?" if isinstance(name, Unknown) else name.short
