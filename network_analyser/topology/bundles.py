"""Bundles, vPC peer-links and keepalives (stories 131-132; decided on #11 point 6).

Links stay physical; members are grouped into a Bundle named after the port-channel at each
end. A port-channel joined to a vPC is one side with an end on each peer, so a port-channel
facing a vPC pair is one Bundle with far ends on two devices. Members whose far end is in no
port-channel, or not in one matching bundle, are flagged. Where membership cannot be told
(an Unvisited Device, or data not collected) nothing is flagged: unknown is never a fault.
"""

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from ipaddress import IPv4Address

from network_analyser.records.collected import Reading, VpcState
from network_analyser.records.topology import (
    Bundle,
    BundleEnd,
    BundleSide,
    Finding,
    FindingKind,
    Link,
    LinkEnd,
    LinkRole,
)
from network_analyser.records.unknown import Unknown
from network_analyser.topology import ids
from network_analyser.topology.devices import Known

NOT_VISITED = "not a Visited Device"
NOT_COLLECTED = "Bundle membership not collected"
PORT_UNKNOWN = "port not advertised"

type Membership = str | Unknown | None
"""The port-channel a port is in; None for none."""


@dataclass(frozen=True, slots=True)
class _Side:
    """One end of a member Link, as a Bundle side. Ends with the same key are one side.

    The side is a port-channel, a vPC, or a device whose port is in none.
    """

    key: str
    kind: str  # "bundle", "none" or "unknown"
    device: str
    channel: Membership
    vpc: int | None = None


@dataclass(slots=True)
class _Group:
    """The member Links between two sides, and each side's ends: one per device."""

    keys: tuple[str, str]
    sides: dict[str, _Side]
    ends: dict[str, dict[str, Membership]]
    members: list[Link]


@dataclass(frozen=True, slots=True)
class Bundling:
    """The Links with their roles and Bundles, the Bundles, and the findings."""

    links: tuple[Link, ...]
    bundles: tuple[Bundle, ...]
    findings: tuple[Finding, ...]


def bundling(
    links: Sequence[Link],
    devices: Sequence[Known],
    owners: Mapping[IPv4Address, str],
    names: Callable[[str], str],
) -> Bundling:
    """Label vPC Links, and group member Links into Bundles."""
    by_id = {d.id: d for d in devices}
    peers = _vpc_peers(devices, owners)
    links = [replace(link, role=_role(link, by_id, peers)) for link in links]
    groups: dict[tuple[str, str], _Group] = {}
    for link in links:
        a, b = (_side(end, by_id, peers) for end in link.ends)
        if a.kind != "bundle" and b.kind != "bundle":
            continue
        first, second = sorted((a, b), key=lambda side: side.key)
        group = groups.setdefault(
            (first.key, second.key),
            _Group((first.key, second.key), {first.key: first, second.key: second}, {}, []),
        )
        group.members.append(link)
        for side in (a, b):
            group.ends.setdefault(side.key, {}).setdefault(side.device, side.channel)
    flagged, findings = _flag(groups.values(), names)
    bundles: list[Bundle] = []
    member_of: dict[str, str] = {}
    for group in groups.values():
        member_ids = sorted(link.id for link in group.members)
        bundle_id = ids.hashed("bundle", list(group.keys))
        roles = {link.role for link in group.members}
        first_side, second_side = (_bundle_side(group, key) for key in group.keys)
        bundles.append(
            Bundle(
                id=bundle_id,
                sides=(first_side, second_side),
                links=tuple(member_ids),
                role=LinkRole.VPC_PEER_LINK if roles == {LinkRole.VPC_PEER_LINK} else None,
                flagged=tuple(i for i in member_ids if i in flagged),
            )
        )
        member_of.update(dict.fromkeys(member_ids, bundle_id))
    links = [replace(link, bundle=member_of.get(link.id)) for link in links]
    finding_items = [
        replace(
            f, items=tuple(sorted({*f.items, *(member_of[i] for i in f.items if i in member_of)}))
        )
        for f in findings
    ]
    return Bundling(
        links=tuple(links),
        bundles=tuple(sorted(bundles, key=lambda b: b.id)),
        findings=tuple(sorted(finding_items, key=lambda f: f.id)),
    )


def membership(device: Known | None, end: LinkEnd) -> Membership:
    """Return the port-channel `end`'s port is in, from the interfaces or the summary."""
    if device is None:
        return Unknown(NOT_VISITED)
    if isinstance(end.interface, Unknown):
        return Unknown(PORT_UNKNOWN)
    short = end.interface.short
    answers: list[Membership] = []
    interfaces = device.collected.interfaces
    if isinstance(interfaces, Reading):
        found = next((i for i in interfaces.value if i.name.short == short), None)
        if found is not None:
            answers.append(found.bundle)
    channels = device.collected.port_channels
    if isinstance(channels, Reading):
        holding = [
            c.name.short for c in channels.value if any(m.port.short == short for m in c.members)
        ]
        answers.append(holding[0] if holding else None)
    named = [a for a in answers if isinstance(a, str)]
    if named:
        return named[0]
    if None in answers:
        return None
    return Unknown(NOT_COLLECTED)


def _vpc(device: Known) -> VpcState | None:
    vpc = device.collected.vpc
    return vpc.value if isinstance(vpc, Reading) else None


def _vpc_peers(devices: Sequence[Known], owners: Mapping[IPv4Address, str]) -> dict[str, str]:
    """Pair vPC peers: the same domain, and each one's keepalive reaches the other."""
    by_id = {d.id: d for d in devices}
    peers: dict[str, str] = {}
    for device in devices:
        state = _vpc(device)
        if state is None or isinstance(state.keepalive, Unknown):
            continue
        other = by_id.get(owners.get(state.keepalive.destination, ""))
        other_state = _vpc(other) if other is not None else None
        if other is not None and other_state is not None and other_state.domain == state.domain:
            peers[device.id] = other.id
    return {a: b for a, b in peers.items() if peers.get(b) == a and a != b}


def _role(link: Link, by_id: Mapping[str, Known], peers: Mapping[str, str]) -> LinkRole | None:
    first, second = link.ends
    if peers.get(first.device) != second.device:
        return None
    if all(_is_peer_link(by_id[e.device], e) for e in link.ends):
        return LinkRole.VPC_PEER_LINK
    if any(_is_keepalive(by_id[e.device], e) for e in link.ends):
        return LinkRole.VPC_PEER_KEEPALIVE
    return None


def _is_peer_link(device: Known, end: LinkEnd) -> bool:
    state = _vpc(device)
    if state is None or isinstance(state.peer_link, Unknown):
        return False
    return membership(device, end) == state.peer_link.short


def _is_keepalive(device: Known, end: LinkEnd) -> bool:
    state = _vpc(device)
    if state is None or isinstance(state.keepalive, Unknown) or isinstance(end.interface, Unknown):
        return False
    source = state.keepalive.source
    short = end.interface.short
    return any(
        i.name.short == short
        and i.ip is not None
        and not isinstance(i.ip, Unknown)
        and any(a.ip == source for a in i.ip.addresses)
        for i in device.interfaces
    )


def _side(end: LinkEnd, by_id: Mapping[str, Known], peers: Mapping[str, str]) -> _Side:
    device = by_id.get(end.device)
    channel = membership(device, end)
    if channel is None:
        return _Side(f"none:{end.device}", "none", end.device, None)
    if isinstance(channel, Unknown):
        return _Side(f"unknown:{end.device}", "unknown", end.device, channel)
    number = _vpc_number(device, channel) if device is not None else None
    peer = peers.get(end.device)
    if number is not None and peer is not None:
        pair = ":".join(sorted((end.device, peer)))
        return _Side(f"vpc:{pair}:{number}", "bundle", end.device, channel, number)
    return _Side(f"pc:{end.device}:{channel}", "bundle", end.device, channel)


def _vpc_number(device: Known, channel: str) -> int | None:
    state = _vpc(device)
    if state is None or isinstance(state.port_channels, Unknown):
        return None
    return next((p.number for p in state.port_channels if p.port_channel.short == channel), None)


def _bundle_side(group: _Group, key: str) -> BundleSide:
    ends = group.ends[key]
    return BundleSide(
        ends=tuple(BundleEnd(device, ends[device]) for device in sorted(ends)),
        vpc=group.sides[key].vpc,
    )


def _flag(groups: Iterable[_Group], names: Callable[[str], str]) -> tuple[set[str], list[Finding]]:
    """Flag members whose far end is in no matching bundle (story 131).

    That is a far end in no port-channel, or one port-channel's members split across more
    than one far bundle. One finding per port-channel.
    """
    facing: dict[str, list[tuple[_Group, _Side]]] = {}
    for group in groups:
        first, second = (group.sides[key] for key in group.keys)
        for near, far in ((first, second), (second, first)):
            if near.kind == "bundle":
                facing.setdefault(near.key, []).append((group, far))
    flagged: set[str] = set()
    findings: list[Finding] = []
    for key, faced in sorted(facing.items()):
        known = [(group, far) for group, far in faced if far.kind != "unknown"]
        split = len({far.key for _, far in known}) > 1
        bad = [m for group, far in known if far.kind == "none" or split for m in group.members]
        if not bad:
            continue
        device, channel = min(faced[0][0].ends[key].items())
        bad_ids = sorted({link.id for link in bad})
        flagged.update(bad_ids)
        findings.append(
            Finding(
                id=ids.hashed("finding", [FindingKind.BUNDLE_MEMBER_MISMATCH.value, key]),
                kind=FindingKind.BUNDLE_MEMBER_MISMATCH,
                summary=(
                    f"{channel} on {names(device)}: {len(bad_ids)} member Link(s) do not reach "
                    "one matching bundle at the far end"
                ),
                devices=tuple(sorted({e.device for link in bad for e in link.ends})),
                items=tuple(bad_ids),
                evidence=tuple(
                    sorted(
                        {e for link in bad for e in link.evidence},
                        key=lambda e: (e.device, e.source.value, e.command),
                    )
                ),
            )
        )
    return flagged, findings
