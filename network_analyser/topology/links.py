"""Links and Shared Segments from CDP and LLDP claims (stories 124, 125, 128, 129; #11).

- One end's report is enough for a Link. Reports of the same port pair, from either end and
  either protocol, are one Link: confirmed when both ends report it, one-sided otherwise.
- A port hearing two or more devices connects to a Shared Segment, and so does every port
  seen on it; overlapping views are one Segment.
- Reports are never resolved silently: when two Links claim the same port, both are kept and
  one finding flags them.
"""

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace

from network_analyser.records.interface_names import InterfaceName
from network_analyser.records.topology import (
    Evidence,
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
from network_analyser.topology.devices import Claim

NOT_ADVERTISED = "the far end did not advertise its port"

type Port = tuple[str, str]
"""A device id and a port's short name."""
type Names = Callable[[str], str]
"""What a summary calls a device, by id."""


@dataclass(frozen=True, slots=True)
class Cabling:
    """The Links and Shared Segments, and the findings flagging disagreements."""

    links: tuple[Link, ...]
    segments: tuple[SharedSegment, ...]
    findings: tuple[Finding, ...]


def cabling(claims: Sequence[Claim], names: Names) -> Cabling:
    """Turn every claim into Links and Shared Segments."""
    on_segment = _segment_claims(claims)
    segments = _segments([claims[i] for i in sorted(on_segment)])
    links = _links([c for i, c in enumerate(claims) if i not in on_segment])
    links, findings = _conflicts(links, names)
    return Cabling(
        links=tuple(sorted(links, key=lambda link: link.id)),
        segments=tuple(sorted(segments, key=lambda s: s.id)),
        findings=findings,
    )


def _near(claim: Claim) -> Port:
    return (claim.reporter, claim.local.short)


def _far(claim: Claim) -> Port | None:
    if isinstance(claim.far_port, Unknown):
        return None
    return (claim.far, claim.far_port.short)


def _segment_claims(claims: Sequence[Claim]) -> set[int]:
    """Return the indexes of claims that belong to a Shared Segment."""
    heard: dict[Port, set[str]] = {}
    for claim in claims:
        heard.setdefault(_near(claim), set()).add(claim.far)
    on_segment = {port for port, devices in heard.items() if len(devices) >= 2}  # noqa: PLR2004 (story 129)
    taken: set[int] = set()
    changed = True
    while changed:
        changed = False
        for index, claim in enumerate(claims):
            if index in taken:
                continue
            far = _far(claim)
            if _near(claim) in on_segment or (far is not None and far in on_segment):
                taken.add(index)
                on_segment.add(_near(claim))
                if far is not None:
                    on_segment.add(far)
                changed = True
    return taken


def _segments(claims: list[Claim]) -> list[SharedSegment]:
    """Group segment claims into one Shared Segment per connected set of ports."""
    parent: dict[object, object] = {}

    def root(item: object) -> object:
        parent.setdefault(item, item)
        while parent[item] != item:
            item = parent[item]
        return item

    for index, claim in enumerate(claims):
        far = _far(claim) or ("unknown", claim.far, index)
        parent[root(far)] = root(_near(claim))
    groups: dict[object, list[Claim]] = {}
    for claim in claims:
        groups.setdefault(root(_near(claim)), []).append(claim)
    return [_segment(group) for group in groups.values()]


def _segment(group: list[Claim]) -> SharedSegment:
    known: dict[Port, SegmentPort] = {}
    unknown_port: set[str] = set()
    for claim in group:
        known[_near(claim)] = SegmentPort(claim.reporter, claim.local)
        far = _far(claim)
        if far is None:
            unknown_port.add(claim.far)
        elif not isinstance(claim.far_port, Unknown):
            known.setdefault(far, SegmentPort(claim.far, claim.far_port))
    with_ports = {device for device, _ in known}
    ports = [known[p] for p in sorted(known)] + [
        SegmentPort(device, Unknown(NOT_ADVERTISED)) for device in sorted(unknown_port - with_ports)
    ]
    keys = [f"{p.device}:{_short(p.interface)}" for p in ports]
    return SharedSegment(
        id=ids.hashed("seg", sorted(keys)),
        ports=tuple(ports),
        evidence=_evidence(group),
    )


def _links(claims: list[Claim]) -> list[Link]:
    """Join claims of the same port pair into Links.

    A claim without the far port joins the one Link from its port to that device, if there
    is exactly one.
    """
    pairs: dict[frozenset[Port], list[Claim]] = {}
    for claim in claims:
        far = _far(claim)
        if far is not None:
            pairs.setdefault(frozenset({_near(claim), far}), []).append(claim)
    open_ended: dict[tuple[Port, str], list[Claim]] = {}
    for claim in claims:
        if _far(claim) is not None:
            continue
        near = _near(claim)
        matches = [
            pair
            for pair in pairs
            if near in pair and any(p[0] == claim.far and p != near for p in pair)
        ]
        if len(matches) == 1:
            pairs[matches[0]].append(claim)
        else:
            open_ended.setdefault((near, claim.far), []).append(claim)
    made = [_link(group) for group in pairs.values()]
    made.extend(_link(group) for group in open_ended.values())
    return made


def _link(group: list[Claim]) -> Link:
    ports: dict[Port, LinkEnd] = {}
    for claim in group:
        ports.setdefault(_near(claim), LinkEnd(claim.reporter, claim.local))
    for claim in group:
        far = _far(claim)
        if far is not None:
            ports.setdefault(far, LinkEnd(claim.far, claim.far_port))
    ends = sorted(ports.values(), key=_end_order)
    if len(ends) == 1:  # the far port was not advertised, or a port hears itself
        claim = group[0]
        far_end = (
            ends[0] if _far(claim) is not None else LinkEnd(claim.far, Unknown(NOT_ADVERTISED))
        )
        ends = sorted([ends[0], far_end], key=_end_order)
    first, second = ends
    reported = {_near(claim) for claim in group}
    confirmed = len(ports) == 2 and set(ports) <= reported  # noqa: PLR2004 (two ends)
    return Link(
        id=ids.hashed("link", [f"{e.device}:{_short(e.interface)}" for e in (first, second)]),
        ends=(first, second),
        status=LinkStatus.CONFIRMED if confirmed else LinkStatus.ONE_SIDED,
        evidence=_evidence(group),
        role=None,
        bundle=None,
        conflicts=(),
    )


def _conflicts(links: list[Link], names: Names) -> tuple[list[Link], tuple[Finding, ...]]:
    """Flag every port claimed by more than one Link, keeping every claim (story 125)."""
    by_port: dict[Port, list[Link]] = {}
    for link in links:
        for end in {
            (e.device, e.interface.short) for e in link.ends if not isinstance(e.interface, Unknown)
        }:
            by_port.setdefault(end, []).append(link)
    findings: list[Finding] = []
    flagged: dict[str, list[str]] = {}
    for (device, port), claiming in sorted(by_port.items()):
        if len(claiming) < 2:  # noqa: PLR2004 (two claims disagree)
            continue
        items = sorted(link.id for link in claiming)
        finding = Finding(
            id=ids.hashed("finding", [FindingKind.CONFLICTING_EVIDENCE.value, *items]),
            kind=FindingKind.CONFLICTING_EVIDENCE,
            summary=(
                f"Reports disagree about {port} on {names(device)}: {len(claiming)} Links claim it"
            ),
            devices=tuple(sorted({e.device for link in claiming for e in link.ends})),
            items=tuple(items),
            evidence=tuple(sorted({e for link in claiming for e in link.evidence}, key=_order)),
        )
        findings.append(finding)
        for item in items:
            flagged.setdefault(item, []).append(finding.id)
    updated = [replace(link, conflicts=tuple(flagged.get(link.id, ()))) for link in links]
    return updated, tuple(sorted(findings, key=lambda f: f.id))


def _evidence(claims: Iterable[Claim]) -> tuple[Evidence, ...]:
    return tuple(sorted({c.evidence for c in claims}, key=_order))


def _order(evidence: Evidence) -> tuple[str, str, str]:
    return (evidence.device, evidence.source.value, evidence.command)


def _end_order(end: LinkEnd) -> tuple[str, str]:
    return (end.device, _short(end.interface))


def _short(name: InterfaceName | Unknown) -> str:
    return "?" if isinstance(name, Unknown) else name.short
