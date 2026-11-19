"""VLAN Mismatches on Links and Bundles (stories 134 and 135; #61).

A trunk's effective VLANs are the ones it allows that are also in its VLAN database. A VLAN
listed there counts whether or not it is active. The four kinds are: VLAN on one end only,
differing native VLAN, trunk facing access, and differing access VLANs.

A mismatch is raised only when both ends are Visited Devices and the fields it needs were
collected. The exception is native VLAN: CDP's advertised native VLAN counts for an Unvisited
Device, and is not used to guess that device's mode. Anything missing is a skipped check,
never a mismatch. Member Links of a Bundle are not checked; the Bundle's port-channels are.
Ends on the same side of a Bundle (a vPC pair) are compared only with the other side.
"""

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from network_analyser.records.collected import Neighbour, Reading, SwitchportMode
from network_analyser.records.interface_names import InterfaceName, interface_name
from network_analyser.records.topology import (
    Bundle,
    Evidence,
    EvidenceSource,
    Finding,
    FindingKind,
    Link,
    SkippedCheck,
    UnvisitedDevice,
)
from network_analyser.records.unknown import Unknown
from network_analyser.topology import ids
from network_analyser.topology.devices import Known

DATA: Final = "vlan_mismatch"
"""`skipped.data` for a VLAN check that could not run. Not a `Collected` field."""
NO_CHANNEL: Final = "the bundle has no port-channel to read"
PORT_MISSING: Final = "the port was not collected"
PORT_CHANNEL_MISSING: Final = "the port-channel was not collected"
_LOWEST_PRINTABLE: Final = 32
_HIGHEST_PRINTABLE: Final = 126


@dataclass(frozen=True, slots=True)
class VlanChecks:
    """The VLAN Mismatch findings, and the checks listed as skipped."""

    findings: tuple[Finding, ...]
    skipped: tuple[SkippedCheck, ...]


@dataclass(frozen=True, slots=True)
class _Port:
    device: str
    interface: InterfaceName | Unknown
    bundle: bool


@dataclass(frozen=True, slots=True)
class _Subject:
    id: str
    sides: tuple[tuple[_Port, ...], tuple[_Port, ...]]


@dataclass(frozen=True, slots=True)
class _End:
    device: str
    port: str
    visited: bool
    mode: SwitchportMode | Unknown
    access: int | Unknown | None
    native: int | Unknown | None
    allowed: frozenset[int] | Unknown | None
    database: frozenset[int] | Unknown
    interface_command: str | None
    vlan_command: str | None
    cdp_command: str | None
    cdp_reporter: str | None


type _Selector = Callable[[_End], int | Unknown | None]


@dataclass(frozen=True, slots=True)
class _Fact:
    kind: FindingKind
    token: str
    device: str
    port: str
    vlan: int | None
    role: str
    evidence: tuple[Evidence, ...]
    parties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Result:
    facts: tuple[_Fact, ...]
    skips: tuple[SkippedCheck, ...]


@dataclass(frozen=True, slots=True)
class _World:
    devices: Mapping[str, Known]
    unvisited: Mapping[str, UnvisitedDevice]
    names: Mapping[str, str]


def vlan_checks(
    links: Sequence[Link],
    bundles: Sequence[Bundle],
    devices: Sequence[Known],
    unvisited: Sequence[UnvisitedDevice],
) -> VlanChecks:
    """Return VLAN Mismatch findings and the checks that were skipped.

    Args:
        links: the Run's Links, members already pointing at their Bundle.
        bundles: the Run's Bundles.
        devices: the Visited Devices.
        unvisited: the Unvisited Devices.
    """
    world = _world(devices, unvisited)
    findings: list[Finding] = []
    skips: list[SkippedCheck] = []
    for subject in _subjects(links, bundles):
        result = _check(world, subject)
        findings.extend(_findings(result.facts, subject.id, world.names))
        skips.extend(result.skips)
    return VlanChecks(
        tuple(sorted(findings, key=lambda finding: finding.id)),
        tuple(sorted(set(skips), key=lambda check: (check.device, check.data, check.reason))),
    )


def _world(devices: Sequence[Known], unvisited: Sequence[UnvisitedDevice]) -> _World:
    names = {device.id: _shown(device.name) for device in devices}
    for device in unvisited:
        label = device.label if isinstance(device.label, str) else device.id
        names[device.id] = _shown(label)
    return _World({item.id: item for item in devices}, {item.id: item for item in unvisited}, names)


def _subjects(links: Sequence[Link], bundles: Sequence[Bundle]) -> list[_Subject]:
    made = [
        _Subject(
            link.id,
            (
                (_Port(link.ends[0].device, link.ends[0].interface, bundle=False),),
                (_Port(link.ends[1].device, link.ends[1].interface, bundle=False),),
            ),
        )
        for link in links
        if link.bundle is None
    ]
    made.extend(_Subject(bundle.id, _bundle_sides(bundle)) for bundle in bundles)
    return made


def _bundle_sides(bundle: Bundle) -> tuple[tuple[_Port, ...], tuple[_Port, ...]]:
    first, second = bundle.sides
    return (
        tuple(_Port(end.device, _channel(end.port_channel), bundle=True) for end in first.ends),
        tuple(_Port(end.device, _channel(end.port_channel), bundle=True) for end in second.ends),
    )


def _channel(channel: str | Unknown | None) -> InterfaceName | Unknown:
    if isinstance(channel, str):
        return interface_name(channel)
    if isinstance(channel, Unknown):
        return channel
    return Unknown(NO_CHANNEL)


def _check(world: _World, subject: _Subject) -> _Result:
    facts: list[_Fact] = []
    skips: list[SkippedCheck] = []
    for near in subject.sides[0]:
        for far in subject.sides[1]:
            result = _compare(_load(world, near, far), _load(world, far, near), subject.id)
            facts.extend(result.facts)
            skips.extend(result.skips)
    return _Result(tuple(facts), tuple(skips))


def _compare(near: _End, far: _End, subject: str) -> _Result:
    if near.visited and far.visited:
        return _visited_pair(near, far, subject)
    if near.visited or far.visited:
        return _unvisited_pair(near, far, subject)
    return _Result((), ())


def _visited_pair(near: _End, far: _End, subject: str) -> _Result:
    if isinstance(near.mode, Unknown) or isinstance(far.mode, Unknown):
        return _Result((), _mode_skips(near, far, subject))
    if near.mode is SwitchportMode.TRUNK and far.mode is SwitchportMode.TRUNK:
        return _trunks(near, far, subject)
    if near.mode is SwitchportMode.ACCESS and far.mode is SwitchportMode.ACCESS:
        return _access_pair(near, far, subject)
    if {near.mode, far.mode} == {SwitchportMode.TRUNK, SwitchportMode.ACCESS}:
        return _Result(_trunk_access(near, far), ())
    return _Result((), ())


def _mode_skips(near: _End, far: _End, subject: str) -> tuple[SkippedCheck, ...]:
    skips: list[SkippedCheck] = []
    if isinstance(near.mode, Unknown):
        skips.append(_skip(near.device, near.mode.reason, subject))
    if isinstance(far.mode, Unknown):
        skips.append(_skip(far.device, far.mode.reason, subject))
    return tuple(skips)


@dataclass(frozen=True, slots=True)
class _Compare:
    """One numeric VLAN comparison: which kind, and how to read the number."""

    kind: FindingKind
    role: str
    missing: str
    select: _Selector
    database: bool


def _trunks(near: _End, far: _End, subject: str) -> _Result:
    native = _numbers(
        near,
        far,
        subject,
        _Compare(
            FindingKind.DIFFERING_NATIVE_VLAN,
            "native",
            "native VLAN not recorded",
            lambda end: end.native,
            database=False,
        ),
    )
    effective = _effective_findings(near, far, subject)
    return _Result((*native.facts, *effective.facts), (*native.skips, *effective.skips))


def _access_pair(near: _End, far: _End, subject: str) -> _Result:
    return _numbers(
        near,
        far,
        subject,
        _Compare(
            FindingKind.DIFFERING_ACCESS_VLANS,
            "access",
            "access VLAN not recorded",
            lambda end: end.access,
            database=False,
        ),
    )


def _numbers(near: _End, far: _End, subject: str, spec: _Compare) -> _Result:
    left = _number(spec.select(near), spec.missing)
    right = _number(spec.select(far), spec.missing)
    skips: list[SkippedCheck] = []
    if isinstance(left, Unknown):
        skips.append(_skip(near.device, left.reason, subject))
    if isinstance(right, Unknown):
        skips.append(_skip(far.device, right.reason, subject))
    if skips or not isinstance(left, int) or not isinstance(right, int) or left == right:
        return _Result((), tuple(skips))
    return _Result(
        (
            _fact(spec.kind, near, far, (spec.role, left), database=spec.database),
            _fact(spec.kind, far, near, (spec.role, right), database=spec.database),
        ),
        (),
    )


def _number(value: int | Unknown | None, missing: str) -> int | Unknown:
    if isinstance(value, bool) or not isinstance(value, int):
        return value if isinstance(value, Unknown) else Unknown(missing)
    return value


def _effective_findings(near: _End, far: _End, subject: str) -> _Result:
    left = _effective(near)
    right = _effective(far)
    skips: list[SkippedCheck] = []
    if isinstance(left, Unknown):
        skips.append(_skip(near.device, left.reason, subject))
    if isinstance(right, Unknown):
        skips.append(_skip(far.device, right.reason, subject))
    if isinstance(left, Unknown) or isinstance(right, Unknown):
        return _Result((), tuple(skips))
    facts = [
        _fact(FindingKind.VLAN_ON_ONE_END, near, far, ("only", vlan), database=True)
        for vlan in sorted(left - right)
    ]
    facts.extend(
        _fact(FindingKind.VLAN_ON_ONE_END, far, near, ("only", vlan), database=True)
        for vlan in sorted(right - left)
    )
    return _Result(tuple(facts), ())


def _effective(end: _End) -> frozenset[int] | Unknown:
    if isinstance(end.allowed, Unknown):
        return end.allowed
    if end.allowed is None:
        return Unknown("allowed VLANs not recorded")
    if isinstance(end.database, Unknown):
        return end.database
    return end.allowed & end.database


def _trunk_access(near: _End, far: _End) -> tuple[_Fact, ...]:
    trunk, access = (near, far) if near.mode is SwitchportMode.TRUNK else (far, near)
    evidence = (
        *_evidence(trunk, database=False),
        *_evidence(access, database=False),
    )
    parties = (trunk.device, access.device)
    return (
        _Fact(
            FindingKind.TRUNK_FACING_ACCESS,
            f"trunk:{trunk.device}",
            trunk.device,
            trunk.port,
            None,
            "trunk",
            evidence,
            parties,
        ),
        _Fact(
            FindingKind.TRUNK_FACING_ACCESS,
            f"access:{access.device}",
            access.device,
            access.port,
            None,
            "access",
            evidence,
            parties,
        ),
    )


def _unvisited_pair(near: _End, far: _End, subject: str) -> _Result:
    visited, other = (near, far) if near.visited else (far, near)
    skips = [_skip(visited.device, "the far end is an Unvisited Device", subject)]
    if not isinstance(visited.mode, SwitchportMode) or visited.mode is not SwitchportMode.TRUNK:
        if isinstance(visited.mode, Unknown):
            skips.append(_skip(visited.device, visited.mode.reason, subject))
        return _Result((), tuple(skips))
    local = _number(visited.native, "native VLAN not recorded")
    remote = _number(other.native, "CDP advertised no native VLAN")
    if isinstance(local, Unknown):
        skips.append(_skip(visited.device, local.reason, subject))
    if isinstance(remote, Unknown):
        skips.append(_skip(visited.device, remote.reason, subject))
    if not isinstance(local, int) or not isinstance(remote, int) or local == remote:
        return _Result((), tuple(skips))
    return _Result(
        (
            _fact(
                FindingKind.DIFFERING_NATIVE_VLAN,
                visited,
                other,
                ("native", local),
                database=False,
            ),
            _fact(
                FindingKind.DIFFERING_NATIVE_VLAN,
                other,
                visited,
                ("native", remote),
                database=False,
            ),
        ),
        tuple(skips),
    )


def _fact(
    kind: FindingKind,
    end: _End,
    other: _End,
    marked: tuple[str, int],
    *,
    database: bool,
) -> _Fact:
    role, vlan = marked
    return _Fact(
        kind,
        f"{role}:{end.device}:{vlan}",
        end.device,
        end.port,
        vlan,
        role,
        (*_evidence(end, database=database), *_evidence(other, database=database)),
        (end.device, other.device),
    )


def _evidence(end: _End, *, database: bool) -> tuple[Evidence, ...]:
    found: list[Evidence] = []
    if end.visited and end.interface_command:
        found.append(Evidence(end.device, end.interface_command, EvidenceSource.VLAN))
    if database and end.visited and end.vlan_command:
        found.append(Evidence(end.device, end.vlan_command, EvidenceSource.VLAN))
    reporter = end.cdp_reporter
    if not end.visited and end.cdp_command and reporter is not None:
        found.append(Evidence(reporter, end.cdp_command, EvidenceSource.CDP))
    return tuple(found)


def _findings(facts: Sequence[_Fact], subject: str, names: Mapping[str, str]) -> list[Finding]:
    grouped: dict[FindingKind, list[_Fact]] = {}
    for fact in facts:
        grouped.setdefault(fact.kind, []).append(fact)
    made: list[Finding] = []
    for kind, group in grouped.items():
        tokens = tuple(sorted({fact.token for fact in group}))
        evidence = tuple(
            sorted(
                {item for fact in group for item in fact.evidence},
                key=lambda item: (item.device, item.source.value, item.command),
            )
        )
        devices = tuple(sorted({party for fact in group for party in fact.parties}))
        made.append(
            Finding(
                id=ids.hashed("finding", [kind.value, subject, *tokens]),
                kind=kind,
                summary=_summary(kind, group, names),
                devices=devices,
                items=(subject,),
                evidence=evidence,
            )
        )
    return made


def _summary(kind: FindingKind, facts: Sequence[_Fact], names: Mapping[str, str]) -> str:
    ordered = sorted(facts, key=lambda fact: fact.token)
    if kind is FindingKind.VLAN_ON_ONE_END:
        return "VLAN on one end only: " + "; ".join(_only_clauses(ordered, names))
    if kind is FindingKind.TRUNK_FACING_ACCESS:
        return "Trunk facing access: " + "; ".join(_mode_clauses(ordered, names))
    label = (
        "Differing native VLAN"
        if kind is FindingKind.DIFFERING_NATIVE_VLAN
        else "Differing access VLANs"
    )
    return f"{label}: " + "; ".join(_vlan_clauses(ordered, names))


def _only_clauses(facts: Sequence[_Fact], names: Mapping[str, str]) -> list[str]:
    grouped: dict[str, list[_Fact]] = {}
    for fact in facts:
        grouped.setdefault(fact.device, []).append(fact)
    return [
        f"{_ranges(fact.vlan for fact in grouped[device])} on {names.get(device, device)} "
        f"{grouped[device][0].port} only"
        for device in sorted(grouped)
    ]


def _vlan_clauses(facts: Sequence[_Fact], names: Mapping[str, str]) -> list[str]:
    return [
        f"{fact.vlan} on {names.get(fact.device, fact.device)} {fact.port}"
        for fact in facts
        if fact.vlan is not None
    ]


def _mode_clauses(facts: Sequence[_Fact], names: Mapping[str, str]) -> list[str]:
    return [f"{fact.role} {fact.port} on {names.get(fact.device, fact.device)}" for fact in facts]


def _ranges(numbers: Iterable[int | None]) -> str:
    return _range_text(sorted({number for number in numbers if isinstance(number, int)}))


def _range_text(ordered: list[int]) -> str:
    if not ordered:
        return ""
    parts: list[str] = []
    start = previous = ordered[0]
    for number in ordered[1:]:
        if number == previous + 1:
            previous = number
            continue
        parts.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = number
    parts.append(str(start) if start == previous else f"{start}-{previous}")
    return ", ".join(parts)


def _skip(device: str, reason: str, subject: str) -> SkippedCheck:
    return SkippedCheck(device, DATA, f"VLAN check skipped: {reason} ({subject})")


def _load(world: _World, port: _Port, other: _Port) -> _End:
    device = world.devices.get(port.device)
    if device is None:
        return _unvisited_end(world, port, other)
    return _visited_end(device, port)


def _visited_end(device: Known, port: _Port) -> _End:
    label = _port_label(port.interface)
    database = _database(device)
    vlan_command = _command(device.collected.vlans)
    if isinstance(port.interface, Unknown):
        return _blank(device.id, label, port.interface, database, (vlan_command, None))
    reading = device.collected.interfaces
    if not isinstance(reading, Reading):
        return _blank(device.id, label, reading, database, (vlan_command, None))
    command = "; ".join(reading.commands) or None
    found = next((item for item in reading.value if item.name.short == port.interface.short), None)
    if found is None:
        reason = PORT_CHANNEL_MISSING if port.bundle else PORT_MISSING
        return _blank(device.id, label, Unknown(reason), database, (vlan_command, command))
    return _End(
        device=device.id,
        port=label,
        visited=True,
        mode=found.mode,
        access=found.access_vlan,
        native=found.native_vlan,
        allowed=found.allowed_vlans,
        database=database,
        interface_command=command,
        vlan_command=vlan_command,
        cdp_command=None,
        cdp_reporter=None,
    )


def _blank(
    device: str,
    port: str,
    missing: Unknown,
    database: frozenset[int] | Unknown,
    commands: tuple[str | None, str | None],
) -> _End:
    vlan_command, interface_command = commands
    return _End(
        device=device,
        port=port,
        visited=True,
        mode=missing,
        access=missing,
        native=missing,
        allowed=missing,
        database=database,
        interface_command=interface_command,
        vlan_command=vlan_command,
        cdp_command=None,
        cdp_reporter=None,
    )


def _unvisited_end(world: _World, port: _Port, other: _Port) -> _End:
    far = world.unvisited.get(port.device)
    reporter = world.devices.get(other.device)
    native, command, reporter_id = _advertised_native(
        reporter, other.interface, far, port.interface
    )
    missing = Unknown("unvisited device")
    return _End(
        device=port.device,
        port=_port_label(port.interface),
        visited=False,
        mode=missing,
        access=missing,
        native=native,
        allowed=missing,
        database=missing,
        interface_command=None,
        vlan_command=None,
        cdp_command=command,
        cdp_reporter=reporter_id,
    )


def _advertised_native(
    reporter: Known | None,
    local: InterfaceName | Unknown,
    far: UnvisitedDevice | None,
    far_port: InterfaceName | Unknown,
) -> tuple[int | Unknown, str | None, str | None]:
    """Return the native VLAN CDP advertised for `far`, plus the command and reporter."""
    if reporter is None or far is None:
        return Unknown("CDP advertised no native VLAN"), None, None
    reading = reporter.collected.cdp
    if not isinstance(reading, Reading):
        return Unknown(reading.reason), None, reporter.id
    if isinstance(local, Unknown):
        return Unknown(PORT_MISSING), None, reporter.id
    matched = [
        entry
        for entry in reading.value
        if entry.local_port.short == local.short and _names_far(entry, far, far_port)
    ]
    command = "; ".join(reading.commands) or None
    natives = {entry.native_vlan for entry in matched}
    if len(natives) == 1:
        native = next(iter(natives))
        if isinstance(native, int):
            return native, command, reporter.id
    return Unknown("CDP advertised no native VLAN"), command, reporter.id


def _names_far(entry: Neighbour, far: UnvisitedDevice, far_port: InterfaceName | Unknown) -> bool:
    if any(address in far.advertised_ips for address in entry.addresses):
        return True
    if entry.chassis_id is not None and entry.chassis_id == far.chassis_id:
        return True
    return (
        not entry.addresses
        and far.chassis_id is None
        and not isinstance(far_port, Unknown)
        and not isinstance(entry.remote_port, Unknown)
        and entry.remote_port.short == far_port.short
    )


def _database(device: Known) -> frozenset[int] | Unknown:
    reading = device.collected.vlans
    if not isinstance(reading, Reading):
        return reading
    if reading.gaps:
        return Unknown("the VLAN database is incomplete")
    return frozenset(vlan.number for vlan in reading.value)


def _command(reading: Reading[object] | Unknown | None) -> str | None:
    if isinstance(reading, Reading):
        return "; ".join(reading.commands) or None
    return None


def _port_label(name: InterfaceName | Unknown) -> str:
    if isinstance(name, Unknown):
        return "?"
    return _shown(name.short)


def _shown(text: str) -> str:
    """Return device text as printable ASCII, so a summary cannot carry a control character."""
    parts: list[str] = []
    for character in text:
        code = ord(character)
        if _LOWEST_PRINTABLE <= code <= _HIGHEST_PRINTABLE:
            parts.append(character)
        else:
            parts.append(f"\\u{code:04x}")
    return "".join(parts)
