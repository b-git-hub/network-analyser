"""Visited Devices, and which device each Neighbour advertisement is (stories 138, 140).

A Visited Device is known by every address it has: the one logged into, its learned aliases,
its interface addresses, and every address an advertisement already folded into it carried.
An advertisement of any of them is that device. The rest are merged into Unvisited Devices
only on a shared advertised address or LLDP chassis ID, never on a name (decided on #11).
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from network_analyser.records.collected import (
    NOT_COLLECTED,
    Collected,
    Interface,
    Neighbour,
    Reading,
)
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.events import DeviceOutcome
from network_analyser.records.interface_names import InterfaceName
from network_analyser.records.topology import (
    Evidence,
    EvidenceSource,
    Report,
    UnvisitedDevice,
    VisitedDevice,
)
from network_analyser.records.unknown import Unknown
from network_analyser.topology import ids

NO_DECISION = "no crawl decision was recorded for it"
NO_NAME = "no name was advertised"
NO_PLATFORM = "no Platform string was advertised"
INCOMPLETE_VLAN_DATABASE = "the VLAN database is incomplete"
NO_VLANS_ON_A_ROUTER = "VLANs do not apply to a router"
_NOT_READ = "show version not read"


@dataclass(frozen=True, slots=True)
class Known:
    """A Visited Device and what the rules read from it."""

    id: str
    record: DeviceRecord
    collected: Collected

    @property
    def name(self) -> str:
        """What a finding's summary calls it: its hostname, else its id."""
        version = self.record.version
        if version is not None and isinstance(version.hostname, str):
            return version.hostname
        return self.id

    @property
    def interfaces(self) -> tuple[Interface, ...]:
        """Its interfaces, or none when they were not collected."""
        found = self.collected.interfaces
        return found.value if isinstance(found, Reading) else ()


@dataclass(frozen=True, slots=True)
class Claim:
    """One CDP or LLDP entry, resolved: this port of `reporter` hears `far`'s `far_port`."""

    reporter: str
    local: InterfaceName
    far: str
    far_port: InterfaceName | Unknown
    evidence: Evidence


def known_devices(records: Iterable[DeviceRecord]) -> list[Known]:
    """Return the Visited Devices (visited or partial), in id order, each with its id."""
    visited = [r for r in records if r.outcome is not DeviceOutcome.UNVISITED]
    bases = [(_serials_or_unknown(r), r.ip, r) for r in visited]
    bases.sort(key=lambda b: (ids.device_id(b[0], b[1]), b[1]))
    made = ids.unique(ids.device_id(s, address) for s, address, _ in bases)
    return sorted(
        (
            Known(i, r, r.collected or Collected.nothing(NOT_COLLECTED))
            for i, (_, _, r) in zip(made, bases, strict=True)
        ),
        key=lambda k: k.id,
    )


def visited_device(known: Known, addresses: dict[IPv4Address, str]) -> VisitedDevice:
    """Return the Topology's record of a Visited Device. It holds no username (story 141)."""
    record = known.record
    version = record.version
    unknown = Unknown(_NOT_READ)
    stack = known.collected.stack_members
    interfaces = known.collected.interfaces
    vpc = known.collected.vpc
    aliases = sorted(a for a, owner in addresses.items() if owner == known.id and a != record.ip)
    return VisitedDevice(
        id=known.id,
        outcome=record.outcome,
        partial_reason=record.partial_reason,
        hostname=version.hostname if version else unknown,
        platform=record.platform or Unknown("Platform not identified"),
        model=version.model if version else unknown,
        software_version=version.software_version if version else unknown,
        serials=_serials_or_unknown(record),
        stack_members=stack.value if isinstance(stack, Reading) else stack,
        management_ip=record.ip,
        alias_ips=tuple(aliases),
        interfaces=interfaces.value if isinstance(interfaces, Reading) else interfaces,
        vlan_database=vlan_database(known),
        vpc=vpc.value if isinstance(vpc, Reading) else vpc,
        hardware_series=version.hardware_series if version else None,
        router_operating_mode=version.router_operating_mode if version else None,
    )


def vlan_database(device: Known) -> frozenset[int] | Unknown:
    """Return the VLANs in a device's VLAN database, active or not; unknown if incomplete."""
    reading = device.collected.vlans
    if reading is None:
        return Unknown(NO_VLANS_ON_A_ROUTER)
    if not isinstance(reading, Reading):
        return reading
    if reading.gaps:
        return Unknown(INCOMPLETE_VLAN_DATABASE)
    return frozenset(vlan.number for vlan in reading.value)


def own_addresses(devices: Sequence[Known]) -> dict[IPv4Address, str]:
    """Map each address a Visited Device has to its id.

    An earlier claim on an address is kept: addresses logged into first, then aliases, then
    interface addresses.
    """
    owners: dict[IPv4Address, str] = {}
    for device in devices:
        owners.setdefault(device.record.ip, device.id)
    for device in devices:
        for alias in device.record.aliases:
            owners.setdefault(alias, device.id)
    for device in devices:
        for interface in device.interfaces:
            if isinstance(interface.ip, Unknown) or interface.ip is None:
                continue
            for address in interface.ip.addresses:
                owners.setdefault(address.ip, device.id)
    return owners


@dataclass(slots=True)
class _Sighting:
    """An advertisement, or a device the crawl tried or chose not to try."""

    keys: tuple[str, ...]
    ips: tuple[IPv4Address, ...]
    ipv6: tuple[IPv6Address, ...]
    report: Report | None = None
    neighbour: Neighbour | None = None
    reason: UnvisitedReason | None = None
    owner: str | None = None


def resolve(
    devices: Sequence[Known], records: Iterable[DeviceRecord], owners: dict[IPv4Address, str]
) -> tuple[list[Claim], list[UnvisitedDevice]]:
    """Resolve every CDP and LLDP entry to a device; return the claims and Unvisited Devices.

    `owners` (from `own_addresses`) gains every address an advertisement folded into a
    Visited Device carried.
    """
    sightings = [*_advertised(devices), *_tried(records)]
    keyed: dict[str, str] = {f"ip:{a}": owner for a, owner in owners.items()}
    _fold(sightings, keyed, owners)
    unvisited = _merge([s for s in sightings if s.owner is None])
    for device in unvisited:
        for sighting in device[1]:
            sighting.owner = device[0].id
    claims = [
        Claim(
            reporter=s.report.device,
            local=s.report.interface,
            far=s.owner,
            far_port=s.neighbour.remote_port,
            evidence=s.report.evidence,
        )
        for s in sightings
        if s.report is not None
        and s.report.interface is not None
        and s.neighbour is not None
        and s.owner is not None
    ]
    return claims, [device for device, _ in unvisited]


def _advertised(devices: Sequence[Known]) -> list[_Sighting]:
    found: list[_Sighting] = []
    for device in devices:
        for source, reading in (
            (EvidenceSource.CDP, device.collected.cdp),
            (EvidenceSource.LLDP, device.collected.lldp),
        ):
            if not isinstance(reading, Reading):
                continue
            evidence = Evidence(device.id, "; ".join(reading.commands), source)
            for entry in reading.value:
                keys = (
                    *(f"ip:{a}" for a in entry.addresses),
                    *(f"ip6:{a}" for a in entry.ipv6_addresses),
                    *((f"chassis:{entry.chassis_id}",) if entry.chassis_id else ()),
                )
                found.append(
                    _Sighting(
                        keys=keys,
                        ips=entry.addresses,
                        ipv6=entry.ipv6_addresses,
                        report=Report(device.id, entry.local_port, evidence),
                        neighbour=entry,
                    )
                )
    return found


def _tried(records: Iterable[DeviceRecord]) -> list[_Sighting]:
    return [
        _Sighting(keys=(f"ip:{r.ip}",), ips=(r.ip,), ipv6=(), reason=r.unvisited_reason)
        for r in sorted(
            (r for r in records if r.outcome is DeviceOutcome.UNVISITED), key=lambda r: r.ip
        )
    ]


def _fold(
    sightings: list[_Sighting], keyed: dict[str, str], owners: dict[IPv4Address, str]
) -> None:
    """Fold each sighting sharing a key with a Visited Device into it, until none is left."""
    changed = True
    while changed:
        changed = False
        for sighting in sightings:
            if sighting.owner is not None:
                continue
            owner = next((keyed[k] for k in sighting.keys if k in keyed), None)
            if owner is None:
                continue
            sighting.owner = owner
            changed = True
            for key in sighting.keys:
                keyed.setdefault(key, owner)
            for address in sighting.ips:
                owners.setdefault(address, owner)


def _merge(sightings: list[_Sighting]) -> list[tuple[UnvisitedDevice, list[_Sighting]]]:
    """Merge sightings sharing an address or chassis ID into Unvisited Devices."""
    parent = list(range(len(sightings)))

    def root(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    first_with: dict[str, int] = {}
    for index, sighting in enumerate(sightings):
        for key in sighting.keys:
            if key in first_with:
                parent[root(index)] = root(first_with[key])
            else:
                first_with[key] = index
    groups: dict[int, list[_Sighting]] = {}
    for index, sighting in enumerate(sightings):
        groups.setdefault(root(index), []).append(sighting)
    made = [(_unvisited(group), group) for group in groups.values()]
    return sorted(made, key=lambda m: m[0].id)


def _unvisited(group: list[_Sighting]) -> UnvisitedDevice:
    reports = sorted(
        (s for s in group if s.report is not None),
        key=lambda s: _report_order(s.report),
    )
    ips = sorted({a for s in group for a in s.ips})
    ipv6 = sorted({a for s in group for a in s.ipv6})
    chassis = sorted(
        {k.removeprefix("chassis:") for s in group for k in s.keys if k.startswith("chassis:")}
    )
    names = [s.neighbour.name for s in reports if s.neighbour and isinstance(s.neighbour.name, str)]
    platforms = [
        s.neighbour.platform
        for s in reports
        if s.neighbour and isinstance(s.neighbour.platform, str)
    ]
    reasons = [s.reason for s in group if s.reason is not None]
    reason: UnvisitedReason | Unknown
    if reasons:
        reason = reasons[0]
    elif not ips and ipv6:
        reason = UnvisitedReason.IPV6_ONLY
    else:
        reason = Unknown(NO_DECISION)
    return UnvisitedDevice(
        id=ids.hashed("unv", [_merge_key(ips, chassis, ipv6, reports)]),
        reason=reason,
        label=names[0] if names else Unknown(NO_NAME),
        advertised_platform=platforms[0] if platforms else Unknown(NO_PLATFORM),
        advertised_ips=tuple(ips),
        advertised_ipv6=tuple(ipv6),
        chassis_id=chassis[0] if chassis else None,
        reported_by=tuple(s.report for s in reports if s.report is not None),
    )


def _merge_key(
    ips: list[IPv4Address], chassis: list[str], ipv6: list[IPv6Address], reports: list[_Sighting]
) -> str:
    """Return what an Unvisited Device's id is made from.

    That is its lowest address, else its chassis ID, else the one report it is known from.
    """
    if ips:
        return f"ip:{ips[0]}"
    if chassis:
        return f"chassis:{chassis[0]}"
    if ipv6:
        return f"ip6:{ipv6[0]}"
    report = reports[0].report if reports and reports[0].report else None
    if report is None or report.interface is None:
        return "none"
    return f"heard:{report.device}:{report.interface.short}:{report.evidence.source.value}"


def _report_order(report: Report | None) -> tuple[str, str, str]:
    if report is None:
        return ("", "", "")
    port = report.interface.short if report.interface is not None else ""
    return (report.device, port, report.evidence.source.value)


def _serials_or_unknown(record: DeviceRecord) -> tuple[str, ...] | Unknown:
    if record.version is None:
        return Unknown(_NOT_READ)
    return record.version.serials
