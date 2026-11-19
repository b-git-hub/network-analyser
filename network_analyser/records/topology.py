"""The Topology record: what `topology.build` makes and `topology.json` holds (#52).

Its shape is the `topology.json` schema (docs/topology-json.md): each record becomes a JSON
object with the same field names. VLAN Mismatches (#61) add four finding kinds and a
`vlan_mismatch` skipped row. Later tickets add L3 Adjacency, Subnets and inferred Links (#62).
A new optional field needs no format-version bump;
a change an older `render` would misread does (`topology.FORMAT_VERSION`).

**Stable ids** (`id` fields) are shared by `topology.json`, the diagram (`#device=<id>`,
`#finding=<id>`) and the Run report. Each is worked out from what it names, never from the
order things were found, so the same network gives the same ids in every Run:

- a Visited Device: `dev-<first serial>`, or `dev-ip-<management IP>` when no serial is known;
- an Unvisited Device: `unv-` and 12 hex digits from the address or chassis ID it was merged
  on;
- a Link, Shared Segment, Bundle or finding: `link-`, `seg-`, `bundle-` or `finding-` and 12
  hex digits from its ends or subjects.

Ids use only letters, digits, `.`, `-` and `_`. Other items point to devices by id.
No record here holds a username (story 141).
"""

from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address, IPv6Address

from network_analyser.records.collected import Interface, StackMember, VpcState
from network_analyser.records.device import UnvisitedReason
from network_analyser.records.events import DeviceOutcome
from network_analyser.records.interface_names import InterfaceName
from network_analyser.records.platform import Platform
from network_analyser.records.unknown import Unknown


@unique
class EvidenceSource(Enum):
    """Where a fact came from (story 124)."""

    CDP = "CDP"
    LLDP = "LLDP"
    ROUTING = "routing"
    MAC = "MAC"
    ARP = "ARP"
    VLAN = "VLAN"
    """Switchport or VLAN-database output. A CDP native VLAN stays `CDP` (#61)."""


@dataclass(frozen=True, slots=True)
class Evidence:
    """One device's report behind a fact: which device, which command, which source.

    Attributes:
        device: the id of the device that reported it.
        command: the command, exactly as sent, whose output said so.
        source: CDP, LLDP, routing, MAC, ARP, or VLAN (switchport and the VLAN database).
    """

    device: str
    command: str
    source: EvidenceSource


@dataclass(frozen=True, slots=True)
class VisitedDevice:
    """A Visited Device in the Topology (story 140; #11 point 10).

    Attributes:
        id: its stable id.
        outcome: visited, or partial when its examination stopped short.
        partial_reason: why it is partial, as fixed text; None when visited in full.
        platform: the Platform identified after login.
        serials: every chassis serial, one per stack member.
        stack_members: the member switches.
        management_ip: the address the tool logged into.
        alias_ips: its other addresses: learned aliases, and its interface addresses.
        interfaces: every interface, down ones included.
        vpc: its vPC domain; None when it has none.
    """

    id: str
    outcome: DeviceOutcome
    partial_reason: str | None
    hostname: str | Unknown
    platform: Platform | Unknown
    model: str | Unknown
    software_version: str | Unknown
    serials: tuple[str, ...] | Unknown
    stack_members: tuple[StackMember, ...] | Unknown
    management_ip: IPv4Address
    alias_ips: tuple[IPv4Address, ...]
    interfaces: tuple[Interface, ...] | Unknown
    vpc: VpcState | Unknown | None


@dataclass(frozen=True, slots=True)
class Report:
    """One Visited Device's report of an Unvisited Device.

    Attributes:
        device: the id of the Visited Device that reported it.
        interface: the reporting device's port it was heard on; None when not heard on a
            port (a device the tool tried to visit itself).
        evidence: the command and source.
    """

    device: str
    interface: InterfaceName | None
    evidence: Evidence


@dataclass(frozen=True, slots=True)
class UnvisitedDevice:
    """An Unvisited Device: known to exist, but not a Visited Device (#11 point 9).

    Advertisements are merged into one only on a shared advertised IP or LLDP chassis ID,
    never on a name (story 138).

    Attributes:
        id: its stable id.
        reason: one of the 13 fixed reasons; `Unknown` when the crawl recorded none for it.
        label: the name it advertised, for display only: the first in `reported_by` order.
        advertised_platform: the Platform string it advertised, the first likewise.
        advertised_ips: every IPv4 address it advertised or was tried at, lowest first.
        advertised_ipv6: every IPv6 address it advertised, lowest first.
        chassis_id: its LLDP chassis ID; None when none was advertised.
        reported_by: which Visited Devices reported it, on which port, and how; in order of
            device id, port and source.
    """

    id: str
    reason: UnvisitedReason | Unknown
    label: str | Unknown
    advertised_platform: str | Unknown
    advertised_ips: tuple[IPv4Address, ...]
    advertised_ipv6: tuple[IPv6Address, ...]
    chassis_id: str | None
    reported_by: tuple[Report, ...]


@unique
class LinkStatus(Enum):
    """How certain a Link is (story 128)."""

    CONFIRMED = "confirmed"
    """Both ends report each other."""
    ONE_SIDED = "one-sided"
    """Only one end reports it."""


@unique
class LinkRole(Enum):
    """What a Link or Bundle is for, where the tool can tell (story 132)."""

    VPC_PEER_LINK = "vPC peer-link"
    VPC_PEER_KEEPALIVE = "vPC peer-keepalive"


@dataclass(frozen=True, slots=True)
class LinkEnd:
    """One end of a Link: a device and its port.

    Attributes:
        device: the id of a Visited or Unvisited Device.
        interface: its port; `Unknown` when the far end's port was not advertised.
    """

    device: str
    interface: InterfaceName | Unknown


@dataclass(frozen=True, slots=True)
class Link:
    """A physical Link between two ports, from either end's CDP or LLDP report (story 128).

    CDP and LLDP reports of the same port pair are one Link. When reports disagree, every
    claim is kept as its own Link and each carries the conflict (story 125).

    Attributes:
        id: its stable id.
        ends: its two ends, in id order.
        status: confirmed when both ends report each other, else one-sided.
        evidence: every report behind it.
        role: vPC peer-link or peer-keepalive; None otherwise.
        bundle: the id of the Bundle it is a member of; None when in none.
        conflicts: the ids of the findings that flag a disagreement about it.
    """

    id: str
    ends: tuple[LinkEnd, LinkEnd]
    status: LinkStatus
    evidence: tuple[Evidence, ...]
    role: LinkRole | None
    bundle: str | None
    conflicts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SegmentPort:
    """A port attached to a Shared Segment."""

    device: str
    interface: InterfaceName | Unknown


@dataclass(frozen=True, slots=True)
class SharedSegment:
    """A part of the network the tool cannot see, such as an unmanaged switch (story 129).

    It is known because a port hears two or more Neighbours. Overlapping views are one.

    Attributes:
        id: its stable id.
        ports: every port seen on it, in order.
        evidence: every report behind it.
    """

    id: str
    ports: tuple[SegmentPort, ...]
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True, slots=True)
class BundleEnd:
    """A port-channel on one device at one side of a Bundle.

    Attributes:
        device: the device's id.
        port_channel: the port-channel's short name, such as `Po10`; None when the members
            on this device are in no port-channel (flagged); `Unknown` when it cannot be told.
    """

    device: str
    port_channel: str | Unknown | None


@dataclass(frozen=True, slots=True)
class BundleSide:
    """One side of a Bundle: one port-channel, or two for a vPC pair.

    Attributes:
        ends: one end, or one per vPC peer.
        vpc: the vPC number when the side is a vPC; None otherwise.
    """

    ends: tuple[BundleEnd, ...]
    vpc: int | None


@dataclass(frozen=True, slots=True)
class Bundle:
    """Physical Links joined into one port-channel, named after it at each end (story 131).

    A port-channel facing a vPC pair is one Bundle whose far side has two ends (story 132).

    Attributes:
        id: its stable id.
        sides: its two sides, in id order.
        links: the ids of its member Links.
        role: vPC peer-link; None otherwise.
        flagged: the ids of member Links whose far end is not in a matching bundle.
    """

    id: str
    sides: tuple[BundleSide, BundleSide]
    links: tuple[str, ...]
    role: LinkRole | None
    flagged: tuple[str, ...]


@unique
class FindingKind(Enum):
    """The kinds of finding the Topology raises. Later tickets add theirs (#62)."""

    CONFLICTING_EVIDENCE = "conflicting evidence"
    """Reports disagree about a port: kept, flagged, never resolved silently (story 125)."""
    BUNDLE_MEMBER_MISMATCH = "Bundle member mismatch"
    """A member Link whose far end is not in a matching bundle (story 131)."""
    VLAN_ON_ONE_END = "VLAN on one end only"
    """An effective VLAN carried on one end of a Link or Bundle only (story 134)."""
    DIFFERING_NATIVE_VLAN = "differing native VLAN"
    """The two ends' native VLANs differ (story 134)."""
    TRUNK_FACING_ACCESS = "trunk facing access"
    """A trunk faces an access port (story 134)."""
    DIFFERING_ACCESS_VLANS = "differing access VLANs"
    """The two ends' access VLANs differ (story 134)."""


@dataclass(frozen=True, slots=True)
class Finding:
    """Something the operator should look at, with a stable id (`#finding=<id>`).

    Attributes:
        id: its stable id.
        kind: what kind of finding.
        summary: one line saying what is wrong, built from fixed text and names.
        devices: the ids of the devices it concerns.
        items: the ids of the Links, Bundles or Shared Segments it concerns.
        evidence: the reports behind it.
    """

    id: str
    kind: FindingKind
    summary: str
    devices: tuple[str, ...]
    items: tuple[str, ...]
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True, slots=True)
class SkippedCheck:
    """Data that was not collected from a device, so the checks needing it were skipped.

    Attributes:
        device: the device's id.
        data: which part of the collected data, by its field name in `records.collected`
            (`cdp`, `interfaces`, `vlans`...).
        reason: why, as fixed text.
    """

    device: str
    data: str
    reason: str


@dataclass(frozen=True, slots=True)
class UnknownInterfaceName:
    """An interface name the fixed short-name table did not know (story 127)."""

    device: str
    reported: str


@dataclass(frozen=True, slots=True)
class Topology:
    """The devices and Links found in a Run, and everything learned about them.

    Every tuple is in id order (the lists of names in order of device, then name).
    """

    devices: tuple[VisitedDevice, ...]
    unvisited: tuple[UnvisitedDevice, ...]
    links: tuple[Link, ...]
    segments: tuple[SharedSegment, ...]
    bundles: tuple[Bundle, ...]
    findings: tuple[Finding, ...]
    skipped: tuple[SkippedCheck, ...]
    unknown_interface_names: tuple[UnknownInterfaceName, ...]
