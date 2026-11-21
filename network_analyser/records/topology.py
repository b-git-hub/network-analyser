"""The Topology record: what `topology.build` makes and `topology.json` holds (#52).

Its shape is the `topology.json` schema (docs/topology-json.md): each record becomes a JSON
object with the same field names. VLAN Mismatches (#61) add four finding kinds and a
`vlan_mismatch` skipped row. Later tickets add L3 Adjacency, Subnets and inferred Links (#62).
Every Finding also carries the 0.2.0 scale: level, Check identity, what was found, what to do,
source, and optional Cisco detail (#93). A new optional field needs no format-version bump;
a change an older `render` would misread does (`topology.FORMAT_VERSION`).

Analysis at the Run's end (#94) adds the per-device advice record, the per-Check ran/skipped
list and its Findings. Its output records live here because they are the `topology.json`
schema: `Topology.analysis` holds the advice and Check list, while `Topology.findings` holds
every Finding, v1's and Analysis's together.

**Stable ids** (`id` fields) are shared by `topology.json`, the diagram (`#device=<id>`,
`#finding=<id>`) and the Run report. Each is worked out from what it names, never from the
order things were found, so the same network gives the same ids in every Run:

- a Visited Device: `dev-<first serial>`, or `dev-ip-<management IP>` when no serial is known;
- an Unvisited Device: `unv-` and 12 hex digits from the address or chassis ID it was merged
  on;
- a Link, Shared Segment, Bundle or finding: `link-`, `seg-`, `bundle-` or `finding-` and 12
  hex digits from its ends or subjects;
- an L3 Adjacency (#62): `adj-` and 12 hex digits from its kind, VRF, devices and prefix;
- a Subnet (#62): `subnet-` and 12 hex digits from its VRF and prefix.

Ids use only letters, digits, `.`, `-` and `_`. Other items point to devices by id.
No record here holds a username (story 141).
"""

from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address
from typing import Final

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
    INTERFACE = "interface"
    """Interface addressing. Story 124 lists no source for it; calling it routing would be false."""
    VLAN = "VLAN"
    """Switchport or VLAN-database output. A CDP native VLAN stays `CDP` (#61)."""


@dataclass(frozen=True, slots=True)
class Evidence:
    """One device's report behind a fact: which device, which command, which source.

    Attributes:
        device: the id of the device that reported it.
        command: the command, exactly as sent, whose output said so.
        source: CDP, LLDP, routing, MAC, ARP, interface addressing, or VLAN (switchport and the
            VLAN database).
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
        vlan_database: the VLANs listed in its VLAN database, active or not, for the
            diagram's VLAN view (#64); unknown when not collected or incomplete.
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
    vlan_database: frozenset[int] | Unknown
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
    INFERRED = "inferred"
    """Placed from ARP and the MAC table, on one edge port (story 130)."""


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
        status: confirmed when both ends report each other, one-sided when only one does,
            inferred when ARP and the MAC table placed it.
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
    """v1's kinds of finding, raised by the Topology. An Analysis Finding has none (#93)."""

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


@unique
class FindingLevel(Enum):
    """How bad a Finding is (spec #92, "Levels"). Critical is worst, and there is no Info."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @property
    def rank(self) -> int:
        """0 for Critical through 3 for Low, for a worst-first sort."""
        return _LEVELS.index(self)


_LEVELS: tuple[FindingLevel, ...] = (
    FindingLevel.CRITICAL,
    FindingLevel.HIGH,
    FindingLevel.MEDIUM,
    FindingLevel.LOW,
)


@unique
class CheckType(Enum):
    """What kind of Check raised a Finding (spec #92, "Finding record")."""

    ADVISORY = "Advisory"
    CONFIGURATION = "Configuration"
    LIFECYCLE = "Lifecycle"
    CONSISTENCY = "Consistency"
    TOPOLOGY = "Topology"


@dataclass(frozen=True, slots=True)
class Check:
    """The Check that raised a Finding: its stable id, name and type (spec #92).

    Attributes:
        id: its stable id, the same in every Run.
        name: its name, as the operator sees it.
        type: Advisory, Configuration, Lifecycle, Consistency or Topology.
        soft: True for a Check whose Findings are drawn fainter and listed last within
            their level (VLAN on one end only, story 85).
    """

    id: str
    name: str
    type: CheckType
    soft: bool = False


@unique
class CiscoDetailKind(Enum):
    """Which Cisco detail a Finding carries: an Advisory's, or EoX dates (#93).

    The discriminator on `cisco_detail`: readers branch on it instead of sniffing `id` or
    `items` (stories 87, 89, 112).
    """

    ADVISORY = "Advisory"
    EOX = "EoX"


ADVISORY_STATUS: Final = "Affected release"
"""Story 49's fixed status, carried by every Advisory Finding."""

ADVISORY_FIXED_LINE: Final = (
    "Matched on software release only. Cisco may limit this Advisory to devices that use a "
    "particular feature; see 'Vulnerable Products' on Cisco's page."
)
"""Story 49's fixed line, so a version-only match is never overread."""


@dataclass(frozen=True, slots=True)
class AdvisoryDetail:
    """Cisco's own detail for an Advisory Finding (stories 49-51).

    Attributes:
        kind: `CiscoDetailKind.ADVISORY`, the discriminator telling a reader this
            `cisco_detail` is an Advisory rather than EoX.
        id: the Advisory id, such as `cisco-sa-example-abc123`.
        title: its title, in Cisco's words.
        sir: Cisco's Security Impact Rating, one of the four `FindingLevel`s. The Finding's
            level equals it (story 47): Cisco's Critical/High/Medium/Low are the same scale.
        cvss: its CVSS score, as Cisco gives it.
        cves: the CVEs it covers, in Cisco's order.
        published: when Cisco published it, as fixed ISO 8601 text.
        updated: when Cisco last updated it, as fixed ISO 8601 text.
        first_fixed: the Advisory's first fixed release in the device's Train; None when
            it has no fix in that Train.
        status: story 49's fixed status, `ADVISORY_STATUS`.
        fixed_line: story 49's fixed line, `ADVISORY_FIXED_LINE`.
        hardware_family_not_confirmed: True when an NX-OS match rests on the release alone
            because the Nexus hardware family could not be worked out (story 46).
    """

    kind: CiscoDetailKind
    id: str
    title: str
    sir: FindingLevel
    cvss: str
    cves: tuple[str, ...]
    published: str
    updated: str
    first_fixed: str | None
    status: str = ADVISORY_STATUS
    fixed_line: str = ADVISORY_FIXED_LINE
    hardware_family_not_confirmed: bool = False


@unique
class EoxKind(Enum):
    """Whether an EoX item is hardware or software (stories 74-75)."""

    HARDWARE = "hardware"
    SOFTWARE = "software"


@dataclass(frozen=True, slots=True)
class EoxItem:
    """One hardware or software item Cisco gives end-of-life dates for (stories 74-75).

    Dates are fixed ISO 8601 text; None means Cisco gave none.

    Attributes:
        kind: hardware or software, so a Check can map the item's level without guessing
            from its name (story 74's hardware vs story 75's software).
        name: the item Cisco names: a PID, or a release string.
        last_date_of_support: Cisco's Last Date of Support.
        end_of_security_support: Cisco's End of Security/Vulnerability Support.
        end_of_sw_maintenance: Cisco's End of SW Maintenance.
        end_of_sale: Cisco's End of Sale.
        replacement: Cisco's replacement PID; None when it names none.
    """

    kind: EoxKind
    name: str
    last_date_of_support: str | None = None
    end_of_security_support: str | None = None
    end_of_sw_maintenance: str | None = None
    end_of_sale: str | None = None
    replacement: str | None = None


@dataclass(frozen=True, slots=True)
class EoxDetail:
    """Cisco's EoX detail for a hardware or software Finding (stories 74-75).

    Attributes:
        kind: `CiscoDetailKind.EOX`, the discriminator telling a reader this `cisco_detail`
            is EoX rather than an Advisory.
        items: one per item Cisco named, in Cisco's order.
    """

    kind: CiscoDetailKind
    items: tuple[EoxItem, ...]


type CiscoDetail = AdvisoryDetail | EoxDetail
"""Cisco's own detail on a Finding: an Advisory's, or EoX dates and replacement PIDs."""


@dataclass(frozen=True, slots=True)
class Finding:
    """Something the operator should look at, with a stable id (`#finding=<id>`).

    A v1 kind keeps its `kind` and `summary` so the v1 pages still draw it; every Finding
    also carries the 0.2.0 scale: its level, Check identity, advice and source (spec #92).
    An Analysis Finding has no v1 kind.

    Every string here is plain data. The Run's secret scan runs over it before it reaches
    `topology.json`, the diagram or a report, so a bug in a Check cannot leak a secret
    (story 116).

    Attributes:
        id: its stable id.
        devices: the ids of the devices it concerns.
        items: the ids of the Links, Bundles or Shared Segments it concerns.
        evidence: the reports behind it.
        level: Critical, High, Medium or Low.
        check: the Check that raised it: stable id, name and type.
        what_was_found: fixed text plus names, keywords, type numbers and counts, never a
            secret, hash, key or quoted config line (story 66).
        what_to_do: how to fix it, as fixed text.
        source: where it comes from: `Cisco openVuln`, `config`, `device reports` or
            `tool policy, not a Cisco rule`.
        summary: one line saying what is wrong, built from fixed text and names; the v1
            pages show it.
        kind: the v1 kind; None for an Analysis Finding.
        cisco_detail: Cisco's own detail for an Advisory or EoX Finding; None otherwise.
        also_flagged_by_cisco: True when Cisco's own insecure-configuration list flags the
            same thing (story 67).
    """

    id: str
    devices: tuple[str, ...]
    items: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    level: FindingLevel
    check: Check
    what_was_found: str
    what_to_do: str
    source: str
    summary: str
    kind: FindingKind | None = None
    cisco_detail: CiscoDetail | None = None
    also_flagged_by_cisco: bool = False

    @property
    def order(self) -> tuple[int, int, str, str]:
        """A worst-first sort key: level, then soft Checks last, then Check and Finding id.

        `VLAN on one end only` is soft, so it is listed last within Low (story 85).
        """
        return (self.level.rank, 1 if self.check.soft else 0, self.check.id, self.id)


NOT_AVAILABLE: Final = "not available"
"""What advice says when Cisco gave no value, or the source was never asked (spec #92)."""


@unique
class AdvisoryOutcomeKind(Enum):
    """What one device's Advisory result says (story 52; #94).

    Every Visited Device ends with exactly one. `COULD_NOT_CHECK` keeps the reason, so
    silence never reads as safe.
    """

    MATCHES = "matches"
    """Critical or High Advisories name the device's release."""
    NONE = "none"
    """Cisco answered, and none of its Critical or High Advisories name the release."""
    COULD_NOT_CHECK = "could not check"
    """No usable answer: the release was unreadable, or the source was unavailable."""


@dataclass(frozen=True, slots=True)
class AdvisoryOutcome:
    """One device's Advisory outcome: exactly one per Visited Device (story 52; #94).

    Attributes:
        kind: whether Advisories match, none match, or the check could not be made.
        matched: how many Critical or High Advisories match; 0 unless `kind` is MATCHES.
        release: the release that was checked, when the outcome names one.
        reason: why the check could not be made; None unless `kind` is COULD_NOT_CHECK.
    """

    kind: AdvisoryOutcomeKind
    matched: int = 0
    release: str | None = None
    reason: str | None = None

    @property
    def text(self) -> str:
        """The outcome as one line, in the words stories 52 and 53 use."""
        if self.kind is AdvisoryOutcomeKind.MATCHES:
            return f"{self.matched} Advisories match"
        if self.kind is AdvisoryOutcomeKind.NONE:
            return f"no known Critical/High Advisories for release {self.release}"
        return f"could not check: {self.reason}"


@dataclass(frozen=True, slots=True)
class DeviceAdvice:
    """What Analysis advises for one Visited Device (stories 55-58, 76; #94/#105/#106).

    Advice is attached to the device, never a Finding, so it does not inflate counts.

    Attributes:
        device: the device's id.
        advisory_outcome: its one Advisory outcome.
        upgrade_target: the highest of each Advisory's first fix above the running release in
            its Train, or the fixed text `no fix in Train T` / `no Critical/High Advisories`;
            `NOT_AVAILABLE` until known (#124).
        latest_release_in_train: the newest release in its Train, or the running-release text;
            `NOT_AVAILABLE` until known (#127).
        latest_release: the newest release overall, or the running-release text;
            `NOT_AVAILABLE` until known (#127).
        latest_in_train_lifecycle: Cisco's lifecycle code beside the in-Train value, only when
            it passed its pattern; None when the value has no code (#127).
        latest_release_lifecycle: Cisco's lifecycle code beside the overall value, only when it
            passed its pattern; None when the value has no code (#127).
        upcoming_eox: EoX dates still in the future, for the device's details rather than a
            Finding (story 76); empty until the Lifecycle Checks fill it.
        train: the device's Train, such as `17.12`, when one was worked out; None otherwise.
            The pages name it in "no fix in Train T" (#124).
        not_cleared: how many of its Critical and High Advisories have no fix in its Train, so
            an Upgrade Target that leaves some open says so (#124). 0 when none is left open.
    """

    device: str
    advisory_outcome: AdvisoryOutcome
    upgrade_target: str = NOT_AVAILABLE
    latest_release_in_train: str = NOT_AVAILABLE
    latest_release: str = NOT_AVAILABLE
    latest_in_train_lifecycle: str | None = None
    latest_release_lifecycle: str | None = None
    upcoming_eox: tuple[EoxItem, ...] = ()
    train: str | None = None
    not_cleared: int = 0


@dataclass(frozen=True, slots=True)
class CheckSkip:
    """One Visited Device a Check could not run for, and why (#102, stories 6 and 80).

    A Device Role that predates a 0.2.0 command makes that command's result `Unknown`; the
    Check that needs it is skipped for that device, never passed. The reason is fixed text
    naming the command and the refusal, such as `show snmp user: denied`.

    Attributes:
        device: the device's id.
        reason: why the Check could not run there, as fixed text.
    """

    device: str
    reason: str


@dataclass(frozen=True, slots=True)
class CheckRun:
    """Whether one shipped Analysis Check ran this Run, and why not (stories 4, 10; #94).

    Every shipped Check runs; a Check is skipped only when a source it needs was
    unavailable. A Check that does not apply to a device raises nothing for that device.

    Attributes:
        check: the Check's stable identity.
        ran: True when the Check ran for at least one Visited Device, or the Run had none.
        reason: why it was skipped everywhere, as fixed text; None when it ran.
        skipped: one record per Visited Device it could not run for (#102); empty otherwise.
    """

    check: Check
    ran: bool
    reason: str | None = None
    skipped: tuple[CheckSkip, ...] = ()


@dataclass(frozen=True, slots=True)
class AnalysisSummary:
    """What `topology.json` keeps of Analysis besides the Findings (#94).

    Attributes:
        advice: one record per Visited Device, in device id order.
        checks: every shipped Check, in Check id order.
    """

    advice: tuple[DeviceAdvice, ...]
    checks: tuple[CheckRun, ...]


@dataclass(frozen=True, slots=True)
class AnalysisResults:
    """Everything Analysis returns for a Run (#94).

    Attributes:
        findings: every Finding, v1's Topology Findings and Analysis's together, worst
            first (`Finding.order`).
        advice: one record per Visited Device, in device id order.
        checks: every shipped Check, in Check id order.
    """

    findings: tuple[Finding, ...]
    advice: tuple[DeviceAdvice, ...]
    checks: tuple[CheckRun, ...]

    @property
    def summary(self) -> AnalysisSummary:
        """The part `topology.json` keeps beside the Findings."""
        return AnalysisSummary(advice=self.advice, checks=self.checks)


@unique
class AdjacencyKind(Enum):
    """What an L3 Adjacency is (stories 136 and 147)."""

    SHARED_SUBNET = "shared subnet"
    """The two devices share one prefix in one VRF."""
    OSPF = "OSPF"
    EIGRP = "EIGRP"
    BGP = "BGP"


@dataclass(frozen=True, slots=True)
class AdjacencyEnd:
    """One device of an L3 Adjacency, and the interfaces it was learned on.

    Attributes:
        device: the device's id.
        interfaces: interfaces that reported it, in short-name order. Empty when the protocol
            named none (BGP) or this device did not report the session.
    """

    device: str
    interfaces: tuple[InterfaceName, ...]


@dataclass(frozen=True, slots=True)
class L3Adjacency:
    """A routed relationship between two devices (stories 136 and 124).

    A shared prefix on exactly two devices is one of these, labelled with the prefix. The
    same prefix on three or more devices is a `Subnet` instead. A routing-protocol
    neighbourship is its own adjacency, labelled with the protocol, even when the devices
    also share a prefix.

    Attributes:
        id: its stable id.
        ends: the two devices, in id order.
        vrf: the VRF the prefix or the neighbourship is in.
        kind: shared subnet, OSPF, EIGRP or BGP.
        prefix: the shared prefix; None for a protocol neighbourship.
        evidence: every report behind it.
        conflicts: the ids of findings that flag a disagreement about it.
    """

    id: str
    ends: tuple[AdjacencyEnd, AdjacencyEnd]
    vrf: str
    kind: AdjacencyKind
    prefix: IPv4Network | None
    evidence: tuple[Evidence, ...]
    conflicts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SubnetAttachment:
    """One device's address on a Subnet.

    Attributes:
        device: the device's id.
        interface: the interface that holds the address.
        address: the address, with its mask.
    """

    device: str
    interface: InterfaceName
    address: IPv4Interface


@dataclass(frozen=True, slots=True)
class Subnet:
    """A prefix in one VRF that three or more devices share (story 137).

    It is one node each device attaches to, not a set of pairs.

    Attributes:
        id: its stable id.
        vrf: the VRF the prefix is in.
        prefix: the shared prefix.
        attachments: one per address, in device, interface and address order.
        evidence: every report behind it.
        conflicts: the ids of findings that flag a disagreement about it.
    """

    id: str
    vrf: str
    prefix: IPv4Network
    attachments: tuple[SubnetAttachment, ...]
    evidence: tuple[Evidence, ...]
    conflicts: tuple[str, ...]


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
class UnplacedNextHop:
    """A routing next hop that was given neither a Link nor a Shared Segment (#66).

    A hop CDP or LLDP already connects, or that MAC/ARP placed, is not one of these.
    One that fell on a Shared Segment is drawn, so it is not listed here either.

    Attributes:
        reporter: the Visited Device that has the route or neighbour.
        far: the device the next-hop address was resolved to.
        vrf: the VRF it was learned in.
        ip: the next-hop address.
        reason: why no Link was placed, as fixed text. Never a hostname.
    """

    reporter: str
    far: str
    vrf: str
    ip: IPv4Address
    reason: str


@dataclass(frozen=True, slots=True)
class CiscoLookups:
    """Whether Cisco was asked this Run, and when (ticket #104).

    It is the top-level `cisco_lookups` record in `topology.json`, so every page that says
    whether lookups ran reads one shape.

    Attributes:
        ran: True only when `advisories` was asked, so a key was unlocked.
        when: when the lookups ran, as fixed ISO 8601 text; None when Cisco was not asked.
    """

    ran: bool
    when: str | None = None


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
    adjacencies: tuple[L3Adjacency, ...]
    """L3 Adjacencies (#62): shared prefixes of two devices, and protocol neighbourships."""
    subnets: tuple[Subnet, ...]
    """Prefixes in one VRF shared by three or more devices (#62)."""
    unplaced_next_hops: tuple[UnplacedNextHop, ...] = ()
    """Next hops with no Link and no Shared Segment (#66). Empty when every hop was placed."""
    analysis: AnalysisSummary | None = None
    """Analysis's advice and Check list (#94); None until Analysis has run."""
    cisco_lookups: CiscoLookups | None = None
    """Whether Cisco was asked and when (#104); None when this Run did not ask."""
