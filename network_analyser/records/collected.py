"""The collected-record contract: what a Visited Device's commands told the tool (#52).

`DeviceRecord.collected` holds one `Collected` per Visited Device. The platform tickets fill
it (IOS/IOS-XE #59, NX-OS #60) and `topology.build` reads it; the Topology depends on nothing
else from a device. It is built only from parsed, checked command output, never from the
running config, and holds no device output beyond the parsed values.

**Unknown, never absent** (story 126; decided on #11). Each part of `Collected` is either a
`Reading` (the commands were sent and parsed) or `Unknown(reason)` (it was not collected: the
command was denied, failed, timed out, could not be parsed, or is not collected by this version
of the tool). Inside a reading, a single value that could not be read is `Unknown` too. An
empty tuple means "the device has none", so it must never stand in for "could not tell". The
reason is fixed text naming the command, such as `show vlan brief: denied`; it never quotes
device output.

**None means "does not apply"**: a CDP neighbour has no LLDP chassis ID, an IOS/IOS-XE device
has no vPC, an access port has no allowed-VLAN list.

**Names and addresses.** Interface names are `InterfaceName`s from the fixed table
(`records.interface_names`). IP addresses are `ipaddress` objects. MAC addresses are 12
lowercase hex digits with no separators (`00005e0001ff`). A VRF is named as the device names
it, with the global table as `default`; the management VRFs are NX-OS `management` and
IOS-XE `Mgmt-intf` (`MANAGEMENT_VRFS`). VLAN sets are frozensets of VLAN numbers, `allowed
all` being every number from 1 to 4094.
"""

from dataclasses import dataclass, fields
from enum import Enum, unique
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address
from typing import Final

from network_analyser.records.interface_names import InterfaceName
from network_analyser.records.unknown import Unknown

MANAGEMENT_VRFS: Final = frozenset({"management", "Mgmt-intf"})
"""The VRFs that never create a shared-subnet L3 Adjacency (NX-OS, IOS-XE; story 136)."""
ALL_VLANS: Final = frozenset(range(1, 4095))
"""A trunk's allowed VLANs when it allows all."""


@dataclass(frozen=True, slots=True)
class Reading[T]:
    """One kind of collected data, and the commands it was read from.

    Attributes:
        commands: the allow-listed commands, exactly as sent, whose output gave `value`. They
            are the evidence for anything built from it (story 124).
        value: the parsed data.
        gaps: the parts that could not be read, each `Unknown` with its reason, such as one VRF
            whose `show ip arp vrf <name>` was denied. Empty when nothing is missing.
    """

    commands: tuple[str, ...]
    value: T
    gaps: tuple[Unknown, ...] = ()


@unique
class SwitchportMode(Enum):
    """How an interface carries traffic."""

    ACCESS = "access"
    TRUNK = "trunk"
    ROUTED = "routed"
    """Not a switchport: a routed port, SVI, loopback or management port."""
    OTHER = "other"
    """A switchport in some other mode, such as dynamic or a private-VLAN mode."""


@dataclass(frozen=True, slots=True)
class InterfaceIp:
    """An interface's IPv4 settings.

    Attributes:
        vrf: the VRF it is in (`default` for the global table).
        addresses: the primary address first, then any secondaries, with their masks. Empty
            when the interface has no address.
        unnumbered: True for `ip unnumbered`, which never makes a shared-subnet Adjacency.
    """

    vrf: str
    addresses: tuple[IPv4Interface, ...]
    unnumbered: bool = False


@dataclass(frozen=True, slots=True)
class Interface:
    """One interface, down ones included (story 140).

    A parser builds it from several commands (interfaces, switchport and trunk state, IP
    interfaces, port-channel summary); each value it could not read is `Unknown`.

    Attributes:
        name: its name.
        description: its description, as configured; redacted like everything written.
        admin_up: False when shut down.
        line_up: whether the line protocol is up.
        speed: the speed as reported, such as `1000Mb/s` or `auto`.
        mode: access, trunk, routed or other.
        access_vlan: the access VLAN; None when not an access port.
        native_vlan: the trunk's native VLAN; None when not a trunk.
        allowed_vlans: the trunk's allowed VLANs; None when not a trunk.
        ip: its IPv4 settings; None when it has none (a layer-2 port).
        bundle: the short name of the port-channel it is a member of, such as `Po10`; None
            when it is in no port-channel.
        stack_member: the stack member switch it sits on, for a stack or StackWise Virtual
            pair (story 133); None otherwise.
    """

    name: InterfaceName
    description: str | Unknown
    admin_up: bool | Unknown
    line_up: bool | Unknown
    speed: str | Unknown
    mode: SwitchportMode | Unknown
    access_vlan: int | Unknown | None = None
    native_vlan: int | Unknown | None = None
    allowed_vlans: frozenset[int] | Unknown | None = None
    ip: InterfaceIp | Unknown | None = None
    bundle: str | Unknown | None = None
    stack_member: int | None = None


@dataclass(frozen=True, slots=True)
class Neighbour:
    """One CDP or LLDP neighbour entry: what a Neighbour advertised on one local port.

    Which protocol it came from is the `Collected` field it sits in (`cdp` or `lldp`).

    Attributes:
        local_port: the port it was heard on.
        name: the CDP Device ID or LLDP System Name. Only a label: never used for identity.
        remote_port: the Neighbour's own port, as it advertised it.
        addresses: its advertised IPv4 addresses, the management address first.
        platform: the advertised Platform string: CDP platform and version, or the LLDP
            System Description.
        ipv6_addresses: its advertised IPv6 addresses.
        chassis_id: the LLDP chassis ID; None for CDP.
        native_vlan: the native VLAN CDP advertised; None for LLDP or when none was sent.
    """

    local_port: InterfaceName
    name: str | Unknown
    remote_port: InterfaceName | Unknown
    addresses: tuple[IPv4Address, ...]
    platform: str | Unknown
    ipv6_addresses: tuple[IPv6Address, ...] = ()
    chassis_id: str | None = None
    native_vlan: int | None = None


_UNKNOWN_RELEASE: Final = Unknown("release not reported by show version")
_UNKNOWN_MODE: Final = Unknown("mode not reported by show version")


@dataclass(frozen=True, slots=True)
class StackMember:
    """One member switch of a stack or StackWise Virtual pair.

    Attributes:
        number: its member number, as `show version` lists it.
        serial: its serial number.
        model: its model, as the member table reports it.
        software_version: the release it runs, as its own row reports it (#99). `Unknown` when
            the member table has no version column or it was not read.
        mode: its boot mode as the member table reports it, such as `INSTALL` or `BUNDLE`
            (#99). `Unknown` when it was not read.
    """

    number: int
    serial: str | Unknown
    model: str | Unknown
    software_version: str | Unknown = _UNKNOWN_RELEASE
    mode: str | Unknown = _UNKNOWN_MODE


@unique
class InventoryKind(Enum):
    """The `show inventory` entries whose PIDs the EoX lookup may send (story 14; #97).

    Optics, power supplies, fans and anything else are never kept, so they can never leave
    the PC.
    """

    CHASSIS = "chassis"
    STACK_MEMBER = "stack member"
    SUPERVISOR = "supervisor"
    LINE_CARD = "line card"


@dataclass(frozen=True, slots=True)
class InventoryItem:
    """One hardware entry from `show inventory` that the EoX Check may ask Cisco about.

    Attributes:
        name: the inventory NAME, as reported, such as `Switch 1` or `Slot 2 - Line Card 1`.
        kind: chassis, stack member, supervisor or line card.
        pid: the product id, such as `C9300-48P`.
        serial: the serial number, kept for the device's own details and never sent.
    """

    name: str
    kind: InventoryKind
    pid: str | Unknown
    serial: str | Unknown


@dataclass(frozen=True, slots=True)
class SnmpUser:
    """One SNMPv3 user from `show snmp user` (#97).

    Attributes:
        name: the user name.
        auth_protocol: the authentication protocol as reported, such as `SHA-256` or `MD5`.
        privacy_protocol: the privacy protocol as reported, such as `AES256`, `DES` or `None`.
        group: the group the user belongs to.
    """

    name: str
    auth_protocol: str | Unknown
    privacy_protocol: str | Unknown
    group: str | Unknown


@dataclass(frozen=True, slots=True)
class NtpAssociation:
    """One NTP association from `show ntp associations` (#97).

    Attributes:
        peer: the peer's address.
        stratum: its stratum as reported.
        synchronised: True for the peer the device is synchronised to (the `*` marker).
    """

    peer: IPv4Address
    stratum: int | Unknown
    synchronised: bool


@dataclass(frozen=True, slots=True)
class ControlPlanePolicy:
    """The service policies applied to the control plane from `show policy-map control-plane`.

    Attributes:
        service_policies: the policy names attached to the control plane, in order. Empty
            when none is attached, which is what the CoPP Check reads (#102).
    """

    service_policies: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SshSettings:
    """What `show ip ssh` says about the SSH server and its host key (#97).

    Attributes:
        enabled: whether SSH is enabled.
        version: the SSH version as reported, such as `2.0` or `1.99`.
        key_bits: the RSA host key's modulus size in bits. `Unknown` on a release whose
            `show ip ssh` does not print it (lab check K5).
    """

    enabled: bool | Unknown
    version: str | Unknown
    key_bits: int | Unknown


@dataclass(frozen=True, slots=True)
class InsecureConfigurationItem:
    """One entry from `show system insecure configuration` (IOS-XE 17.18.2+, #97).

    Cisco's own fields, as Cisco prints them, so the Cisco insecure-list Check can report an
    unmatched item in Cisco's words (#102, story 67).

    Attributes:
        module: the Cisco module, such as `SNMP` or `FTP`.
        command: the CLI command pattern, as Cisco prints it, with any value as a
            placeholder such as `<STRING>`. The reply's other lines echo configured values,
            and are never kept.
        reason: why Cisco flags it.
        severity: the severity Cisco gives it.
    """

    module: str | Unknown
    command: str | Unknown
    reason: str | Unknown
    severity: str | Unknown


@dataclass(frozen=True, slots=True)
class Vlan:
    """One VLAN in the device's VLAN database.

    Attributes:
        number: the VLAN number.
        name: its name.
        active: True when it is active (IOS: "allowed and active in the management domain").
    """

    number: int
    name: str | Unknown
    active: bool


@dataclass(frozen=True, slots=True)
class BundleMember:
    """One member port of a port-channel.

    Attributes:
        port: the member port.
        bundled: True when it is up in the bundle, False when down, suspended or standalone.
    """

    port: InterfaceName
    bundled: bool | Unknown


@dataclass(frozen=True, slots=True)
class PortChannel:
    """One port-channel and its members, from the port-channel summary.

    Attributes:
        name: the port-channel, such as `Po10`.
        members: its member ports.
        protocol: `LACP`, `PAgP` or `none`, as reported.
    """

    name: InterfaceName
    members: tuple[BundleMember, ...]
    protocol: str | Unknown


@dataclass(frozen=True, slots=True)
class VpcKeepalive:
    """A vPC peer-keepalive: the addresses it runs between, and in which VRF."""

    source: IPv4Address
    destination: IPv4Address
    vrf: str


@dataclass(frozen=True, slots=True)
class VpcPortChannel:
    """A port-channel joined to a vPC, by its vPC number."""

    number: int
    port_channel: InterfaceName


@dataclass(frozen=True, slots=True)
class VpcState:
    """A device's vPC domain (NX-OS only).

    Attributes:
        domain: the vPC domain number.
        peer_link: the peer-link port-channel.
        keepalive: the peer-keepalive's addresses.
        port_channels: the port-channels joined to a vPC.
    """

    domain: int
    peer_link: InterfaceName | Unknown
    keepalive: VpcKeepalive | Unknown
    port_channels: tuple[VpcPortChannel, ...] | Unknown


@dataclass(frozen=True, slots=True)
class Vrf:
    """One VRF, and whether it is the management VRF (`MANAGEMENT_VRFS`)."""

    name: str
    management: bool


@dataclass(frozen=True, slots=True)
class ArpEntry:
    """One ARP entry."""

    vrf: str
    ip: IPv4Address
    mac: str
    interface: InterfaceName | None


@dataclass(frozen=True, slots=True)
class MacEntry:
    """One MAC address table entry.

    Attributes:
        dynamic: True when learned, False when static or the device's own.
    """

    vlan: int
    mac: str
    port: InterfaceName
    dynamic: bool


@unique
class RoutingProtocol(Enum):
    """The routing protocols the tool reads neighbours of (IS-IS is not in v1)."""

    OSPF = "OSPF"
    EIGRP = "EIGRP"
    BGP = "BGP"


@dataclass(frozen=True, slots=True)
class RoutingNeighbour:
    """One OSPF, EIGRP or BGP neighbour.

    Attributes:
        interface: the interface it is reached on; None when not reported (BGP).
        state: the state as reported, such as `FULL` or `Established`.
    """

    protocol: RoutingProtocol
    vrf: str
    ip: IPv4Address
    interface: InterfaceName | None
    state: str | Unknown


@dataclass(frozen=True, slots=True)
class StaticRoute:
    """One static route, the default route included.

    Attributes:
        next_hop: the next-hop address; None for a route out of an interface only.
        interface: the exit interface; None when not given.
    """

    vrf: str
    prefix: IPv4Network
    next_hop: IPv4Address | None
    interface: InterfaceName | None


@unique
class FhrpProtocol(Enum):
    """First-hop redundancy protocols, read to leave their virtual IPs out of Adjacency."""

    HSRP = "HSRP"
    VRRP = "VRRP"
    GLBP = "GLBP"


@dataclass(frozen=True, slots=True)
class FhrpGroup:
    """One HSRP, VRRP or GLBP group on an interface, and its virtual IP."""

    protocol: FhrpProtocol
    interface: InterfaceName
    group: int
    virtual_ip: IPv4Address


@dataclass(frozen=True, slots=True)
class Collected:
    """Everything collected from one Visited Device, each part a `Reading` or `Unknown`.

    Attributes:
        stack_members: the member switches; one member for a lone switch.
        interfaces: every interface, down ones included, with IPs, VRF and Bundle membership.
        cdp: the CDP neighbour entries.
        lldp: the LLDP neighbour entries.
        vlans: the VLAN database; None when it does not apply (an IOS-XE router, #72).
        port_channels: the port-channel summary; None when it does not apply (an IOS-XE
            router, #72).
        vpc: the vPC domain; None when the device has none (IOS/IOS-XE, or not configured).
        vrfs: the VRFs.
        arp: the ARP entries, every VRF.
        mac: the MAC address table; None when it does not apply (an IOS-XE router, #72).
        routing_neighbours: OSPF, EIGRP and BGP neighbours, every VRF.
        static_routes: the static routes, every VRF.
        fhrp: HSRP, VRRP and GLBP groups.
        inventory: the chassis, stack-member, supervisor and line-card PIDs (#97). None when
            this Platform's collection does not read it; on IOS/IOS-XE, `Unknown` when it was
            refused or not understood.
        snmp_users: the SNMPv3 users, with their protocols (#97). None when not collected.
        ntp_associations: the NTP peers and which one the device is synchronised to (#97).
            None when not collected.
        control_plane: the control-plane service policies (#97). None when not collected.
        ssh: the SSH server's settings and RSA host key size (#97). None when not collected.
        insecure_configuration: Cisco's own insecure-configuration entries (#97). None when
            the Platform has no such command, or an IOS/IOS-XE release below 17.18.2 cannot
            run it (story 68), so None never means "Cisco found nothing".
        guest_shell: whether the NX-OS Guest Shell is installed and enabled (#98). None when
            the Platform has no such command, which is every Platform but NX-OS.
    """

    stack_members: Reading[tuple[StackMember, ...]] | Unknown
    interfaces: Reading[tuple[Interface, ...]] | Unknown
    cdp: Reading[tuple[Neighbour, ...]] | Unknown
    lldp: Reading[tuple[Neighbour, ...]] | Unknown
    vlans: Reading[tuple[Vlan, ...]] | Unknown | None
    port_channels: Reading[tuple[PortChannel, ...]] | Unknown | None
    vpc: Reading[VpcState] | Unknown | None
    vrfs: Reading[tuple[Vrf, ...]] | Unknown
    arp: Reading[tuple[ArpEntry, ...]] | Unknown
    mac: Reading[tuple[MacEntry, ...]] | Unknown | None
    routing_neighbours: Reading[tuple[RoutingNeighbour, ...]] | Unknown
    static_routes: Reading[tuple[StaticRoute, ...]] | Unknown
    fhrp: Reading[tuple[FhrpGroup, ...]] | Unknown
    inventory: Reading[tuple[InventoryItem, ...]] | Unknown | None = None
    snmp_users: Reading[tuple[SnmpUser, ...]] | Unknown | None = None
    ntp_associations: Reading[tuple[NtpAssociation, ...]] | Unknown | None = None
    control_plane: Reading[ControlPlanePolicy] | Unknown | None = None
    ssh: Reading[SshSettings] | Unknown | None = None
    insecure_configuration: Reading[tuple[InsecureConfigurationItem, ...]] | Unknown | None = None
    guest_shell: Reading[bool] | Unknown | None = None

    @classmethod
    def nothing(cls, reason: str) -> Collected:
        """Return a `Collected` with every part unknown for `reason`."""
        unknown = Unknown(reason)
        return cls(**{f.name: unknown for f in fields(cls)})


NOT_COLLECTED: Final = "not collected by this version of the tool"
"""Why a Visited Device's data is unknown before the collection tickets fill it in."""
