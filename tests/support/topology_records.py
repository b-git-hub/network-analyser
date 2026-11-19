"""Hand-written synthetic device records for `topology.build`, with no device (#52).

The seam later suites build on: synthetic collected records in, a Topology out. Every name,
serial and address is synthetic (RFC 5737 addresses, hostnames like `sw-a`).
"""

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Interface

from network_analyser.records import CredentialSetView, Platform
from network_analyser.records.collected import (
    ArpEntry,
    BundleMember,
    Collected,
    FhrpGroup,
    Interface,
    InterfaceIp,
    MacEntry,
    Neighbour,
    PortChannel,
    Reading,
    RoutingNeighbour,
    StaticRoute,
    SwitchportMode,
    VpcKeepalive,
    VpcPortChannel,
    VpcState,
    Vrf,
)
from network_analyser.records.device import DeviceRecord, UnvisitedReason, VersionFacts
from network_analyser.records.events import DeviceOutcome
from network_analyser.records.interface_names import interface_name
from network_analyser.records.unknown import Unknown

CDP = "show cdp neighbors detail"
LLDP = "show lldp neighbors detail"
INTERFACES = "show interfaces"
PORT_CHANNELS = "show etherchannel summary"
VPC = "show vpc brief | json"
ARP = "show ip arp"
MAC = "show mac address-table"
ROUTING = "show ip ospf neighbor"
STATIC = "show ip route static"
FHRP = "show standby brief"
VRFS = "show vrf"
NOT_IN_TEST = "not collected in this test"


def ip(text: str) -> IPv4Address:
    return IPv4Address(text)


def neighbour(  # noqa: PLR0913 (every advertised field, by name)
    local: str,
    name: str = "sw-x",
    port: str | None = "Gi1/0/1",
    *addresses: str,
    platform: str = "cisco C9300-48P",
    chassis: str | None = None,
    ipv6: Iterable[str] = (),
) -> Neighbour:
    """Return one CDP or LLDP entry heard on `local`."""
    from ipaddress import IPv6Address  # noqa: PLC0415 (used only here)

    return Neighbour(
        local_port=interface_name(local),
        name=name,
        remote_port=interface_name(port) if port is not None else Unknown("no port advertised"),
        addresses=tuple(IPv4Address(a) for a in addresses),
        ipv6_addresses=tuple(IPv6Address(a) for a in ipv6),
        platform=platform,
        chassis_id=chassis,
    )


def port(  # noqa: PLR0913 (an interface's settings, by name)
    name: str,
    *,
    bundle: str | None = None,
    mode: SwitchportMode = SwitchportMode.TRUNK,
    ips: Iterable[str] = (),
    vrf: str = "default",
    stack_member: int | None = None,
    unnumbered: bool = False,
    admin_up: bool | Unknown = True,
    line_up: bool | Unknown = True,
) -> Interface:
    """Return one interface, up unless `admin_up` or `line_up` says otherwise."""
    addresses = tuple(IPv4Interface(a) for a in ips)
    ip_settings = (
        InterfaceIp(vrf=vrf, addresses=addresses, unnumbered=unnumbered)
        if addresses or unnumbered
        else None
    )
    return Interface(
        name=interface_name(name),
        description="uplink",
        admin_up=admin_up,
        line_up=line_up,
        speed="1000Mb/s",
        mode=mode,
        ip=ip_settings,
        bundle=bundle,
        stack_member=stack_member,
    )


def port_channel(name: str, *members: str) -> PortChannel:
    return PortChannel(
        name=interface_name(name),
        members=tuple(BundleMember(interface_name(m), bundled=True) for m in members),
        protocol="LACP",
    )


def vpc(
    domain: int,
    peer_link: str,
    keepalive: tuple[str, str],
    *port_channels: tuple[int, str],
) -> VpcState:
    return VpcState(
        domain=domain,
        peer_link=interface_name(peer_link),
        keepalive=VpcKeepalive(ip(keepalive[0]), ip(keepalive[1]), vrf="management"),
        port_channels=tuple(VpcPortChannel(n, interface_name(p)) for n, p in port_channels),
    )


def visited(  # noqa: PLR0913 (a device's collected data, by name)
    address: str,
    serial: str | None,
    hostname: str = "sw-a",
    *,
    platform: Platform = Platform.IOS_XE,
    cdp: Iterable[Neighbour] | Unknown = (),
    lldp: Iterable[Neighbour] | Unknown = (),
    interfaces: Iterable[Interface] | None = None,
    port_channels: Iterable[PortChannel] | None = None,
    vpc_state: VpcState | None = None,
    aliases: Iterable[str] = (),
    outcome: DeviceOutcome = DeviceOutcome.VISITED,
    arp: Iterable[ArpEntry] | None = None,
    mac: Iterable[MacEntry] | None = None,
    routing: Iterable[RoutingNeighbour] | None = None,
    static: Iterable[StaticRoute] | None = None,
    fhrp: Iterable[FhrpGroup] | None = None,
    vrfs: Iterable[Vrf] | None = None,
) -> DeviceRecord:
    """Return a Visited Device's record; any data not given is unknown.

    An empty tuple means the command was read and there were none. `None` means the command
    was not collected.
    """
    unknown = Unknown(NOT_IN_TEST)

    def reading[T](command: str, value: T | None) -> Reading[T] | Unknown:
        return unknown if value is None else Reading((command,), value)

    nothing = Collected.nothing(NOT_IN_TEST)
    collected = Collected(
        stack_members=nothing.stack_members,
        interfaces=reading(INTERFACES, None if interfaces is None else tuple(interfaces)),
        cdp=cdp if isinstance(cdp, Unknown) else Reading((CDP,), tuple(cdp)),
        lldp=lldp if isinstance(lldp, Unknown) else Reading((LLDP,), tuple(lldp)),
        vlans=nothing.vlans,
        port_channels=reading(
            PORT_CHANNELS, None if port_channels is None else tuple(port_channels)
        ),
        vpc=None if vpc_state is None else Reading((VPC,), vpc_state),
        vrfs=reading(VRFS, None if vrfs is None else tuple(vrfs)),
        arp=reading(ARP, None if arp is None else tuple(arp)),
        mac=reading(MAC, None if mac is None else tuple(mac)),
        routing_neighbours=reading(ROUTING, None if routing is None else tuple(routing)),
        static_routes=reading(STATIC, None if static is None else tuple(static)),
        fhrp=reading(FHRP, None if fhrp is None else tuple(fhrp)),
    )
    serials: tuple[str, ...] | Unknown = (
        (serial,) if serial is not None else Unknown("serial not found in show version")
    )
    return DeviceRecord(
        ip=ip(address),
        outcome=outcome,
        platform=platform,
        credential_set=CredentialSetView(number=1, username="netops-ro", platform_limit=None),
        version=VersionFacts(
            hostname=hostname, model="C9300-48P", software_version="17.9.4", serials=serials
        ),
        aliases=tuple(ip(a) for a in aliases),
        collected=collected,
    )


def unvisited(address: str, reason: UnvisitedReason) -> DeviceRecord:
    """Return the record of a device the tool tried, or chose not to try, and did not visit."""
    return DeviceRecord(ip=ip(address), outcome=DeviceOutcome.UNVISITED, unvisited_reason=reason)
