"""IOS/IOS-XE collection: every Visited Device's data for the Topology (#59; spec #37).

`collect(send, version)` sends each collection command once, through the gateway's
allow-list gate, and builds `records.collected.Collected`. A command that is denied or not
understood leaves its data unknown, is handed back as a `Problem` for the Audit log, never
ends the visit, and never stands in for "none" (story 126). A reply of `Unknown` (the
session was dropped) leaves that data unknown with the gateway's reason. Nothing comes from
the running config.

The CDP and LLDP tables are not read here: the crawl reads them before the Backup (#50) and
the gateway puts its readings in their place. `show version` is sent again for the stack
member table, which `VersionFacts` does not carry; its model and serials come from the
gateway's own reading.

Per VRF: `show vrf` lists the VRFs; each that carries IPv4 is asked for its ARP table, EIGRP
and BGP neighbours and static routes with the per-VRF templates. OSPF needs no per-VRF form:
`show ip ospf neighbor` covers every process, and a neighbour's VRF is its interface's.
"""

from collections.abc import Callable
from functools import partial
from typing import Final

from network_analyser.platforms.allowlist import Template
from network_analyser.platforms.collection import Collection, Send
from network_analyser.platforms.ios_xe import commands as c
from network_analyser.platforms.ios_xe import parsers
from network_analyser.platforms.ios_xe.asking import Asker, Part
from network_analyser.platforms.ios_xe.parsers import DEFAULT_VRF, Peer
from network_analyser.records.collected import (
    NOT_COLLECTED,
    ArpEntry,
    Collected,
    FhrpGroup,
    Interface,
    InterfaceIp,
    Reading,
    RoutingNeighbour,
    RoutingProtocol,
    StackMember,
    StaticRoute,
    SwitchportMode,
    Vrf,
)
from network_analyser.records.device import VersionFacts
from network_analyser.records.interface_names import InterfaceName
from network_analyser.records.unknown import Unknown

PARSER: Final = "Network Analyser IOS/IOS-XE reader (ntc-templates cisco_ios)"
"""The parser's name in a `parse_failed` Audit log event. One name for every command: each
command has exactly one reader, an ntc-templates template or our own, so the command in the
event already says which."""

_NO_PEERS: Final[tuple[Peer, ...]] = ()
_NO_GROUPS: Final[tuple[FhrpGroup, ...]] = ()
"""What a routing or FHRP feature that is not running means: none of its neighbours or
groups."""

type Ips = dict[str, InterfaceIp | None]


def collect(send: Send, version: VersionFacts) -> Collection:
    """Collect every part of a Visited IOS/IOS-XE device's data through `send`."""
    asker = Asker(send)
    stack = _stack(asker, version)
    ips = asker.ask(c.SHOW_IP_INTERFACE, parsers.ip_interfaces)
    shown_vrfs = asker.ask(c.SHOW_VRF, parsers.vrfs)
    vrf_names = (
        shown_vrfs
        if isinstance(shown_vrfs, Unknown)
        else tuple(s.vrf.name for s in shown_vrfs if s.ipv4)
    )
    stacked = isinstance(stack, Reading) and len(stack.value) > 1
    collected = Collected(
        stack_members=stack,
        interfaces=_interfaces(asker, ips, stacked=stacked),
        cdp=Unknown(NOT_COLLECTED),  # the crawl's own reading goes here (#50)
        lldp=Unknown(NOT_COLLECTED),
        vlans=_single(asker, c.SHOW_VLAN_BRIEF, parsers.vlans),
        port_channels=_single(asker, c.SHOW_ETHERCHANNEL_SUMMARY, parsers.port_channels),
        vpc=None,
        vrfs=_vrfs(shown_vrfs),
        arp=_arp(asker, vrf_names),
        mac=_single(asker, c.SHOW_MAC_ADDRESS_TABLE, parsers.mac_table),
        routing_neighbours=_routing(asker, ips, vrf_names),
        static_routes=_static_routes(asker, vrf_names),
        fhrp=_fhrp(asker),
    )
    return Collection(collected, tuple(asker.problems), PARSER)


def _single[T](asker: Asker, command: str, read: Callable[[str], T | None]) -> Reading[T] | Unknown:
    value = asker.ask(command, read)
    return value if isinstance(value, Unknown) else Reading((command,), value)


def _stack(asker: Asker, version: VersionFacts) -> Reading[tuple[StackMember, ...]] | Unknown:
    """The member switches, from the member table of `show version` sent again (story 133)."""
    return _single(
        asker,
        c.SHOW_VERSION,
        partial(parsers.stack_members, model=version.model, serials=version.serials),
    )


# -- Interfaces -------------------------------------------------------------------------------


def _interfaces(
    asker: Asker, ips: Ips | Unknown, *, stacked: bool
) -> Reading[tuple[Interface, ...]] | Unknown:
    part = Part()
    shown = part.take(c.SHOW_INTERFACES, asker.ask(c.SHOW_INTERFACES, parsers.interfaces))
    if shown is None:
        return part.reading(())
    ports = asker.ask(c.SHOW_INTERFACES_SWITCHPORT, parsers.switchports)
    trunks = asker.ask(c.SHOW_INTERFACES_TRUNK, parsers.trunks)
    channels = asker.ask(c.SHOW_ETHERCHANNEL_SUMMARY, parsers.port_channels)
    part.take(c.SHOW_INTERFACES_SWITCHPORT, ports)
    part.take(c.SHOW_INTERFACES_TRUNK, trunks)
    part.take(c.SHOW_IP_INTERFACE, ips)
    part.take(c.SHOW_ETHERCHANNEL_SUMMARY, channels)
    bundles = (
        channels
        if isinstance(channels, Unknown)
        else {m.port.short: pc.name.short for pc in channels for m in pc.members}
    )
    built = tuple(_interface(one, ports, trunks, ips, bundles, stacked=stacked) for one in shown)
    return part.reading(built)


def _interface(  # noqa: PLR0913 (one interface, from each command that describes it)
    shown: parsers.Shown,
    ports: dict[str, parsers.Switchport] | Unknown,
    trunks: dict[str, parsers.Trunk] | Unknown,
    ips: Ips | Unknown,
    bundles: dict[str, str] | Unknown,
    *,
    stacked: bool,
) -> Interface:
    short = shown.name.short
    if isinstance(ports, Unknown):
        mode: SwitchportMode | Unknown = ports
        access: int | Unknown | None = ports
        native: int | Unknown | None = ports
        allowed: frozenset[int] | Unknown | None = ports
    else:
        port = ports.get(short) or parsers.Switchport(SwitchportMode.ROUTED, None, None, None)
        mode, access, native, allowed = (
            port.mode,
            port.access_vlan,
            port.native_vlan,
            port.allowed_vlans,
        )
        trunk = None if isinstance(trunks, Unknown) else trunks.get(short)
        if mode is SwitchportMode.TRUNK and trunk is not None:
            native = native if trunk.native_vlan is None else trunk.native_vlan
            allowed = allowed if trunk.allowed_vlans is None else trunk.allowed_vlans
    return Interface(
        name=shown.name,
        description=shown.description,
        admin_up=shown.admin_up,
        line_up=shown.line_up,
        speed=shown.speed,
        mode=mode,
        access_vlan=access,
        native_vlan=native,
        allowed_vlans=allowed,
        ip=ips if isinstance(ips, Unknown) else ips.get(short),
        bundle=bundles if isinstance(bundles, Unknown) else bundles.get(short),
        stack_member=_stack_member(shown.name) if stacked else None,
    )


def _stack_member(name: InterfaceName) -> int | None:
    """The member switch of a stack port: the first number of `Gi2/0/1` (story 133)."""
    numbers = name.short.lstrip("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-")
    parts = numbers.split("/")
    if not name.known or len(parts) < 3 or not parts[0].isdigit():  # noqa: PLR2004 (x/y/z)
        return None
    return int(parts[0])


# -- VRFs and the per-VRF commands ------------------------------------------------------------


def _vrfs(shown: tuple[parsers.VrfShown, ...] | Unknown) -> Reading[tuple[Vrf, ...]] | Unknown:
    if isinstance(shown, Unknown):
        return shown
    named = tuple(s.vrf for s in shown if s.vrf.name != DEFAULT_VRF)
    return Reading((c.SHOW_VRF,), (Vrf(DEFAULT_VRF, management=False), *named))


def _each_vrf[T](  # noqa: PLR0913 (the per-VRF command and how to read each reply)
    asker: Asker,
    part: Part,
    template: Template,
    vrfs: tuple[str, ...] | Unknown,
    read: Callable[..., T | None],
    *,
    off: T | None = None,
) -> list[tuple[str, T]]:
    """Ask `template` for each VRF; each VRF that cannot be asked or read is a gap."""
    if isinstance(vrfs, Unknown):
        part.gap(f"{template.text}: not sent, the VRFs are unknown ({vrfs.reason})")
        return []
    found: list[tuple[str, T]] = []
    for vrf in vrfs:
        command = template.fill(vrf=vrf)
        if command is None:
            part.gap(f"{template.text}: a VRF's name does not fit the allow-list, so not sent")
            continue
        value = part.take(command, asker.ask(command, partial(read, vrf=vrf), off=off))
        if value is not None:
            found.append((vrf, value))
    return found


def _arp(asker: Asker, vrfs: tuple[str, ...] | Unknown) -> Reading[tuple[ArpEntry, ...]] | Unknown:
    part = Part()
    entries: list[ArpEntry] = []
    found = part.take(
        c.SHOW_IP_ARP, asker.ask(c.SHOW_IP_ARP, partial(parsers.arp, vrf=DEFAULT_VRF))
    )
    entries.extend(found or ())
    for _, value in _each_vrf(asker, part, c.SHOW_IP_ARP_VRF, vrfs, parsers.arp):
        entries.extend(value)
    return part.reading(tuple(entries))


def _routing(
    asker: Asker, ips: Ips | Unknown, vrfs: tuple[str, ...] | Unknown
) -> Reading[tuple[RoutingNeighbour, ...]] | Unknown:
    part = Part()
    found: list[RoutingNeighbour] = []
    ospf = part.take(
        c.SHOW_IP_OSPF_NEIGHBOR,
        asker.ask(c.SHOW_IP_OSPF_NEIGHBOR, parsers.ospf_neighbours, off=_NO_PEERS),
    )
    if ospf and isinstance(ips, Unknown):
        part.gap(f"{c.SHOW_IP_OSPF_NEIGHBOR}: the neighbours' VRFs are unknown ({ips.reason})")
    elif ospf and not isinstance(ips, Unknown):
        found.extend(
            _neighbour(RoutingProtocol.OSPF, _vrf_of(peer.interface, ips), peer) for peer in ospf
        )
    for protocol, command, template, read in (
        (
            RoutingProtocol.EIGRP,
            c.SHOW_IP_EIGRP_NEIGHBORS,
            c.SHOW_IP_EIGRP_VRF_NEIGHBORS,
            parsers.eigrp_neighbours,
        ),
        (
            RoutingProtocol.BGP,
            c.SHOW_IP_BGP_SUMMARY,
            c.SHOW_IP_BGP_VPNV4_VRF_SUMMARY,
            parsers.bgp_neighbours,
        ),
    ):
        peers = part.take(command, asker.ask(command, read, off=_NO_PEERS))
        found.extend(_neighbour(protocol, DEFAULT_VRF, peer) for peer in peers or ())
        each = _each_vrf(asker, part, template, vrfs, _ignore_vrf(read), off=_NO_PEERS)
        found.extend(_neighbour(protocol, vrf, peer) for vrf, peers in each for peer in peers)
    return part.reading(tuple(found))


def _ignore_vrf[T](read: Callable[[str], T | None]) -> Callable[..., T | None]:
    """A reader that takes the `vrf` keyword `_each_vrf` passes, and ignores it."""

    def reader(text: str, *, vrf: str) -> T | None:
        del vrf
        return read(text)

    return reader


def _vrf_of(interface: InterfaceName | None, ips: Ips) -> str:
    ip = ips.get(interface.short) if interface is not None else None
    return ip.vrf if ip is not None else DEFAULT_VRF


def _neighbour(protocol: RoutingProtocol, vrf: str, peer: Peer) -> RoutingNeighbour:
    return RoutingNeighbour(protocol, vrf, peer.ip, peer.interface, peer.state)


def _static_routes(
    asker: Asker, vrfs: tuple[str, ...] | Unknown
) -> Reading[tuple[StaticRoute, ...]] | Unknown:
    part = Part()
    routes: list[StaticRoute] = []
    found = part.take(
        c.SHOW_IP_ROUTE_STATIC,
        asker.ask(c.SHOW_IP_ROUTE_STATIC, partial(parsers.static_routes, vrf=DEFAULT_VRF)),
    )
    routes.extend(found or ())
    for _, value in _each_vrf(asker, part, c.SHOW_IP_ROUTE_VRF_STATIC, vrfs, parsers.static_routes):
        routes.extend(value)
    return part.reading(tuple(routes))


def _fhrp(asker: Asker) -> Reading[tuple[FhrpGroup, ...]] | Unknown:
    part = Part()
    groups: list[FhrpGroup] = []
    for command, read in (
        (c.SHOW_STANDBY_BRIEF, parsers.hsrp),
        (c.SHOW_VRRP_BRIEF, parsers.vrrp),
        (c.SHOW_GLBP_BRIEF, parsers.glbp),
    ):
        groups.extend(part.take(command, asker.ask(command, read, off=_NO_GROUPS)) or ())
    return part.reading(tuple(groups))
