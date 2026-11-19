"""Collect everything the Topology needs from one Visited Nexus (#60; spec #37 stories 124-140).

Each command on the collection list is sent once, through the gateway's `Send`, and its
`| json` reply read into the collected-record contract (`records.collected`, #52). A command
that is denied, rejected or not understood leaves only its own data unknown, with the
reason `<command>: <why>`, and is handed back as a `Problem` for the Audit log; it never
ends the visit. A reply of `Unknown` (the session was dropped) leaves that data unknown
with the gateway's reason, which the gateway has already recorded.

`show feature` comes first: a command for a feature that is off (LLDP, vPC, OSPF, EIGRP,
BGP, HSRP, VRRP) is not sent, and its data is "none", with `show feature` as the evidence.
When `show feature` itself gives nothing, every command is sent.

No value is taken from the running config.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from network_analyser.platforms.collection import Collection, Problem, Send
from network_analyser.platforms.nxos import commands as c
from network_analyser.platforms.nxos import readers
from network_analyser.platforms.nxos.json_reply import (
    NOT_UNDERSTOOD,
    NotUnderstood,
    Refused,
    Row,
    read,
)
from network_analyser.records.collected import (
    Collected,
    Interface,
    InterfaceIp,
    PortChannel,
    Reading,
    StackMember,
    SwitchportMode,
    VpcKeepalive,
    VpcState,
)
from network_analyser.records.device import VersionFacts
from network_analyser.records.unknown import Unknown

_NEVER_SWITCHPORTS: Final = frozenset({"Vl", "Lo", "mgmt", "Tu", "nve"})
"""Interface types that are never switchports, whatever `show interface switchport` says."""
_SHOW_VERSION: Final = "show version"
PARSER: Final = "Network Analyser NX-OS JSON reader"
"""The parser's name in a `parse_failed` Audit log event."""


def collect(send: Send, version: VersionFacts) -> Collection:
    """Send the collection commands over one session and return what they told the tool."""
    return _Collector(send).run(version)


@dataclass(frozen=True, slots=True)
class _Part[T]:
    """One command's parsed data, or why there is none."""

    command: str
    value: T | Unknown


class _Collector:
    def __init__(self, send: Send) -> None:
        self.send = send
        self.problems: list[Problem] = []
        self.features: Mapping[str, bool] | None = None

    def run(self, version: VersionFacts) -> Collection:
        found = self.ask(c.SHOW_FEATURE, readers.features)
        self.features = None if isinstance(found, Unknown) else found
        channels = self.part(c.SHOW_PORT_CHANNEL_SUMMARY, readers.port_channels)
        interfaces = self.interfaces(channels)
        collected = Collected(
            stack_members=_stack(version),
            interfaces=interfaces,
            cdp=self.reading(c.SHOW_CDP_NEIGHBORS_DETAIL, readers.cdp),
            lldp=self.reading(c.SHOW_LLDP_NEIGHBORS_DETAIL, readers.lldp, feature="lldp"),
            vlans=self.reading(c.SHOW_VLAN_BRIEF, readers.vlans),
            port_channels=_reading(channels),
            vpc=self.vpc(interfaces),
            vrfs=self.reading(c.SHOW_VRF, readers.vrfs),
            arp=self.reading(c.SHOW_IP_ARP, readers.arp),
            mac=self.reading(c.SHOW_MAC_ADDRESS_TABLE, readers.mac_table),
            routing_neighbours=self.combined(
                (
                    (c.SHOW_IP_OSPF_NEIGHBORS, readers.ospf_neighbours, "ospf"),
                    (c.SHOW_IP_EIGRP_NEIGHBORS, readers.eigrp_neighbours, "eigrp"),
                    (c.SHOW_IP_BGP_SUMMARY, readers.bgp_neighbours, "bgp"),
                )
            ),
            static_routes=self.reading(c.SHOW_IP_ROUTE_STATIC, readers.static_routes),
            fhrp=self.combined(
                (
                    (c.SHOW_HSRP_BRIEF, readers.hsrp_groups, "hsrp_engine"),
                    (c.SHOW_VRRP, readers.vrrp_groups, "vrrp"),
                )
            ),
        )
        return Collection(collected, tuple(self.problems), PARSER)

    # -- Sending and reading one command ------------------

    def ask[T](self, command: str, reader: Callable[[Row], T]) -> T | Unknown:
        """Send `command` and read its reply; Unknown, with a problem recorded, if it fails."""
        reply = self.send(command)
        if isinstance(reply, Unknown):
            return reply
        try:
            data = read(reply)
            if isinstance(data, Refused):
                return self.problem(command, data.reason)
            return reader(data)
        except NotUnderstood:
            return self.problem(command, NOT_UNDERSTOOD)

    def problem(self, command: str, reason: str) -> Unknown:
        self.problems.append(Problem(command, reason))
        return Unknown(f"{command}: {reason}")

    def part[T](self, command: str, reader: Callable[[Row], T]) -> _Part[T]:
        return _Part(command, self.ask(command, reader))

    def is_off(self, feature: str | None) -> bool:
        """Say whether `show feature` showed `feature` turned off."""
        return (
            feature is not None
            and self.features is not None
            and not self.features.get(feature, True)
        )

    def reading[T](
        self,
        command: str,
        reader: Callable[[Row], tuple[T, ...]],
        *,
        feature: str | None = None,
    ) -> Reading[tuple[T, ...]] | Unknown:
        """One command's data; none, with `show feature` as evidence, if its feature is off."""
        if self.is_off(feature):
            return Reading((c.SHOW_FEATURE,), ())
        return _reading(self.part(command, reader))

    def combined[T](
        self, sources: Sequence[tuple[str, Callable[[Row], tuple[T, ...]], str]]
    ) -> Reading[tuple[T, ...]] | Unknown:
        """Several commands' data as one reading; each one that failed is a gap."""
        commands: list[str] = []
        values: list[T] = []
        gaps: list[Unknown] = []
        for command, reader, feature in sources:
            if self.is_off(feature):
                if c.SHOW_FEATURE not in commands:
                    commands.append(c.SHOW_FEATURE)
                continue
            found = self.ask(command, reader)
            if isinstance(found, Unknown):
                gaps.append(found)
            else:
                commands.append(command)
                values.extend(found)
        if not commands:
            return gaps[0]
        return Reading(tuple(commands), tuple(values), tuple(gaps))

    # -- Interfaces ------------------

    def interfaces(
        self, channels: _Part[tuple[PortChannel, ...]]
    ) -> Reading[tuple[Interface, ...]] | Unknown:
        """Every interface, from `show interface` with switchport, IP and Bundle detail."""
        base = self.ask(c.SHOW_INTERFACE, lambda d: readers.interfaces(d, c.SHOW_INTERFACE))
        if isinstance(base, Unknown):
            return base
        switchports = self.part(c.SHOW_INTERFACE_SWITCHPORT, readers.switchports)
        ips = self.part(c.SHOW_IP_INTERFACE, readers.ip_interfaces)
        parts: list[tuple[str, object]] = [
            (switchports.command, switchports.value),
            (ips.command, ips.value),
            (channels.command, channels.value),
        ]
        members = (
            channels.value
            if isinstance(channels.value, Unknown)
            else {m.port.short: pc.name.short for pc in channels.value for m in pc.members}
        )
        built = tuple(_interface(one, switchports.value, ips.value, members) for one in base)
        return Reading(
            (c.SHOW_INTERFACE, *(command for command, v in parts if not isinstance(v, Unknown))),
            built,
            tuple(v for _, v in parts if isinstance(v, Unknown)),
        )

    # -- vPC ------------------

    def vpc(
        self, interfaces: Reading[tuple[Interface, ...]] | Unknown
    ) -> Reading[VpcState] | Unknown | None:
        """The vPC domain; None when vPC is off or no domain is configured."""
        if self.is_off("vpc"):
            return None
        brief = self.ask(c.SHOW_VPC_BRIEF, lambda d: readers.vpc_brief(d, c.SHOW_VPC_BRIEF))
        if brief is None or isinstance(brief, Unknown):
            return brief
        found = self.ask(c.SHOW_VPC_PEER_KEEPALIVE, readers.vpc_keepalive)
        keepalive = found if isinstance(found, Unknown) else _keepalive(found, interfaces)
        state = VpcState(brief.domain, brief.peer_link, keepalive, brief.port_channels)
        if isinstance(found, Unknown):
            return Reading((c.SHOW_VPC_BRIEF,), state, (found,))
        return Reading((c.SHOW_VPC_BRIEF, c.SHOW_VPC_PEER_KEEPALIVE), state)


def _reading[T](part: _Part[T]) -> Reading[T] | Unknown:
    return part.value if isinstance(part.value, Unknown) else Reading((part.command,), part.value)


def _stack(version: VersionFacts) -> Reading[tuple[StackMember, ...]]:
    """A Nexus is one switch: one member, with the chassis serial `show version` gave."""
    serial = version.serials if isinstance(version.serials, Unknown) else version.serials[0]
    return Reading((_SHOW_VERSION,), (StackMember(1, serial, version.model),))


type _Vlans = tuple[int | Unknown | None, int | Unknown | None, frozenset[int] | Unknown | None]


def _interface(
    base: readers.BaseInterface,
    switchports: Mapping[str, readers.Switchport] | Unknown,
    ips: Mapping[str, InterfaceIp] | Unknown,
    members: Mapping[str, str] | Unknown,
) -> Interface:
    short = base.name.short
    mode, (access, native, allowed) = _switchport(base, switchports)
    return Interface(
        name=base.name,
        description=base.description,
        admin_up=base.admin_up,
        line_up=base.line_up,
        speed=base.speed,
        mode=mode,
        access_vlan=access,
        native_vlan=native,
        allowed_vlans=allowed,
        ip=ips if isinstance(ips, Unknown) else ips.get(short),
        bundle=members if isinstance(members, Unknown) else members.get(short),
    )


def _switchport(
    base: readers.BaseInterface, switchports: Mapping[str, readers.Switchport] | Unknown
) -> tuple[SwitchportMode | Unknown, _Vlans]:
    """The mode and VLANs; an interface missing from `show interface switchport` is routed."""
    name = base.name
    never = name.known and name.short.rstrip("0123456789/.:") in _NEVER_SWITCHPORTS
    if isinstance(switchports, Unknown) and not never:
        return switchports, (switchports, switchports, switchports)
    port = None if isinstance(switchports, Unknown) or never else switchports.get(name.short)
    if port is None:
        return SwitchportMode.ROUTED, (None, None, None)
    return port.mode, (port.access_vlan, port.native_vlan, port.allowed_vlans)


def _keepalive(
    found: readers.Keepalive, interfaces: Reading[tuple[Interface, ...]] | Unknown
) -> VpcKeepalive | Unknown:
    """The keepalive; its source is the device's own address on the destination's subnet.

    NX-OS shows only the destination and VRF, so the source is the device's address in that
    VRF whose subnet holds the destination, unless the reply names it.
    """
    if found.source is not None:
        return VpcKeepalive(found.source, found.destination, found.vrf)
    if not isinstance(interfaces, Unknown):
        for interface in interfaces.value:
            ip = interface.ip
            if ip is None or isinstance(ip, Unknown) or ip.vrf != found.vrf:
                continue
            for address in ip.addresses:
                if found.destination in address.network and address.ip != found.destination:
                    return VpcKeepalive(address.ip, found.destination, found.vrf)
    return Unknown(f"{c.SHOW_VPC_PEER_KEEPALIVE}: keepalive source not found")
