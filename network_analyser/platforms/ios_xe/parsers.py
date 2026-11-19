"""IOS/IOS-XE readers: one per collection command, from its text to plain values (#59).

Most read the ntc-templates TextFSM template for the command (decision #2). Where no template
exists, or the template drops what the Topology needs, a small reader of our own does it:
`show interfaces trunk`, `show glbp brief` and the per-VRF EIGRP header have no template, and
the `show ip interface` template does not record unnumbered interfaces.

Every reader returns its values, or None when it does not understand the reply. Device text
is untrusted (#28, #30): a row whose address, MAC or number does not check out is dropped, and
free text is made printable and capped. Nothing here keeps the reply.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Final

from network_analyser.platforms import fields
from network_analyser.platforms.textfsm_parse import parse
from network_analyser.records.collected import (
    MANAGEMENT_VRFS,
    ArpEntry,
    BundleMember,
    FhrpGroup,
    FhrpProtocol,
    InterfaceIp,
    MacEntry,
    PortChannel,
    StackMember,
    StaticRoute,
    SwitchportMode,
    Vlan,
    Vrf,
)
from network_analyser.records.interface_names import InterfaceName, interface_name
from network_analyser.records.unknown import Unknown

NTC: Final = "ntc-templates cisco_ios"
OWN: Final = "Network Analyser IOS/IOS-XE reader"
"""The parser names a `parse_failed` Audit log event gives."""
DEFAULT_VRF: Final = "default"

_TEMPLATES: Final = "cisco_ios"
_PORT: Final = re.compile(r"[A-Za-z][A-Za-z-]*\s?\d+(?:/\d+)*(?:[.:]\d+)?")
_NOT_REPORTED: Final = "not reported by show interfaces"

type Row = Mapping[str, object]


def _rows(command: str, text: str) -> list[Row] | None:
    return parse(_TEMPLATES, command, text)


def _table(command: str, text: str, header: str) -> list[Row] | None:
    """The template's rows, only when the reply shows the table's own header.

    Some templates skip lines they do not know, so a reply of another shape would read as
    an empty table: "none" where the truth is "could not tell". A blank reply is no rows.
    """
    if _has_data(text) and not re.search(header, text, re.MULTILINE):
        return None
    return _rows(command, text)


def _port(value: str) -> InterfaceName | None:
    """An interface name from a table cell; None for `CPU`, `Router` and other non-ports."""
    return interface_name(value) if _PORT.fullmatch(value) else None


def _has_data(text: str) -> bool:
    return any(line.strip() for line in text.splitlines())


# -- Stack members (`show version`) -----------------------------------------------------------

_SWITCH_ROW: Final = re.compile(r"^\s*(\*)?\s*(\d{1,2})\s+\d+\s+(\S+)\s+\S+", re.MULTILINE)
_SWITCH_SECTION: Final = re.compile(r"^Switch 0*(\d{1,2})\s*\n-+\s*$", re.MULTILINE)
_SERIAL: Final = re.compile(
    r"^(?:System Serial Number\s*:|Processor board ID)\s*([A-Za-z0-9]{1,40})\s*$", re.MULTILINE
)


def stack_members(
    text: str, model: str | Unknown, serials: tuple[str, ...] | Unknown
) -> tuple[StackMember, ...]:
    """Read the stack's member switches from `show version`; one member for a lone device.

    The member table (`Switch Ports Model ...`) gives each number and model; the serial of
    the switch logged into (`*`) comes before the table, each other member's from its own
    `Switch 0N` section.
    """
    table_at = text.find("Switch Ports Model")
    if table_at < 0:
        only = serials[0] if not isinstance(serials, Unknown) else serials
        return (StackMember(1, only, model),)
    head = _SERIAL.search(text[:table_at])
    sections = list(_SWITCH_SECTION.finditer(text))
    found: dict[int, str] = {}
    for index, section in enumerate(sections):
        end = sections[index + 1].start() if index + 1 < len(sections) else len(text)
        listed = _SERIAL.search(text[section.end() : end])
        if listed:
            found[int(section.group(1))] = listed.group(1)
    members: list[StackMember] = []
    for row in _SWITCH_ROW.finditer(text[table_at:]):
        number = int(row.group(2))
        serial = head.group(1) if row.group(1) and head else found.get(number)
        members.append(
            StackMember(
                number,
                serial or Unknown("serial not found in show version"),
                fields.word({"model": row.group(3)}, "model", "model"),
            )
        )
    return tuple(members)


# -- Interfaces -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Shown:
    """One interface as `show interfaces` shows it."""

    name: InterfaceName
    description: str
    admin_up: bool
    line_up: bool
    speed: str | Unknown


def interfaces(text: str) -> tuple[Shown, ...] | None:
    """Read `show interfaces`: every interface, down ones included."""
    rows = _rows("show interfaces", text)
    if rows is None or (not rows and _has_data(text)):
        return None
    found: list[Shown] = []
    for row in rows:
        name = fields.text(row, "interface")
        if not name:
            continue
        speed = fields.label(fields.text(row, "speed"))
        found.append(
            Shown(
                name=interface_name(name),
                description=fields.label(fields.text(row, "description")),
                admin_up=not fields.text(row, "link_status").startswith("administratively"),
                line_up=fields.text(row, "protocol_status").startswith("up"),
                speed=speed or Unknown(_NOT_REPORTED),
            )
        )
    return tuple(found)


@dataclass(frozen=True, slots=True)
class Switchport:
    """One interface's layer-2 settings, from `show interfaces switchport`."""

    mode: SwitchportMode
    access_vlan: int | Unknown | None
    native_vlan: int | Unknown | None
    allowed_vlans: frozenset[int] | Unknown | None


def switchports(text: str) -> dict[str, Switchport] | None:
    """Read `show interfaces switchport`, by short interface name."""
    rows = _rows("show interfaces switchport", text)
    if rows is None or (not rows and _has_data(text)):
        return None
    found: dict[str, Switchport] = {}
    for row in rows:
        name = fields.text(row, "interface")
        if name:
            found[interface_name(name).short] = _switchport(row)
    return found


def _switchport(row: Row) -> Switchport:
    if fields.text(row, "switchport").lower() == "disabled":
        return Switchport(SwitchportMode.ROUTED, None, None, None)
    operational = fields.text(row, "mode").lower()
    mode_text = operational if operational and operational != "down" else ""
    mode_text = mode_text or fields.text(row, "admin_mode").lower()
    if mode_text.startswith("trunk"):
        native = fields.number(fields.text(row, "native_vlan"))
        allowed = fields.vlan_set(fields.text_list(row, "trunking_vlans"))
        return Switchport(
            SwitchportMode.TRUNK,
            None,
            Unknown("native VLAN not understood") if native is None else native,
            Unknown("allowed VLANs not understood") if allowed is None else allowed,
        )
    if mode_text in {"static access", "access"}:
        vlan = fields.number(fields.text(row, "access_vlan"))
        return Switchport(
            SwitchportMode.ACCESS,
            Unknown("access VLAN not assigned") if vlan is None else vlan,
            None,
            None,
        )
    return Switchport(SwitchportMode.OTHER, None, None, None)


@dataclass(frozen=True, slots=True)
class Trunk:
    """One trunking port, from `show interfaces trunk`."""

    native_vlan: int | None
    allowed_vlans: frozenset[int] | None


_TRUNK_ROW: Final = re.compile(r"^(\S+)\s+(.*\S)\s*$")


def trunks(text: str) -> dict[str, Trunk] | None:
    """Read `show interfaces trunk`, by short interface name: only ports now trunking."""
    if not _has_data(text):
        return {}
    native: dict[str, int | None] = {}
    allowed: dict[str, frozenset[int] | None] = {}
    section = ""
    for line in text.splitlines():
        row = _TRUNK_ROW.match(line)
        if row is None:
            continue
        if row.group(1) == "Port":
            section = row.group(2)
            continue
        port = _port(row.group(1))
        if port is None:
            return None
        if section.endswith("Native vlan"):
            native[port.short] = fields.number(row.group(2).split()[-1])
        elif section == "Vlans allowed on trunk":
            allowed[port.short] = fields.vlan_set([row.group(2)])
    if not section:
        return None
    return {p: Trunk(native.get(p), allowed.get(p)) for p in dict.fromkeys([*native, *allowed])}


_IP_HEADER: Final = re.compile(r"^(\S+) is .+, line protocol is ")
_IP_ADDRESS: Final = re.compile(r"^\s+(?:Internet address is|Secondary address)\s+(\S+)\s*$")
_IP_VRF: Final = re.compile(r'^\s+VPN Routing/Forwarding "([^"]+)"')
_IP_UNNUMBERED: Final = re.compile(r"^\s+Interface is unnumbered\b")


def ip_interfaces(text: str) -> dict[str, InterfaceIp | None] | None:
    """Read `show ip interface`, by short interface name: None for no IPv4 at all.

    The primary address comes first, then each secondary, with masks. An interface with
    `ip unnumbered` is marked so, with no address of its own.
    """
    found: dict[str, InterfaceIp | None] = {}
    current: str | None = None
    addresses: list[IPv4Interface] = []
    vrf = DEFAULT_VRF
    unnumbered = False

    def close() -> None:
        if current is not None:
            has_ip = addresses or unnumbered
            found[current] = InterfaceIp(vrf, tuple(addresses), unnumbered) if has_ip else None

    for line in text.splitlines():
        header = _IP_HEADER.match(line)
        if header:
            close()
            current = interface_name(header.group(1)).short
            addresses, vrf, unnumbered = [], DEFAULT_VRF, False
        elif current is not None:
            if address := _IP_ADDRESS.match(line):
                try:
                    addresses.append(IPv4Interface(address.group(1)))
                except ValueError:
                    return None
            elif named := _IP_VRF.match(line):
                vrf = fields.label(named.group(1))
            elif _IP_UNNUMBERED.match(line):
                unnumbered = True
    close()
    return None if current is None and _has_data(text) else found


def port_channels(text: str) -> tuple[PortChannel, ...] | None:
    """Read `show etherchannel summary`: each port-channel, its protocol and members."""
    rows = _table("show etherchannel summary", text, r"^Group\s+Port-channel\s+Protocol")
    if rows is None:
        return None
    found: list[PortChannel] = []
    for row in rows:
        name = _port(fields.text(row, "bundle_name"))
        if name is None:
            continue
        statuses = fields.text_list(row, "member_interface_status")
        members = [
            BundleMember(port, "P" in status)
            for member, status in zip(
                fields.text_list(row, "member_interface"), statuses, strict=False
            )
            if (port := _port(member)) is not None
        ]
        protocol = fields.text(row, "bundle_protocol")
        found.append(
            PortChannel(
                name,
                tuple(members),
                "none" if protocol in {"", "-"} else fields.label(protocol),
            )
        )
    return tuple(found)


# -- VLANs and VRFs ---------------------------------------------------------------------------


def vlans(text: str) -> tuple[Vlan, ...] | None:
    """Read `show vlan brief`."""
    rows = _rows("show vlan brief", text)
    if rows is None or (not rows and _has_data(text)):
        return None
    found: list[Vlan] = []
    for row in rows:
        number = fields.number(fields.text(row, "vlan_id"))
        if number is None:
            continue
        name = fields.label(fields.text(row, "vlan_name"))
        found.append(
            Vlan(number, name or Unknown("no name"), fields.text(row, "status") == "active")
        )
    return tuple(found)


@dataclass(frozen=True, slots=True)
class VrfShown:
    """One VRF from `show vrf`, and whether it carries IPv4."""

    vrf: Vrf
    ipv4: bool


def vrfs(text: str) -> tuple[VrfShown, ...] | None:
    """Read `show vrf`: the named VRFs. The global table (`default`) is not listed."""
    if not _has_data(text):
        return ()
    rows = _rows("show vrf", text)
    if rows is None:
        return None
    found: list[VrfShown] = []
    for row in rows:
        name = fields.label(fields.text(row, "name"))
        if name:
            ipv4 = "ipv4" in fields.text(row, "protocols").lower().split(",")
            found.append(VrfShown(Vrf(name, name in MANAGEMENT_VRFS), ipv4))
    return tuple(found)


# -- ARP and MAC ------------------------------------------------------------------------------


def arp(text: str, vrf: str) -> tuple[ArpEntry, ...] | None:
    """Read `show ip arp` (or its per-VRF form): entries with a resolved MAC address."""
    rows = _table("show ip arp", text, r"^Protocol\s+Address\s+Age")
    if rows is None:
        return None
    found: list[ArpEntry] = []
    for row in rows:
        ip = fields.ipv4(fields.text(row, "ip_address"))
        address = fields.mac(fields.text(row, "mac_address"))
        if ip is None or address is None:
            continue  # `Incomplete`: no MAC learned yet
        found.append(ArpEntry(vrf, ip, address, _port(fields.text(row, "interface"))))
    return tuple(found)


def mac_table(text: str) -> tuple[MacEntry, ...] | None:
    """Read `show mac address-table`: one entry per VLAN, MAC and port."""
    rows = _table("show mac address-table", text, r"^\s*Vlan\s+Mac Address\s+Type")
    if rows is None:
        return None
    found: list[MacEntry] = []
    for row in rows:
        vlan = fields.number(fields.text(row, "vlan_id"))
        address = fields.mac(fields.text(row, "destination_address"))
        if vlan is None or address is None:
            continue  # `All` VLANs: the device's own addresses
        dynamic = fields.text(row, "type").upper() == "DYNAMIC"
        found.extend(
            MacEntry(vlan, address, port, dynamic)
            for value in fields.text_list(row, "destination_port")
            if (port := _port(value)) is not None
        )
    return tuple(found)


# -- Routing ----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Peer:
    """One routing neighbour before its VRF is known: OSPF and EIGRP name an interface."""

    ip: IPv4Address
    interface: InterfaceName | None
    state: str | Unknown


def ospf_neighbours(text: str) -> tuple[Peer, ...] | None:
    """Read `show ip ospf neighbor`: every process, VRFs included."""
    rows = _table("show ip ospf neighbor", text, r"^Neighbor ID\s+Pri\s+State")
    if rows is None:
        return None
    found: list[Peer] = []
    for row in rows:
        ip = fields.ipv4(fields.text(row, "ip_address"))
        port = _port(fields.text(row, "interface"))
        if ip is not None and port is not None:
            state = re.sub(r"\s+", "", fields.label(fields.text(row, "state")))
            found.append(Peer(ip, port, state or Unknown("state not reported")))
    return tuple(found)


_EIGRP_ROW: Final = re.compile(
    r"^\s*\d+\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+\d+\s+\S+\s+\d+\s+\d+\s+\d+\s+\d+\s*$"
)
_EIGRP_HEADER: Final = re.compile(r"^\s*(?:EIGRP-IPv4|IP-EIGRP)\b|^\s*H\s+Address\s+Interface")


def eigrp_neighbours(text: str) -> tuple[Peer, ...] | None:
    """Read `show ip eigrp neighbors` or its per-VRF form: each listed neighbour is up."""
    found: list[Peer] = []
    understood = True
    for line in text.splitlines():
        row = _EIGRP_ROW.match(line)
        if row is None:
            understood = understood and (not line.strip() or bool(_EIGRP_HEADER.match(line)))
            continue
        ip = fields.ipv4(row.group(1))
        port = _port(row.group(2))
        if ip is not None and port is not None:
            found.append(Peer(ip, port, "up"))
    if not found and not understood:
        return None
    return tuple(found)


def bgp_neighbours(text: str) -> tuple[Peer, ...] | None:
    """Read `show ip bgp summary` or a per-VRF summary: an established peer counts prefixes."""
    if not _has_data(text):
        return ()
    rows = _table("show ip bgp summary", text, r"^BGP router identifier")
    if rows is None:
        return None
    found: list[Peer] = []
    for row in rows:
        ip = fields.ipv4(fields.text(row, "bgp_neighbor"))
        if ip is None:
            continue
        state = fields.label(fields.text(row, "state_or_prefixes_received"))
        if state.isdigit():
            state = "Established"
        found.append(Peer(ip, None, state or Unknown("state not reported")))
    return tuple(found)


def static_routes(text: str, vrf: str) -> tuple[StaticRoute, ...] | None:
    """Read `show ip route static` or its per-VRF form."""
    if not _has_data(text):
        return ()
    rows = _table("show ip route", text, r"^Codes:|^Gateway of last resort")
    if rows is None:
        return None
    found: list[StaticRoute] = []
    for row in rows:
        if not fields.text(row, "protocol").startswith("S"):
            continue
        try:
            prefix = IPv4Network(
                f"{fields.text(row, 'network')}/{fields.text(row, 'prefix_length')}"
            )
        except ValueError:
            continue
        hop = fields.ipv4(fields.text(row, "nexthop_ip"))
        port = _port(fields.text(row, "nexthop_if"))
        found.append(StaticRoute(vrf, prefix, hop, port))
    return tuple(found)


# -- First-hop redundancy ---------------------------------------------------------------------


def hsrp(text: str) -> tuple[FhrpGroup, ...] | None:
    """Read `show standby brief`."""
    return _fhrp(
        _table("show standby brief", text, r"^Interface\s+Grp\s+Pri\s+P\s+State"),
        FhrpProtocol.HSRP,
    )


def vrrp(text: str) -> tuple[FhrpGroup, ...] | None:
    """Read `show vrrp brief`: IPv4 groups only."""
    rows = _table("show vrrp brief", text, r"^Interface\s+Grp\s+A-F\s+Pri")
    if rows is None:
        return None
    ipv4 = [r for r in rows if fields.text(r, "addr_family").lower() in {"", "ipv4"}]
    return _fhrp(ipv4, FhrpProtocol.VRRP)


def _fhrp(rows: list[Row] | None, protocol: FhrpProtocol) -> tuple[FhrpGroup, ...] | None:
    if rows is None:
        return None
    found: list[FhrpGroup] = []
    for row in rows:
        port = _port(fields.text(row, "interface"))
        group = fields.number(fields.text(row, "group"), highest=4095)
        virtual = fields.ipv4(fields.text(row, "virtual_ip_address"))
        if port is not None and group is not None and virtual is not None:
            found.append(FhrpGroup(protocol, port, group, virtual))
    return tuple(found)


_GLBP_GROUP: Final = re.compile(r"^(\S+)\s+(\d+)\s+-\s+\S+\s+\S+\s+(\d+\.\d+\.\d+\.\d+)(?:\s|$)")
_GLBP_HEADER: Final = re.compile(r"^Interface\s+Grp\s+Fwd\s+Pri\s+State")


def glbp(text: str) -> tuple[FhrpGroup, ...] | None:
    """Read `show glbp brief`: the group rows (forwarder `-`) carry the virtual IP."""
    if not _has_data(text):
        return ()
    if not any(_GLBP_HEADER.match(line) for line in text.splitlines()):
        return None
    found: list[FhrpGroup] = []
    for line in text.splitlines():
        row = _GLBP_GROUP.match(line)
        if row is None:
            continue
        port = _port(row.group(1))
        group = fields.number(row.group(2), highest=1023)
        virtual = fields.ipv4(row.group(3))
        if port is not None and group is not None and virtual is not None:
            found.append(FhrpGroup(FhrpProtocol.GLBP, port, group, virtual))
    return tuple(found)
