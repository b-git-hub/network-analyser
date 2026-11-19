"""Readers from NX-OS `| json` replies to the collected-record contract (#60; #52).

One reader per command. Each takes the reply's top-level object (`json_reply.read`) and
returns plain values, or raises `NotUnderstood` when the reply does not have the expected
shape, so that command's data is unknown. The JSON keys are provisional until the lab
confirms them (lab checklist section I); a key that is missing or malformed never becomes a
guess. Only parsed values leave here: no reply, and no line of one, is kept.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from network_analyser.platforms.nxos.json_reply import (
    NotUnderstood,
    Row,
    ipv4,
    ipv4_interface,
    is_port,
    label,
    mac,
    number,
    port,
    required,
    rows,
    tables,
    text,
    vlan_set,
)
from network_analyser.records.collected import (
    MANAGEMENT_VRFS,
    ArpEntry,
    BundleMember,
    FhrpGroup,
    FhrpProtocol,
    InterfaceIp,
    MacEntry,
    PortChannel,
    RoutingNeighbour,
    RoutingProtocol,
    StaticRoute,
    SwitchportMode,
    Vlan,
    VpcPortChannel,
    Vrf,
)
from network_analyser.records.interface_names import InterfaceName
from network_analyser.records.unknown import Unknown

# -- Features ------------------------------------------------------------------------------


def features(data: Row) -> Mapping[str, bool]:
    """`show feature`: each feature's name, and whether any instance of it is on."""
    found: dict[str, bool] = {}
    for row in rows(data, "cfcFeatureCtrlTable"):
        name = required(row, "cfcFeatureCtrlName2")
        on = required(row, "cfcFeatureCtrlOpStatus2").startswith("enabled")
        found[name] = found.get(name, False) or on
    if not found:
        raise NotUnderstood
    return found


# -- Interfaces ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BaseInterface:
    """What `show interface` says about one interface."""

    name: InterfaceName
    description: str
    admin_up: bool | Unknown
    line_up: bool | Unknown
    speed: str | Unknown


def interfaces(data: Row, command: str) -> tuple[BaseInterface, ...]:
    """`show interface`: every interface, down ones included, with its state."""
    found: list[BaseInterface] = []
    for row in rows(data, "interface"):
        admin = text(row, "admin_state") or text(row, "svi_admin_state")
        line = text(row, "state") or text(row, "svi_line_proto")
        speed = text(row, "eth_speed")
        found.append(
            BaseInterface(
                name=port(required(row, "interface")),
                description=label(text(row, "desc") or text(row, "svi_desc") or ""),
                admin_up=Unknown(f"{command}: admin state not reported")
                if admin is None
                else admin.strip() == "up",
                line_up=Unknown(f"{command}: line state not reported")
                if line is None
                else line.strip() == "up",
                speed=Unknown(f"{command}: speed not reported") if speed is None else label(speed),
            )
        )
    if not found:
        raise NotUnderstood
    return tuple(found)


@dataclass(frozen=True, slots=True)
class Switchport:
    """What `show interface switchport` says about one switchport."""

    mode: SwitchportMode
    access_vlan: int | None
    native_vlan: int | None
    allowed_vlans: frozenset[int] | None


def switchports(data: Row) -> Mapping[str, Switchport]:
    """`show interface switchport`: each switchport's mode and VLANs, by short name."""
    found: dict[str, Switchport] = {}
    for row in rows(data, "interface"):
        name = port(required(row, "interface"))
        if (text(row, "switchport") or "").strip().lower() != "enabled":
            continue
        mode = (text(row, "oper_mode") or "").strip().lower()
        if mode == "access":
            found[name.short] = Switchport(
                SwitchportMode.ACCESS, number(text(row, "access_vlan")), None, None
            )
        elif mode == "trunk":
            found[name.short] = Switchport(
                SwitchportMode.TRUNK,
                None,
                number(text(row, "native_vlan")),
                vlan_set(text(row, "trunk_vlans")),
            )
        else:
            found[name.short] = Switchport(SwitchportMode.OTHER, None, None, None)
    return found


def ip_interfaces(data: Row) -> Mapping[str, InterfaceIp]:
    """`show ip interface vrf all`: each interface's VRF and addresses, by short name.

    NX-OS gives `TABLE_intf` and `TABLE_vrf` side by side: the VRF row at each position names
    the VRF of the interfaces at the same position. A row naming its own VRF wins.
    """
    intf_tables = tables(data, "intf")
    vrf_tables = tables(data, "vrf")
    if len(vrf_tables) != len(intf_tables):
        vrf_tables = [None] * len(intf_tables)
    found: dict[str, InterfaceIp] = {}
    for intf_table, vrf_table in zip(intf_tables, vrf_tables, strict=True):
        vrf_rows = rows({"TABLE_vrf": vrf_table}, "vrf") if vrf_table is not None else []
        table_vrf = text(vrf_rows[0], "vrf-name-out") if vrf_rows else None
        for row in rows({"TABLE_intf": intf_table}, "intf"):
            name = port(required(row, "intf-name"))
            vrf = text(row, "vrf-name-out") or table_vrf
            if vrf is None:
                raise NotUnderstood
            found[name.short] = InterfaceIp(label(vrf), _addresses(row), "unnum-intf" in row)
    return found


def _addresses(row: Row) -> tuple[IPv4Interface, ...]:
    primary = text(row, "prefix")
    if primary is None:
        return ()
    secondaries = rows(row, "secondary_address")
    return (
        ipv4_interface(primary, text(row, "masklen")),
        *(ipv4_interface(text(s, "prefix1"), text(s, "masklen1")) for s in secondaries),
    )


# -- Port-channels, VLANs and vPC ----------------------------------------------------------------


def port_channels(data: Row) -> tuple[PortChannel, ...]:
    """`show port-channel summary`: each port-channel, its members and protocol."""
    found: list[PortChannel] = []
    for row in rows(data, "channel"):
        name = port(required(row, "port-channel"))
        members = tuple(
            BundleMember(port(required(m, "port")), _bundled(text(m, "port-status")))
            for m in rows(row, "member")
        )
        protocol = text(row, "prtcl")
        found.append(
            PortChannel(
                name,
                members,
                Unknown("protocol not reported")
                if protocol is None
                else ("none" if protocol.strip().upper() == "NONE" else label(protocol)),
            )
        )
    return tuple(found)


def _bundled(status: str | None) -> bool | Unknown:
    if status is None:
        return Unknown("member state not reported")
    return status.strip() == "P"


def vlans(data: Row) -> tuple[Vlan, ...]:
    """`show vlan brief`: the VLAN database."""
    found: list[Vlan] = []
    for row in rows(data, "vlanbriefxbrief"):
        name = text(row, "vlanshowbr-vlanname")
        state = required(row, "vlanshowbr-vlanstate").strip().lower()
        shut = (text(row, "vlanshowbr-shutstate") or "noshutdown").strip().lower()
        found.append(
            Vlan(
                number(text(row, "vlanshowbr-vlanid")),
                Unknown("VLAN name not reported") if name is None else label(name),
                active=state == "active" and shut == "noshutdown",
            )
        )
    return tuple(found)


@dataclass(frozen=True, slots=True)
class VpcBrief:
    """What `show vpc brief` says: the domain, peer-link and vPC port-channels."""

    domain: int
    peer_link: InterfaceName | Unknown
    port_channels: tuple[VpcPortChannel, ...]


def vpc_brief(data: Row, command: str) -> VpcBrief | None:
    """`show vpc brief`; None when no vPC domain is configured."""
    domain = required(data, "vpc-domain-id")
    if domain.strip().lower() == "not configured":
        return None
    links = rows(data, "peerlink")
    link = text(links[0], "peerlink-ifindex") if links else None
    return VpcBrief(
        number(domain),
        Unknown(f"{command}: peer-link not reported") if link is None else port(link),
        tuple(
            VpcPortChannel(number(text(r, "vpc-id")), port(required(r, "vpc-ifindex")))
            for r in rows(data, "vpc")
        ),
    )


@dataclass(frozen=True, slots=True)
class Keepalive:
    """What `show vpc peer-keepalive` says: where it goes, in which VRF, and maybe from where."""

    source: IPv4Address | None
    destination: IPv4Address
    vrf: str


def vpc_keepalive(data: Row) -> Keepalive:
    """`show vpc peer-keepalive`: the destination and VRF (the source only when shown)."""
    source = text(data, "vpc-keepalive-src")
    return Keepalive(
        None if source is None else ipv4(source),
        ipv4(text(data, "vpc-keepalive-dest")),
        label(required(data, "vpc-keepalive-vrf")),
    )


# -- VRFs ----------------------------------------------------------------------


def vrfs(data: Row) -> tuple[Vrf, ...]:
    """`show vrf`: every VRF, the management VRF marked."""
    names = [label(required(row, "vrf_name")) for row in rows(data, "vrf")]
    if not names:
        raise NotUnderstood
    return tuple(Vrf(name, management=name in MANAGEMENT_VRFS) for name in names)


# -- ARP and MAC ---------------------------------------------------------------------------------


def arp(data: Row) -> tuple[ArpEntry, ...]:
    """`show ip arp vrf all`: every entry with a MAC address; incomplete ones are left out."""
    found: list[ArpEntry] = []
    for vrf_row in rows(data, "vrf"):
        vrf = label(required(vrf_row, "vrf-name-out"))
        for row in rows(vrf_row, "adj"):
            ip = ipv4(text(row, "ip-addr-out"))
            address = mac(text(row, "mac"))
            interface = text(row, "intf-out")
            if address is not None:
                found.append(
                    ArpEntry(vrf, ip, address, None if interface is None else port(interface))
                )
    return tuple(found)


def mac_table(data: Row) -> tuple[MacEntry, ...]:
    """`show mac address-table`: entries learned or set on a port; the device's own left out."""
    found: list[MacEntry] = []
    for row in rows(data, "mac_address"):
        address = mac(text(row, "disp_mac_addr"))
        vlan = text(row, "disp_vlan")
        where = text(row, "disp_port")
        if address is None:
            raise NotUnderstood
        if vlan is None or not vlan.strip().isdigit() or where is None or not is_port(where):
            continue  # the device's own MACs (`G`, `sup-eth1(R)`) are on no port
        static = (text(row, "disp_is_static") or "").strip().lower() == "enabled"
        found.append(MacEntry(int(vlan), address, port(where), dynamic=not static))
    return tuple(found)


# -- Routing -------------------------------------------------------------------------------------


def ospf_neighbours(data: Row) -> tuple[RoutingNeighbour, ...]:
    """`show ip ospf neighbors vrf all`: every neighbour, in every process and VRF."""
    found: list[RoutingNeighbour] = []
    for context in rows(data, "ctx"):
        vrf = label(required(context, "cname"))
        for row in rows(context, "nbr"):
            interface = text(row, "intf")
            found.append(
                RoutingNeighbour(
                    RoutingProtocol.OSPF,
                    vrf,
                    ipv4(text(row, "addr")),
                    None if interface is None else port(interface),
                    _state(text(row, "state")),
                )
            )
    return tuple(found)


def eigrp_neighbours(data: Row) -> tuple[RoutingNeighbour, ...]:
    """`show ip eigrp neighbors vrf all`: every neighbour, in every AS and VRF."""
    found: list[RoutingNeighbour] = []
    for asn in rows(data, "asn"):
        for vrf_row in rows(asn, "vrf"):
            vrf = label(required(vrf_row, "vrf"))
            for row in rows(vrf_row, "peer"):
                interface = text(row, "peer_ifname")
                found.append(
                    RoutingNeighbour(
                        RoutingProtocol.EIGRP,
                        vrf,
                        ipv4(text(row, "peer_ipaddr")),
                        None if interface is None else port(interface),
                        Unknown("EIGRP shows no neighbour state"),
                    )
                )
    return tuple(found)


def bgp_neighbours(data: Row) -> tuple[RoutingNeighbour, ...]:
    """`show ip bgp summary vrf all`: every IPv4 neighbour, in every VRF, listed once."""
    found: dict[tuple[str, IPv4Address], RoutingNeighbour] = {}
    for vrf_row in rows(data, "vrf"):
        vrf = label(required(vrf_row, "vrf-name-out"))
        for family in rows(vrf_row, "af"):
            for sub_family in rows(family, "saf"):
                for row in rows(sub_family, "neighbor"):
                    neighbour = required(row, "neighborid")
                    if ":" in neighbour:
                        continue  # an IPv6 neighbour: v1 reads IPv4 only
                    ip = ipv4(neighbour)
                    found.setdefault(
                        (vrf, ip),
                        RoutingNeighbour(
                            RoutingProtocol.BGP, vrf, ip, None, _state(text(row, "state"))
                        ),
                    )
    return tuple(found.values())


def _state(value: str | None) -> str | Unknown:
    shown = label(value) if value is not None else ""
    return shown or Unknown("neighbour state not reported")


def static_routes(data: Row) -> tuple[StaticRoute, ...]:
    """`show ip route static vrf all`: one route per next hop, in every VRF."""
    found: list[StaticRoute] = []
    for vrf_row in rows(data, "vrf"):
        vrf = label(required(vrf_row, "vrf-name-out"))
        for family in rows(vrf_row, "addrf"):
            for prefix_row in rows(family, "prefix"):
                prefix = _network(required(prefix_row, "ipprefix"))
                for path in rows(prefix_row, "path"):
                    hop = text(path, "ipnexthop")
                    interface = text(path, "ifname")
                    found.append(
                        StaticRoute(
                            vrf,
                            prefix,
                            None if hop is None else ipv4(hop),
                            None if interface is None else port(interface),
                        )
                    )
    return tuple(found)


def _network(value: str) -> IPv4Network:
    try:
        return IPv4Network(value.strip())
    except ValueError:
        raise NotUnderstood from None


# -- First-hop redundancy -------------------------------------------------------------------


def hsrp_groups(data: Row) -> tuple[FhrpGroup, ...]:
    """`show hsrp brief`: each IPv4 group's virtual IP."""
    return tuple(
        FhrpGroup(
            FhrpProtocol.HSRP,
            port(required(row, "sh_if_index")),
            number(text(row, "sh_group_num")),
            ipv4(text(row, "sh_vip")),
        )
        for row in rows(data, "grp_detail")
        if (text(row, "sh_group_type") or "v4").strip().lower() != "v6"
    )


def vrrp_groups(data: Row) -> tuple[FhrpGroup, ...]:
    """`show vrrp`: each IPv4 group's virtual IP."""
    return tuple(
        FhrpGroup(
            FhrpProtocol.VRRP,
            port(required(row, "sh_if_index")),
            number(text(row, "sh_group_id")),
            ipv4(text(row, "sh_vip_addr")),
        )
        for row in rows(data, "vrrp_group")
        if (text(row, "sh_group_type") or "ipv4").strip().lower() in {"ipv4", "v4"}
    )
