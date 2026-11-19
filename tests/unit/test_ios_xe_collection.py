"""IOS/IOS-XE collection (#59): from command replies to the collected-record contract (#52).

Driven through `platforms.collect` with synthetic replies (tests/support/ios_xe_text): a fake
`send` answers each command as `sw-a` would, and the test reads the `Collected` that comes
back. Expected values are written out by hand from the synthetic text.
"""

from collections.abc import Mapping
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address

import pytest

from network_analyser import platforms
from network_analyser.platforms import Collection, ParseProblem
from network_analyser.records import Platform
from network_analyser.records.collected import (
    ALL_VLANS,
    NOT_COLLECTED,
    ArpEntry,
    BundleMember,
    Collected,
    FhrpGroup,
    FhrpProtocol,
    Interface,
    InterfaceIp,
    MacEntry,
    Neighbour,
    PortChannel,
    Reading,
    RoutingNeighbour,
    RoutingProtocol,
    StackMember,
    StaticRoute,
    SwitchportMode,
    Vlan,
    Vrf,
)
from network_analyser.records.interface_names import interface_name
from network_analyser.records.unknown import Unknown
from tests.support import device_text, ios_xe_text

DENIED = "                 ^\n% Invalid input detected at '^' marker.\n"


class Device:
    """A fake `send`: answers from `replies`, records what was asked."""

    def __init__(self, replies: Mapping[str, str | Unknown] | None = None) -> None:
        self.replies = dict(ios_xe_text.REPLIES if replies is None else replies)
        self.asked: list[str] = []

    def __call__(self, command: str) -> str | Unknown:
        assert platforms.permits(Platform.IOS_XE, command), command
        self.asked.append(command)
        return self.replies.get(command, DENIED)


def collect(device: Device, version: str = device_text.IOS_XE_SHOW_VERSION) -> Collection:
    return platforms.collect(Platform.IOS_XE, device, version)


def value[T](part: Reading[T] | Unknown | None) -> T:
    assert isinstance(part, Reading), part
    return part.value


def by_name(collected: Collected) -> dict[str, Interface]:
    return {i.name.short: i for i in value(collected.interfaces)}


@pytest.fixture(scope="module")
def sw_a() -> Collection:
    return collect(Device())


def gi(name: str) -> object:
    return interface_name(name)


# -- What is sent -----------------------------------------------------------------------------


def test_every_command_is_on_the_allow_list_and_sent_once() -> None:
    device = Device()

    collect(device)

    assert len(device.asked) == len(set(device.asked))
    assert set(device.asked) == set(ios_xe_text.REPLIES) - {"show vrf V6ONLY"}


def test_each_vrf_that_carries_ipv4_is_asked_with_the_per_vrf_forms() -> None:
    device = Device()

    collect(device)

    assert "show ip arp vrf BLUE" in device.asked
    assert "show ip route vrf Mgmt-intf static" in device.asked
    assert not [c for c in device.asked if "V6ONLY" in c]


def test_a_vrf_name_that_does_not_fit_the_allow_list_is_never_sent() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies["show vrf"] = ios_xe_text.SHOW_VRF.replace("BLUE  ", "B|LUE ")
    device = Device(replies)

    collected = collect(device).collected

    assert not [c for c in device.asked if "B|LUE" in c]
    arp = collected.arp
    assert isinstance(arp, Reading)
    assert any("does not fit the allow-list" in gap.reason for gap in arp.gaps)


# -- Stack and interfaces ---------------------------------------------------------------------


def test_stack_members_come_from_show_version(sw_a: Collection) -> None:
    assert sw_a.collected.stack_members == Reading(
        ("show version",),
        (StackMember(1, "TEST0000A01", "C9300-48P"), StackMember(2, "TEST0000A02", "C9300-48P")),
    )


def test_a_lone_device_is_one_member() -> None:
    collected = collect(Device(), device_text.IOL_SHOW_VERSION).collected

    members = value(collected.stack_members)
    assert len(members) == 1
    assert members[0].number == 1
    assert members[0].serial == "TEST0000B01"
    assert all(i.stack_member is None for i in value(collected.interfaces))


def test_a_trunk_member_of_a_port_channel(sw_a: Collection) -> None:
    port = by_name(sw_a.collected)["Gi2/0/1"]

    assert port == Interface(
        name=interface_name("GigabitEthernet2/0/1"),
        description="to sw-b Gi2/0/24",
        admin_up=True,
        line_up=True,
        speed="1000Mb/s",
        mode=SwitchportMode.TRUNK,
        access_vlan=None,
        native_vlan=99,
        allowed_vlans=frozenset({10, 20, 30, 31, 32}),
        ip=None,
        bundle="Po10",
        stack_member=2,
    )


def test_a_shut_access_port(sw_a: Collection) -> None:
    port = by_name(sw_a.collected)["Gi1/0/2"]

    assert (port.admin_up, port.line_up, port.mode, port.access_vlan) == (
        False,
        False,
        SwitchportMode.ACCESS,
        10,
    )
    assert (port.native_vlan, port.allowed_vlans, port.bundle) == (None, None, None)


def test_svis_carry_their_vrf_masks_and_secondaries(sw_a: Collection) -> None:
    interfaces = by_name(sw_a.collected)

    assert interfaces["Vl10"].ip == InterfaceIp(
        "default", (IPv4Interface("192.0.2.1/25"), IPv4Interface("203.0.113.129/25"))
    )
    assert interfaces["Vl20"].ip == InterfaceIp("BLUE", (IPv4Interface("198.51.100.1/24"),))
    assert interfaces["Vl20"].mode is SwitchportMode.ROUTED
    assert interfaces["Gi0/0"].ip == InterfaceIp("Mgmt-intf", (IPv4Interface("203.0.113.10/24"),))
    assert interfaces["Vl10"].speed == Unknown("not reported by show interfaces")


def test_an_unnumbered_interface_is_marked(sw_a: Collection) -> None:
    port = by_name(sw_a.collected)["Te1/1/1"]

    assert port.ip == InterfaceIp("default", (), unnumbered=True)
    assert port.mode is SwitchportMode.ROUTED
    assert port.stack_member == 1


def test_the_trunk_table_gives_the_allowed_vlans_of_a_trunking_port() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies["show interfaces trunk"] = ios_xe_text.SHOW_INTERFACES_TRUNK.replace(
        "Po10        10,20,30-32", "Po10        10-12"
    )

    po10 = by_name(collect(Device(replies)).collected)["Po10"]

    assert po10.allowed_vlans == frozenset({10, 11, 12})
    assert po10.native_vlan == 99


def test_allowed_all_is_every_vlan() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies["show interfaces trunk"] = ""
    replies["show interfaces switchport"] = ios_xe_text.SHOW_INTERFACES_SWITCHPORT.replace(
        "Trunking VLANs Enabled: 10,20,30-32", "Trunking VLANs Enabled: ALL"
    )

    assert by_name(collect(Device(replies)).collected)["Po10"].allowed_vlans == ALL_VLANS


def test_interface_names_are_short_with_the_reported_name_kept(sw_a: Collection) -> None:
    names = {i.name.reported: i.name.short for i in value(sw_a.collected.interfaces)}

    assert names == {
        "GigabitEthernet0/0": "Gi0/0",
        "GigabitEthernet1/0/1": "Gi1/0/1",
        "GigabitEthernet1/0/2": "Gi1/0/2",
        "GigabitEthernet2/0/1": "Gi2/0/1",
        "TenGigabitEthernet1/1/1": "Te1/1/1",
        "Port-channel10": "Po10",
        "Vlan10": "Vl10",
        "Vlan20": "Vl20",
        "Loopback0": "Lo0",
    }


def test_the_interfaces_reading_names_every_command_it_used(sw_a: Collection) -> None:
    interfaces = sw_a.collected.interfaces

    assert isinstance(interfaces, Reading)
    assert interfaces.commands == (
        "show interfaces",
        "show interfaces switchport",
        "show interfaces trunk",
        "show ip interface",
        "show etherchannel summary",
    )
    assert interfaces.gaps == ()


def test_a_denied_switchport_command_leaves_modes_unknown_not_routed() -> None:
    replies = dict(ios_xe_text.REPLIES)
    del replies["show interfaces switchport"]

    interfaces = collect(Device(replies)).collected.interfaces

    assert isinstance(interfaces, Reading)
    reason = Unknown("show interfaces switchport: denied or not supported by the device")
    assert interfaces.gaps == (reason,)
    port = {i.name.short: i for i in interfaces.value}["Gi1/0/1"]
    assert (port.mode, port.allowed_vlans, port.access_vlan) == (reason, reason, reason)
    assert port.bundle == "Po10"


# -- Port-channels, VLANs, VRFs ----------------------------------------------------------------


def test_port_channels_and_their_members(sw_a: Collection) -> None:
    assert value(sw_a.collected.port_channels) == (
        PortChannel(
            interface_name("Po10"),
            (
                BundleMember(interface_name("Gi1/0/1"), bundled=True),
                BundleMember(interface_name("Gi2/0/1"), bundled=False),
            ),
            "LACP",
        ),
    )


def test_the_vlan_database(sw_a: Collection) -> None:
    assert value(sw_a.collected.vlans) == (
        Vlan(1, "default", active=True),
        Vlan(10, "users", active=True),
        Vlan(20, "servers", active=True),
        Vlan(99, "NATIVE", active=True),
        Vlan(1002, "fddi-default", active=False),
    )


def test_vrfs_include_the_global_table_and_mark_the_management_vrf(sw_a: Collection) -> None:
    assert value(sw_a.collected.vrfs) == (
        Vrf("default", management=False),
        Vrf("BLUE", management=False),
        Vrf("Mgmt-intf", management=True),
        Vrf("V6ONLY", management=False),
    )


# -- Neighbours -------------------------------------------------------------------------------


def test_cdp_neighbours_with_every_address_management_first(sw_a: Collection) -> None:
    sw_b, rtr_c = value(sw_a.collected.cdp)

    assert sw_b == Neighbour(
        local_port=interface_name("GigabitEthernet1/0/1"),
        name="sw-b.example.net",
        remote_port=interface_name("GigabitEthernet1/0/24"),
        addresses=(
            IPv4Address("203.0.113.2"),
            IPv4Address("192.0.2.2"),
            IPv4Address("198.51.100.2"),
        ),
        platform="cisco C9300-48P",
        ipv6_addresses=(IPv6Address("2001:db8::2"),),
        native_vlan=99,
    )
    assert rtr_c.addresses == (IPv4Address("192.0.2.254"),)
    assert rtr_c.native_vlan is None
    assert rtr_c.remote_port == interface_name("GigabitEthernet2")


def test_lldp_neighbours_and_what_was_not_advertised(sw_a: Collection) -> None:
    sw_b, host = value(sw_a.collected.lldp)

    assert sw_b == Neighbour(
        local_port=interface_name("Gi1/0/1"),
        name="sw-b.example.net",
        remote_port=interface_name("Gi1/0/24"),
        addresses=(IPv4Address("203.0.113.2"),),
        platform=(
            "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), "
            "Version 17.9.4a"
        ),
        ipv6_addresses=(IPv6Address("2001:db8::2"),),
        chassis_id="0000.5e00.5340",
    )
    assert host.name == Unknown("not advertised")
    assert host.platform == Unknown("not advertised")
    assert host.addresses == ()
    assert host.remote_port == interface_name("0000.5e00.5351")
    assert host.remote_port.known is False


def test_cdp_not_enabled_is_unknown_never_no_neighbours() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies["show cdp neighbors detail"] = ios_xe_text.CDP_NOT_ENABLED
    replies["show lldp neighbors detail"] = ios_xe_text.LLDP_NOT_ENABLED

    collected = collect(Device(replies)).collected

    assert collected.cdp == Unknown("show cdp neighbors detail: CDP is not enabled on the device")
    assert collected.lldp == Unknown(
        "show lldp neighbors detail: LLDP is not enabled on the device"
    )


def test_an_empty_neighbour_table_is_none() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies["show cdp neighbors detail"] = "\nTotal cdp entries displayed : 0\n"

    assert value(collect(Device(replies)).collected.cdp) == ()


# -- ARP, MAC, routing, FHRP -----------------------------------------------------------------


def test_arp_from_every_vrf_and_incomplete_entries_left_out(sw_a: Collection) -> None:
    arp = sw_a.collected.arp

    assert isinstance(arp, Reading)
    assert arp.value == (
        ArpEntry("default", IPv4Address("192.0.2.1"), "00005e005306", interface_name("Vlan10")),
        ArpEntry("default", IPv4Address("192.0.2.20"), "00005e005320", interface_name("Vlan10")),
        ArpEntry("BLUE", IPv4Address("198.51.100.20"), "00005e005321", interface_name("Vlan20")),
        ArpEntry(
            "Mgmt-intf",
            IPv4Address("203.0.113.1"),
            "00005e005322",
            interface_name("GigabitEthernet0/0"),
        ),
    )
    assert arp.commands == ("show ip arp", "show ip arp vrf BLUE", "show ip arp vrf Mgmt-intf")


def test_the_mac_table_without_the_devices_own_addresses(sw_a: Collection) -> None:
    assert value(sw_a.collected.mac) == (
        MacEntry(10, "00005e005320", interface_name("Gi1/0/2"), dynamic=True),
        MacEntry(10, "00005e005330", interface_name("Po10"), dynamic=True),
        MacEntry(20, "00005e005321", interface_name("Gi1/0/1"), dynamic=False),
    )


def test_routing_neighbours_in_every_vrf(sw_a: Collection) -> None:
    ospf, eigrp, bgp = RoutingProtocol.OSPF, RoutingProtocol.EIGRP, RoutingProtocol.BGP

    assert value(sw_a.collected.routing_neighbours) == (
        RoutingNeighbour(
            ospf, "BLUE", IPv4Address("198.51.100.2"), interface_name("Vlan20"), "FULL/DR"
        ),
        RoutingNeighbour(
            ospf,
            "default",
            IPv4Address("192.0.2.254"),
            interface_name("TenGigabitEthernet1/1/1"),
            "FULL/-",
        ),
        RoutingNeighbour(eigrp, "default", IPv4Address("192.0.2.2"), interface_name("Vl10"), "up"),
        RoutingNeighbour(eigrp, "BLUE", IPv4Address("198.51.100.3"), interface_name("Vl20"), "up"),
        RoutingNeighbour(bgp, "default", IPv4Address("192.0.2.3"), None, "Established"),
        RoutingNeighbour(bgp, "default", IPv4Address("192.0.2.4"), None, "Idle"),
        RoutingNeighbour(bgp, "BLUE", IPv4Address("198.51.100.4"), None, "Established"),
    )


def test_bgp_not_running_means_no_bgp_neighbours() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies["show ip bgp summary"] = ios_xe_text.BGP_NOT_ACTIVE

    routing = collect(Device(replies)).collected.routing_neighbours

    assert isinstance(routing, Reading)
    assert routing.gaps == ()
    assert IPv4Address("192.0.2.3") not in {n.ip for n in routing.value}


def test_static_routes_in_every_vrf(sw_a: Collection) -> None:
    assert value(sw_a.collected.static_routes) == (
        StaticRoute("default", IPv4Network("0.0.0.0/0"), IPv4Address("192.0.2.126"), None),
        StaticRoute("default", IPv4Network("203.0.113.64/26"), IPv4Address("192.0.2.125"), None),
        StaticRoute("default", IPv4Network("203.0.113.128/26"), None, interface_name("Vlan10")),
        StaticRoute("BLUE", IPv4Network("198.51.100.128/25"), IPv4Address("198.51.100.254"), None),
    )


def test_hsrp_vrrp_and_glbp_virtual_ips(sw_a: Collection) -> None:
    assert value(sw_a.collected.fhrp) == (
        FhrpGroup(FhrpProtocol.HSRP, interface_name("Vl10"), 10, IPv4Address("192.0.2.126")),
        FhrpGroup(FhrpProtocol.VRRP, interface_name("Vl20"), 20, IPv4Address("198.51.100.254")),
        FhrpGroup(FhrpProtocol.GLBP, interface_name("Vl20"), 30, IPv4Address("198.51.100.253")),
    )


def test_ios_xe_has_no_vpc(sw_a: Collection) -> None:
    assert sw_a.collected.vpc is None


# -- Unknown, never absent --------------------------------------------------------------------


def test_every_command_denied_leaves_every_part_unknown_and_nothing_fails() -> None:
    collection = collect(Device({}))

    collected = collection.collected
    assert collected.interfaces == Unknown("show interfaces: denied or not supported by the device")
    assert collected.vlans == Unknown("show vlan brief: denied or not supported by the device")
    assert collected.arp == Unknown("show ip arp: denied or not supported by the device")
    assert isinstance(collected.stack_members, Reading)  # from show version, already read
    assert collection.parse_problems == ()


def test_a_command_that_was_not_sent_is_unknown_with_the_gateways_reason() -> None:
    replies: dict[str, str | Unknown] = dict(ios_xe_text.REPLIES)
    replies["show vlan brief"] = Unknown("a command timed out, so the session was dropped")

    collected = collect(Device(replies)).collected

    assert collected.vlans == Unknown(
        "show vlan brief: a command timed out, so the session was dropped"
    )


def test_output_that_cannot_be_parsed_is_unknown_and_a_parse_problem() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies["show vlan brief"] = "VLAN tables are made of wood\n"
    replies["show ip ospf neighbor"] = ios_xe_text.NOT_UNDERSTOOD

    collection = collect(Device(replies))

    assert collection.collected.vlans == Unknown("show vlan brief: not understood")
    routing = collection.collected.routing_neighbours
    assert isinstance(routing, Reading)
    assert routing.gaps == (Unknown("show ip ospf neighbor: not understood"),)
    assert collection.parse_problems == (
        ParseProblem("show vlan brief", "ntc-templates cisco_ios", "not understood"),
        ParseProblem("show ip ospf neighbor", "ntc-templates cisco_ios", "not understood"),
    )


def test_a_denied_per_vrf_command_is_a_gap_in_its_part() -> None:
    replies = dict(ios_xe_text.REPLIES)
    del replies["show ip arp vrf BLUE"]

    arp = collect(Device(replies)).collected.arp

    assert isinstance(arp, Reading)
    assert arp.gaps == (Unknown("show ip arp vrf BLUE: denied or not supported by the device"),)
    assert "show ip arp vrf BLUE" not in arp.commands


def test_unknown_vrfs_leave_a_gap_where_the_per_vrf_commands_would_be() -> None:
    replies = dict(ios_xe_text.REPLIES)
    del replies["show vrf"]

    collected = collect(Device(replies)).collected

    assert collected.vrfs == Unknown("show vrf: denied or not supported by the device")
    arp = collected.arp
    assert isinstance(arp, Reading)
    assert [gap.reason.split(":")[0] for gap in arp.gaps] == ["show ip arp vrf {vrf}"]


def test_device_text_is_never_kept_beyond_parsed_values() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies["show interfaces"] = ios_xe_text.SHOW_INTERFACES.replace(
        "Description: spare", "Description: spare\x1b[2J\x07 bell"
    )

    port = by_name(collect(Device(replies)).collected)["Gi1/0/2"]

    assert port.description == "spare?[2J? bell"


def test_nx_os_is_not_collected_until_its_own_ticket() -> None:
    collection = platforms.collect(Platform.NX_OS, Device(), device_text.NXOS_SHOW_VERSION)

    assert collection.collected == Collected.nothing(NOT_COLLECTED)


@pytest.mark.parametrize("command", sorted(ios_xe_text.REPLIES))
def test_a_reply_of_the_wrong_shape_is_never_read_as_none(command: str) -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies[command] = "CANARY-out-77e1 this is not\nwhat the command prints\n"

    collection = collect(Device(replies))

    assert [p.command for p in collection.parse_problems] == [command]
    assert "CANARY-out-77e1" not in repr(collection)
