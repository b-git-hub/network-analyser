"""IOS/IOS-XE collection (#59): from command replies to the collected-record contract (#52).

Driven through `platforms.collect` with synthetic replies (tests/support/ios_xe_text): a fake
`send` answers each command as `sw-a` would, and the test reads the `Collection` that comes
back. Expected values are written out by hand from the synthetic text.
"""

from collections.abc import Mapping
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

import pytest

from network_analyser import platforms
from network_analyser.platforms import Collection, Problem
from network_analyser.platforms.ios_xe import parsers
from network_analyser.platforms.ios_xe.collect import PARSER
from network_analyser.records import Platform
from network_analyser.records.collected import (
    ALL_VLANS,
    ArpEntry,
    BundleMember,
    Collected,
    FhrpGroup,
    FhrpProtocol,
    Interface,
    InterfaceIp,
    MacEntry,
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
SHOW_VERSION = "show version"
CRAWL_COMMANDS = frozenset({"show cdp neighbors detail", "show lldp neighbors detail"})


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
    """Collect as the gateway does: `show version` already read, and answered again."""
    device.replies.setdefault(SHOW_VERSION, version)
    found = platforms.collect(
        Platform.IOS_XE, device, platforms.read_version(Platform.IOS_XE, version)
    )
    assert found is not None
    return found


def value[T](part: Reading[T] | Unknown | None) -> T:
    assert isinstance(part, Reading), part
    return part.value


def by_name(collected: Collected) -> dict[str, Interface]:
    return {i.name.short: i for i in value(collected.interfaces)}


@pytest.fixture(scope="module")
def sw_a() -> Collection:
    return collect(Device())


# -- What is sent -----------------------------------------------------------------------------


def test_every_command_is_on_the_allow_list_and_sent_once() -> None:
    device = Device()

    collect(device)

    assert len(device.asked) == len(set(device.asked))
    assert set(device.asked) == set(ios_xe_text.REPLIES) | {SHOW_VERSION}


def test_the_crawls_neighbour_tables_are_not_asked_for_again() -> None:
    device = Device()

    collected = collect(device).collected

    assert not CRAWL_COMMANDS & set(device.asked)
    assert collected.cdp == Unknown("not collected by this version of the tool")
    assert collected.lldp == Unknown("not collected by this version of the tool")


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


def test_stack_members_come_from_show_version_sent_again(sw_a: Collection) -> None:
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


def test_show_version_not_answered_again_leaves_the_stack_unknown() -> None:
    replies: dict[str, str | Unknown] = dict(ios_xe_text.REPLIES)
    dropped = Unknown("show version: not read, the session was dropped")
    replies[SHOW_VERSION] = dropped

    collected = collect(Device(replies)).collected

    assert collected.stack_members == dropped
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
    reason = Unknown("show interfaces switchport: denied")
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


@pytest.mark.parametrize(
    "text",
    [
        "  BLUE                             65000:1               ipv4        Vl20\n",
        "  Interfaces are listed below\n  BLUE  ipv4\n",
        "Load for five secs: 1%/0%; one minute: 1%\nTime source is NTP\n",
    ],
)
def test_show_vrf_without_its_header_is_not_understood_never_no_vrfs(text: str) -> None:
    assert parsers.vrfs(text) is None


def test_show_vrf_with_its_header_and_no_rows_is_no_vrfs() -> None:
    header = "  Name                             Default RD            Protocols   Interfaces\n"

    assert parsers.vrfs(header) == ()


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

    collection = collect(Device(replies))

    routing = collection.collected.routing_neighbours
    assert isinstance(routing, Reading)
    assert routing.gaps == ()
    assert IPv4Address("192.0.2.3") not in {n.ip for n in routing.value}
    assert collection.problems == ()


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


def test_a_full_collection_has_no_problems_and_names_its_parser(sw_a: Collection) -> None:
    assert sw_a.problems == ()
    assert sw_a.parser == PARSER


def test_every_command_denied_leaves_every_part_unknown_and_nothing_fails() -> None:
    device = Device({})
    collection = collect(device)

    collected = collection.collected
    assert collected.interfaces == Unknown("show interfaces: denied")
    assert collected.vlans == Unknown("show vlan brief: denied")
    assert collected.arp == Unknown("show ip arp: denied")
    assert isinstance(collected.stack_members, Reading)  # show version is always allowed
    denied = [c for c in device.asked if c != SHOW_VERSION]
    assert collection.problems == tuple(Problem(c, "denied") for c in denied)


def test_a_command_that_was_not_sent_is_unknown_with_the_gateways_reason() -> None:
    replies: dict[str, str | Unknown] = dict(ios_xe_text.REPLIES)
    dropped = Unknown("show vlan brief: not read, the session was dropped")
    replies["show vlan brief"] = dropped

    collection = collect(Device(replies))

    assert collection.collected.vlans == dropped
    assert collection.problems == ()  # the gateway has recorded the drop itself


def test_output_that_cannot_be_parsed_is_unknown_and_a_problem() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies["show vlan brief"] = "VLAN tables are made of wood\n"
    replies["show ip ospf neighbor"] = ios_xe_text.NOT_UNDERSTOOD

    collection = collect(Device(replies))

    assert collection.collected.vlans == Unknown("show vlan brief: not understood")
    routing = collection.collected.routing_neighbours
    assert isinstance(routing, Reading)
    assert routing.gaps == (Unknown("show ip ospf neighbor: not understood"),)
    assert collection.problems == (
        Problem("show vlan brief", "not understood"),
        Problem("show ip ospf neighbor", "not understood"),
    )


def test_a_denied_per_vrf_command_is_a_gap_in_its_part() -> None:
    replies = dict(ios_xe_text.REPLIES)
    del replies["show ip arp vrf BLUE"]

    collection = collect(Device(replies))

    arp = collection.collected.arp
    assert isinstance(arp, Reading)
    assert arp.gaps == (Unknown("show ip arp vrf BLUE: denied"),)
    assert "show ip arp vrf BLUE" not in arp.commands
    assert collection.problems == (Problem("show ip arp vrf BLUE", "denied"),)


def test_unknown_vrfs_leave_a_gap_where_the_per_vrf_commands_would_be() -> None:
    replies = dict(ios_xe_text.REPLIES)
    del replies["show vrf"]

    collected = collect(Device(replies)).collected

    assert collected.vrfs == Unknown("show vrf: denied")
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


@pytest.mark.parametrize("command", sorted(ios_xe_text.REPLIES))
def test_a_reply_of_the_wrong_shape_is_never_read_as_none(command: str) -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies[command] = "CANARY-out-77e1 this is not\nwhat the command prints\n"

    collection = collect(Device(replies))

    assert collection.problems == (Problem(command, "not understood"),)
    assert "CANARY-out-77e1" not in repr(collection)
