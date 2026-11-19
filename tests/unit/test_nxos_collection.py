"""NX-OS collection: every Visited Nexus yields the data the Topology needs (ticket #60).

Driven through `platforms.collect` with a scripted `send` that answers from hand-written,
synthetic `| json` replies (tests/support/nxos_json). Each test checks the collected record
(`records.collected`) and the problems handed back for the Audit log.
"""

import json
from collections.abc import Mapping
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address

import pytest

from network_analyser import platforms
from network_analyser.platforms import Collection, Problem
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
    Neighbour,
    PortChannel,
    Reading,
    RoutingNeighbour,
    RoutingProtocol,
    StackMember,
    StaticRoute,
    SwitchportMode,
    Vlan,
    VpcKeepalive,
    VpcPortChannel,
    VpcState,
    Vrf,
)
from network_analyser.records.device import Unknown, VersionFacts
from network_analyser.records.interface_names import InterfaceName, interface_name
from tests.support import nxos_json
from tests.support.nxos_json import NXOS_JSON_REPLIES

VERSION = VersionFacts("nx-a", "C9300v", "9.3(8)", ("TEST0000N01",))
FEATURES = "show feature | json"


class Device:
    """Answers each command from `replies`; anything else gets NX-OS's invalid-command text."""

    def __init__(self, replies: Mapping[str, str | Unknown] = NXOS_JSON_REPLIES) -> None:
        self.replies = dict(replies)
        self.sent: list[str] = []

    def send(self, command: str) -> str | Unknown:
        assert platforms.permits(Platform.NX_OS, command), command
        self.sent.append(command)
        return self.replies.get(command, nxos_json.INVALID)

    def collect(self) -> Collection:
        found = platforms.collect(Platform.NX_OS, self.send, VERSION)
        assert found is not None
        return found


def _collected(device: Device | None = None) -> Collected:
    return (device or Device()).collect().collected


def _value[T](part: Reading[T] | Unknown | None) -> T:
    assert isinstance(part, Reading), part
    return part.value


def _name(reported: str) -> InterfaceName:
    return interface_name(reported)


def _interface(collected: Collected, short: str) -> Interface:
    return next(i for i in _value(collected.interfaces) if i.name.short == short)


# -- A healthy vPC switch ------------------------------------------------------------------


def test_every_interface_is_read_down_ones_included_with_its_reported_name() -> None:
    interfaces = _value(_collected().interfaces)

    assert [i.name for i in interfaces] == [
        InterfaceName("mgmt0", "mgmt0", known=True),
        InterfaceName("Eth1/1", "Ethernet1/1", known=True),
        InterfaceName("Eth1/2", "Ethernet1/2", known=True),
        InterfaceName("Eth1/3", "Ethernet1/3", known=True),
        InterfaceName("Eth1/4", "Ethernet1/4", known=True),
        InterfaceName("Eth1/5", "Ethernet1/5", known=True),
        InterfaceName("Po1", "port-channel1", known=True),
        InterfaceName("Po10", "port-channel10", known=True),
        InterfaceName("Lo0", "loopback0", known=True),
        InterfaceName("Vl10", "Vlan10", known=True),
    ]


def test_a_trunk_port_carries_its_vlans_bundle_and_state() -> None:
    assert _interface(_collected(), "Eth1/3") == Interface(
        name=_name("Ethernet1/3"),
        description="to sw-c",
        admin_up=True,
        line_up=True,
        speed="10 Gb/s",
        mode=SwitchportMode.TRUNK,
        native_vlan=10,
        allowed_vlans=frozenset({10, 20, 30, 31, 32}),
        bundle="Po10",
    )


def test_a_trunk_allowing_all_vlans_allows_1_to_4094() -> None:
    peer_link = _interface(_collected(), "Po1")

    assert peer_link.allowed_vlans == ALL_VLANS
    assert peer_link.bundle is None


def test_an_access_port_has_only_its_access_vlan() -> None:
    port = _interface(_collected(), "Eth1/5")

    assert (port.mode, port.access_vlan, port.native_vlan, port.allowed_vlans) == (
        SwitchportMode.ACCESS,
        20,
        None,
        None,
    )
    assert (port.admin_up, port.line_up, port.description) == (True, False, "")


def test_routed_ports_svis_and_loopbacks_carry_their_vrf_and_addresses() -> None:
    collected = _collected()

    svi = _interface(collected, "Vl10")
    assert (svi.mode, svi.description, svi.admin_up, svi.line_up) == (
        SwitchportMode.ROUTED,
        "users",
        True,
        True,
    )
    assert svi.ip == InterfaceIp(
        "default", (IPv4Interface("192.0.2.129/25"), IPv4Interface("203.0.113.1/24"))
    )
    routed = _interface(collected, "Eth1/4")
    assert (routed.mode, routed.admin_up, routed.ip) == (
        SwitchportMode.ROUTED,
        False,
        InterfaceIp("default", (IPv4Interface("198.51.100.1/30"),)),
    )
    assert _interface(collected, "mgmt0").ip == InterfaceIp(
        "management", (IPv4Interface("192.0.2.11/24"),)
    )
    assert _interface(collected, "Lo0").ip == InterfaceIp(
        "default", (IPv4Interface("198.51.100.200/32"),)
    )


def test_a_layer_2_port_has_no_ip_settings() -> None:
    assert _interface(_collected(), "Eth1/1").ip is None


def test_the_management_vrf_is_marked() -> None:
    assert _value(_collected().vrfs) == (
        Vrf("blue", management=False),
        Vrf("default", management=False),
        Vrf("management", management=True),
    )


def test_the_vlan_database_is_read() -> None:
    assert _value(_collected().vlans) == (
        Vlan(1, "default", active=True),
        Vlan(10, "users", active=True),
        Vlan(20, "voice", active=False),
    )


def test_the_port_channel_summary_is_read() -> None:
    assert _value(_collected().port_channels) == (
        PortChannel(
            _name("port-channel1"),
            (
                BundleMember(_name("Ethernet1/1"), bundled=True),
                BundleMember(_name("Ethernet1/2"), bundled=False),
            ),
            "LACP",
        ),
        PortChannel(
            _name("port-channel10"), (BundleMember(_name("Ethernet1/3"), bundled=True),), "none"
        ),
    )


def test_the_vpc_domain_peer_link_keepalive_and_members_are_read() -> None:
    vpc = _collected().vpc

    assert _value(vpc) == VpcState(
        domain=10,
        peer_link=_name("Po1"),
        keepalive=VpcKeepalive(IPv4Address("192.0.2.11"), IPv4Address("192.0.2.12"), "management"),
        port_channels=(VpcPortChannel(10, _name("Po10")),),
    )
    assert isinstance(vpc, Reading)
    assert vpc.commands == ("show vpc brief | json", "show vpc peer-keepalive | json")


def test_cdp_neighbours_keep_every_address_management_first() -> None:
    assert _value(_collected().cdp) == (
        Neighbour(
            local_port=_name("Ethernet1/1"),
            name="nx-b(TEST0000N02)",
            remote_port=_name("Ethernet1/1"),
            addresses=(IPv4Address("192.0.2.12"),),
            platform=("N9K-C9300v, Cisco Nexus Operating System (NX-OS) Software, Version 9.3(8)"),
            native_vlan=1,
        ),
        Neighbour(
            local_port=_name("Ethernet1/3"),
            name="sw-c",
            remote_port=_name("GigabitEthernet1/0/49"),
            addresses=(
                IPv4Address("192.0.2.30"),
                IPv4Address("198.51.100.20"),
            ),
            platform="cisco C9300-48P, Cisco IOS Software [Cupertino]",
            native_vlan=10,
        ),
    )


def test_lldp_neighbours_carry_their_chassis_id_and_ipv6_addresses() -> None:
    assert _value(_collected().lldp) == (
        Neighbour(
            local_port=_name("Eth1/3"),
            name="sw-c",
            remote_port=_name("Gi1/0/49"),
            addresses=(IPv4Address("192.0.2.30"),),
            platform="Cisco IOS Software, Catalyst L3 Switch",
            ipv6_addresses=(IPv6Address("2001:db8::30"),),
            chassis_id="0000.5e00.5302",
        ),
    )


def test_arp_entries_are_read_in_every_vrf_and_incomplete_ones_left_out() -> None:
    assert _value(_collected().arp) == (
        ArpEntry("default", IPv4Address("192.0.2.140"), "00005e005310", _name("Vlan10")),
        ArpEntry("management", IPv4Address("192.0.2.12"), "00005e005312", _name("mgmt0")),
    )


def test_the_mac_table_keeps_port_entries_and_leaves_out_the_devices_own() -> None:
    assert _value(_collected().mac) == (
        MacEntry(10, "00005e005310", _name("Ethernet1/3"), dynamic=True),
        MacEntry(20, "00005e005320", _name("port-channel10"), dynamic=False),
    )


def test_ospf_and_bgp_neighbours_are_read_in_every_vrf() -> None:
    assert _value(_collected().routing_neighbours) == (
        RoutingNeighbour(
            RoutingProtocol.OSPF, "default", IPv4Address("192.0.2.130"), _name("Vlan10"), "FULL"
        ),
        RoutingNeighbour(
            RoutingProtocol.BGP, "default", IPv4Address("203.0.113.9"), None, "Established"
        ),
        RoutingNeighbour(RoutingProtocol.BGP, "default", IPv4Address("203.0.113.10"), None, "Idle"),
    )


def test_static_routes_are_read_in_every_vrf() -> None:
    assert _value(_collected().static_routes) == (
        StaticRoute(
            "default", IPv4Network("0.0.0.0/0"), IPv4Address("192.0.2.254"), _name("Vlan10")
        ),
        StaticRoute("default", IPv4Network("203.0.113.128/25"), None, _name("Null0")),
        StaticRoute("management", IPv4Network("198.51.100.0/24"), IPv4Address("192.0.2.1"), None),
    )


def test_hsrp_virtual_ips_are_read() -> None:
    assert _value(_collected().fhrp) == (
        FhrpGroup(FhrpProtocol.HSRP, _name("Vlan10"), 10, IPv4Address("192.0.2.254")),
    )


def test_a_nexus_is_one_member_with_its_chassis_serial() -> None:
    stack = _collected().stack_members

    assert _value(stack) == (StackMember(1, "TEST0000N01", "C9300v"),)
    assert isinstance(stack, Reading)
    assert stack.commands == ("show version",)


# -- What is sent ----------------------------------------------------------------------------


def test_each_collection_command_is_sent_once_and_features_turned_off_are_not_asked() -> None:
    device = Device()

    found = device.collect()

    assert device.sent[0] == FEATURES
    assert sorted(device.sent) == sorted(NXOS_JSON_REPLIES)
    assert found.problems == ()
    collected = found.collected
    assert all(not isinstance(getattr(collected, f), Unknown) for f in collected.__slots__)


def test_a_feature_turned_off_means_none_with_show_feature_as_evidence() -> None:
    collected = _collected()

    fhrp = collected.fhrp
    assert isinstance(fhrp, Reading)
    assert FEATURES in fhrp.commands
    routing = collected.routing_neighbours
    assert isinstance(routing, Reading)
    assert FEATURES in routing.commands
    assert all(n.protocol is not RoutingProtocol.EIGRP for n in routing.value)


def test_a_device_without_vpc_has_no_vpc_state() -> None:
    features = json.loads(NXOS_JSON_REPLIES[FEATURES])
    for row in features["TABLE_cfcFeatureCtrlTable"]["ROW_cfcFeatureCtrlTable"]:
        if row["cfcFeatureCtrlName2"] == "vpc":
            row["cfcFeatureCtrlOpStatus2"] = "disabled"
    replies = dict(NXOS_JSON_REPLIES)
    replies[FEATURES] = json.dumps(features)
    device = Device(replies)

    assert device.collect().collected.vpc is None
    assert "show vpc brief | json" not in device.sent


def test_a_vpc_feature_with_no_domain_configured_has_no_vpc_state() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show vpc brief | json"] = '{"vpc-domain-id": "not configured"}'

    assert Device(replies).collect().collected.vpc is None


def test_an_empty_reply_means_there_are_none() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show lldp neighbors detail | json"] = ""
    replies["show ip arp vrf all | json"] = "\n"

    collected = _collected(Device(replies))

    assert _value(collected.lldp) == ()
    assert _value(collected.arp) == ()


# -- Denied, refused or not understood -------------------------------------------------------


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        (nxos_json.DENIED, "show vlan brief | json: denied"),
        ("% Authorization failed.\n", "show vlan brief | json: denied"),
        (nxos_json.INVALID, "show vlan brief | json: rejected by the device"),
        ('{"TABLE_vlanbriefxbrief": 7}', "show vlan brief | json: not understood"),
        ("not json at all CANARY-device-text", "show vlan brief | json: not understood"),
    ],
    ids=["role denies", "AAA denies", "invalid command", "wrong shape", "not JSON"],
)
def test_a_denied_or_unreadable_command_leaves_only_its_data_unknown(
    reply: str, reason: str
) -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show vlan brief | json"] = reply

    found = Device(replies).collect()

    assert found.collected.vlans == Unknown(reason)
    assert found.problems == (Problem("show vlan brief | json", reason.split(": ")[1]),)
    assert isinstance(found.collected.interfaces, Reading)
    assert "CANARY" not in repr(found)


def test_a_denied_switchport_command_leaves_the_switchport_values_unknown() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show interface switchport | json"] = nxos_json.DENIED

    interfaces = _collected(Device(replies)).interfaces

    assert isinstance(interfaces, Reading)
    gap = Unknown("show interface switchport | json: denied")
    assert interfaces.gaps == (gap,)
    port = next(i for i in interfaces.value if i.name.short == "Eth1/3")
    assert (port.mode, port.access_vlan, port.native_vlan, port.allowed_vlans) == (gap,) * 4
    assert port.admin_up is True
    svi = next(i for i in interfaces.value if i.name.short == "Vl10")
    assert svi.mode is SwitchportMode.ROUTED


def test_a_denied_ip_interface_command_leaves_every_ip_unknown() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show ip interface vrf all | json"] = nxos_json.DENIED

    interfaces = _collected(Device(replies)).interfaces

    assert isinstance(interfaces, Reading)
    gap = Unknown("show ip interface vrf all | json: denied")
    assert interfaces.gaps == (gap,)
    assert all(i.ip == gap for i in interfaces.value)


def test_a_denied_port_channel_summary_leaves_bundle_membership_unknown() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show port-channel summary | json"] = nxos_json.DENIED

    collected = _collected(Device(replies))

    gap = Unknown("show port-channel summary | json: denied")
    assert collected.port_channels == gap
    assert _interface(collected, "Eth1/3").bundle == gap


def test_without_show_interface_the_interfaces_are_unknown() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show interface | json"] = nxos_json.DENIED

    assert _collected(Device(replies)).interfaces == Unknown("show interface | json: denied")


def test_one_denied_routing_protocol_is_a_gap_and_the_others_are_kept() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show ip bgp summary vrf all | json"] = nxos_json.DENIED

    routing = _collected(Device(replies)).routing_neighbours

    assert isinstance(routing, Reading)
    assert routing.gaps == (Unknown("show ip bgp summary vrf all | json: denied"),)
    assert [n.protocol for n in routing.value] == [RoutingProtocol.OSPF]


def test_a_denied_keepalive_leaves_only_the_keepalive_unknown() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show vpc peer-keepalive | json"] = nxos_json.DENIED

    vpc = _value(_collected(Device(replies)).vpc)

    assert vpc.keepalive == Unknown("show vpc peer-keepalive | json: denied")
    assert vpc.peer_link == _name("Po1")


def test_without_show_feature_every_command_is_tried_and_a_missing_one_is_unknown() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies[FEATURES] = nxos_json.DENIED
    device = Device(replies)

    found = device.collect()

    assert "show ip eigrp neighbors vrf all | json" in device.sent
    assert "show vrrp | json" in device.sent
    routing = found.collected.routing_neighbours
    assert isinstance(routing, Reading)
    assert routing.gaps == (
        Unknown("show ip eigrp neighbors vrf all | json: rejected by the device"),
    )
    assert Problem(FEATURES, "denied") in found.problems


def test_a_dropped_session_leaves_the_rest_unknown_with_its_reason() -> None:
    dropped = Unknown("show vlan brief | json: not read, the session was dropped")
    replies: dict[str, str | Unknown] = dict(NXOS_JSON_REPLIES)
    replies["show vlan brief | json"] = dropped

    found = Device(replies).collect()

    assert found.collected.vlans == dropped
    assert Problem("show vlan brief | json", "not read, the session was dropped") not in (
        found.problems
    )


# -- Untrusted device text ---------------------------------------------------------------------


def test_device_text_is_made_printable_and_capped() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show interface | json"] = replies["show interface | json"].replace(
        '"desc": "to sw-c"', '"desc": "to \\u001b[2Jsw-c' + "x" * 300 + '"'
    )

    description = _interface(_collected(Device(replies)), "Eth1/3").description

    assert isinstance(description, str)
    assert description.startswith("to ?[2Jsw-c")
    assert len(description) == 255


def test_a_malformed_address_leaves_the_reading_unknown_never_guessed() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show ip arp vrf all | json"] = replies["show ip arp vrf all | json"].replace(
        "192.0.2.140", "192.0.2.999"
    )

    found = Device(replies).collect()

    assert found.collected.arp == Unknown("show ip arp vrf all | json: not understood")


def test_a_reply_nested_too_deep_to_read_is_not_understood() -> None:
    replies = dict(NXOS_JSON_REPLIES)
    replies["show vrf | json"] = '{"a": ' + "[" * 100_000 + "]" * 100_000 + "}"

    assert _collected(Device(replies)).vrfs == Unknown("show vrf | json: not understood")
