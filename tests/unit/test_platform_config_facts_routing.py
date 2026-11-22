"""Routing-protocol authentication, judged per interface and per BGP block (#142).

Driven through `platforms.read_config_facts` with synthetic configs. OSPF and EIGRP are
missing authentication when any interface that runs them has none; a protocol whose
interfaces cannot be placed falls back to "any authentication line anywhere". Every secret is
a `CANARY-...` value, and none may reach a fact.
"""

from network_analyser import platforms
from network_analyser.records import Platform
from network_analyser.records.config_facts import ROUTING_AUTHENTICATION_MISSING, FactValue

CANARY = "CANARY-cfg-142-c3d4"
OSPF_AUTH = " ip ospf authentication message-digest\n"
EIGRP_AUTH = " ip authentication mode eigrp 10 md5\n ip authentication key-chain eigrp 10 KC\n"


def _missing(platform: Platform, config: str) -> FactValue:
    facts = {fact.name: fact.value for fact in platforms.read_config_facts(platform, config)}
    assert CANARY not in repr(facts)
    return facts[ROUTING_AUTHENTICATION_MISSING]


def _ospf_two_vlans(auth10: str = "", auth20: str = "") -> str:
    return (
        "router ospf 1\n"
        " network 192.0.2.0 0.0.0.255 area 0\n"
        " network 198.51.100.0 0.0.0.255 area 1\n"
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        f"{auth10}"
        "interface Vlan20\n"
        " ip address 198.51.100.1 255.255.255.0\n"
        f"{auth20}"
    )


# -- OSPF --------------------------------------------------------------------------------------


def test_ospf_with_one_unauthenticated_interface_is_missing_authentication() -> None:
    assert _missing(Platform.IOS_XE, _ospf_two_vlans(auth10=OSPF_AUTH)) == ("OSPF",)


def test_ospf_with_every_interface_authenticated_is_not_missing() -> None:
    config = _ospf_two_vlans(auth10=OSPF_AUTH, auth20=OSPF_AUTH)

    assert _missing(Platform.IOS_XE, config) == ()


def test_ospf_area_authentication_covers_only_the_interfaces_in_that_area() -> None:
    config = _ospf_two_vlans(auth20=OSPF_AUTH)
    area_zero = config.replace("router ospf 1\n", "router ospf 1\n area 0 authentication\n")
    both_areas = area_zero.replace("router ospf 1\n", "router ospf 1\n area 1 authentication\n")

    assert _missing(Platform.IOS_XE, config) == ("OSPF",)
    assert _missing(Platform.IOS_XE, both_areas) == ()
    assert _missing(Platform.IOS_XE, area_zero) == ()


def test_ospf_area_authentication_for_one_area_leaves_the_other_area_missing() -> None:
    config = _ospf_two_vlans().replace("router ospf 1\n", "router ospf 1\n area 0 authentication\n")

    assert _missing(Platform.IOS_XE, config) == ("OSPF",)


def test_ospf_null_authentication_is_not_authentication() -> None:
    null = " ip ospf authentication null\n"

    assert _missing(Platform.IOS_XE, _ospf_two_vlans(null, null)) == ("OSPF",)


def test_a_virtual_link_authentication_line_does_not_authenticate_the_interfaces() -> None:
    config = (
        "router ospf 1\n"
        " network 192.0.2.0 0.0.0.255 area 0\n"
        " area 1 virtual-link 203.0.113.9 authentication message-digest\n"
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
    )

    assert _missing(Platform.IOS_XE, config) == ("OSPF",)


def test_ospf_ignores_loopback_shutdown_and_passive_interfaces() -> None:
    config = (
        "router ospf 1\n"
        " passive-interface Vlan30\n"
        " network 192.0.2.0 0.0.0.255 area 0\n"
        " network 198.51.100.0 0.0.0.255 area 0\n"
        " network 203.0.113.0 0.0.0.255 area 0\n"
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        f"{OSPF_AUTH}"
        "interface Loopback0\n"
        " ip address 198.51.100.1 255.255.255.255\n"
        "interface Vlan20\n"
        " ip address 198.51.100.2 255.255.255.0\n"
        " shutdown\n"
        "interface Vlan30\n"
        " ip address 203.0.113.1 255.255.255.0\n"
    )

    assert _missing(Platform.IOS_XE, config) == ()


def test_passive_interface_default_makes_only_the_exceptions_run_ospf() -> None:
    config = (
        "router ospf 1\n"
        " passive-interface default\n"
        " no passive-interface Vlan10\n"
        " network 192.0.2.0 0.0.0.255 area 0\n"
        " network 198.51.100.0 0.0.0.255 area 0\n"
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        "{auth}"
        "interface Vlan20\n"
        " ip address 198.51.100.1 255.255.255.0\n"
    )

    assert _missing(Platform.IOS_XE, config.format(auth="")) == ("OSPF",)
    assert _missing(Platform.IOS_XE, config.format(auth=OSPF_AUTH)) == ()


def test_ios_xe_interface_area_commands_decide_which_interfaces_run_ospf() -> None:
    config = (
        "router ospf 1\n"
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        " ip ospf 1 area 0\n"
        f"{OSPF_AUTH}"
        "interface Vlan20\n"
        " ip address 198.51.100.1 255.255.255.0\n"
        " ip ospf 1 area 0\n"
    )

    assert _missing(Platform.IOS_XE, config) == ("OSPF",)


def _nxos_ospf(auth30: str = "") -> str:
    return (
        "router ospf 1\n"
        "  area 0.0.0.1 authentication message-digest\n"
        "interface Vlan10\n"
        "  ip address 192.0.2.1/24\n"
        "  ip router ospf 1 area 0.0.0.0\n"
        "  ip ospf authentication message-digest\n"
        "interface Vlan20\n"
        "  ip address 198.51.100.1/24\n"
        "  ip router ospf 1 area 0.0.0.1\n"
        "interface Vlan30\n"
        "  ip address 203.0.113.1/24\n"
        "  ip router ospf 1 area 0.0.0.2\n"
        f"{auth30}"
    )


def test_nxos_ospf_is_judged_per_interface_and_by_area() -> None:
    assert _missing(Platform.NX_OS, _nxos_ospf()) == ("OSPF",)
    assert _missing(Platform.NX_OS, _nxos_ospf("  ip ospf authentication\n")) == ()


def test_nxos_ospf_area_authentication_covers_the_interfaces_in_its_area() -> None:
    config = (
        "router ospf 1\n"
        "  area 0.0.0.1 authentication message-digest\n"
        "interface Vlan20\n"
        "  ip address 198.51.100.1/24\n"
        "  ip router ospf 1 area 1\n"
    )

    assert _missing(Platform.NX_OS, config) == ()


def test_ospf_with_no_interface_it_can_place_falls_back_to_any_authentication() -> None:
    assert _missing(Platform.IOS_XE, "router ospf 1\n router-id 192.0.2.1\n") == ("OSPF",)
    assert _missing(Platform.IOS_XE, "router ospf 1\n area 0 authentication\n") == ()


# -- EIGRP -------------------------------------------------------------------------------------


def _eigrp_classic(auth10: str = "", auth20: str = "") -> str:
    return (
        "router eigrp 10\n"
        " network 192.0.2.0 0.0.0.255\n"
        " network 198.51.100.0\n"
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        f"{auth10}"
        "interface Vlan20\n"
        " ip address 198.51.100.1 255.255.255.0\n"
        f"{auth20}"
    )


def test_eigrp_with_one_unauthenticated_interface_is_missing_authentication() -> None:
    assert _missing(Platform.IOS_XE, _eigrp_classic(auth10=EIGRP_AUTH)) == ("EIGRP",)


def test_eigrp_with_every_interface_authenticated_is_not_missing() -> None:
    config = _eigrp_classic(auth10=EIGRP_AUTH, auth20=EIGRP_AUTH)

    assert _missing(Platform.IOS_XE, config) == ()


def test_eigrp_named_mode_default_af_interface_authentication_covers_every_interface() -> None:
    config = (
        "router eigrp EDGE\n"
        " address-family ipv4 unicast autonomous-system 10\n"
        "  af-interface default\n"
        f"   authentication mode hmac-sha-256 7 {CANARY}-eigrp\n"
        "  exit-af-interface\n"
        "  network 192.0.2.0 0.0.0.255\n"
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
    )

    assert _missing(Platform.IOS_XE, config) == ()


def test_eigrp_named_mode_authentication_on_one_af_interface_covers_only_it() -> None:
    config = (
        "router eigrp EDGE\n"
        " address-family ipv4 unicast autonomous-system 10\n"
        "  af-interface Vlan10\n"
        "   authentication mode md5\n"
        "  exit-af-interface\n"
        "  network 192.0.2.0 0.0.0.255\n"
        "  network 198.51.100.0 0.0.0.255\n"
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        "interface Vlan20\n"
        " ip address 198.51.100.1 255.255.255.0\n"
    )

    assert _missing(Platform.IOS_XE, config) == ("EIGRP",)


def test_eigrp_ignores_passive_loopback_and_shutdown_interfaces() -> None:
    config = (
        "router eigrp 10\n"
        " passive-interface Vlan30\n"
        " network 192.0.2.0 0.0.0.255\n"
        " network 198.51.100.0 0.0.0.255\n"
        " network 203.0.113.0 0.0.0.255\n"
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        f"{EIGRP_AUTH}"
        "interface Loopback0\n"
        " ip address 198.51.100.1 255.255.255.255\n"
        "interface Vlan30\n"
        " ip address 203.0.113.1 255.255.255.0\n"
    )

    assert _missing(Platform.IOS_XE, config) == ()


def test_nxos_eigrp_is_judged_per_interface_unless_the_router_authenticates() -> None:
    config = (
        "router eigrp 10\n"
        "{router_auth}"
        "interface Vlan10\n"
        "  ip address 192.0.2.1/24\n"
        "  ip router eigrp 10\n"
        "  ip authentication mode eigrp 10 md5\n"
        "interface Vlan20\n"
        "  ip address 198.51.100.1/24\n"
        "  ip router eigrp 10\n"
    )

    assert _missing(Platform.NX_OS, config.format(router_auth="")) == ("EIGRP",)
    assert _missing(Platform.NX_OS, config.format(router_auth="  authentication mode md5\n")) == ()


# -- BGP and the rest --------------------------------------------------------------------------


def test_a_bgp_neighbour_password_on_its_own_line_counts_as_authenticated() -> None:
    nxos = f"router bgp 65000\n  neighbor 192.0.2.3\n    password 3 {CANARY}-bgp\n"
    ios_xe = (
        "router bgp 65000\n"
        " template peer-session PS\n"
        f"  password 7 {CANARY}-bgp\n"
        " neighbor 192.0.2.3 inherit peer-session PS\n"
    )

    assert _missing(Platform.NX_OS, nxos) == ()
    assert _missing(Platform.IOS_XE, ios_xe) == ()


def test_a_bgp_neighbour_password_on_the_neighbour_line_still_counts() -> None:
    config = f"router bgp 65000\n neighbor 192.0.2.3 password 7 {CANARY}-bgp\n"

    assert _missing(Platform.IOS_XE, config) == ()


def test_bgp_without_any_password_is_missing_authentication() -> None:
    assert _missing(Platform.NX_OS, "router bgp 65000\n  neighbor 192.0.2.3\n") == ("BGP",)
    config = "router bgp 65000\n neighbor 192.0.2.3 remote-as 65001\n"
    assert _missing(Platform.IOS_XE, config) == ("BGP",)


def test_a_protocol_that_is_not_configured_is_never_missing_authentication() -> None:
    assert _missing(Platform.IOS_XE, "hostname sw-a\n") == ()


def test_each_protocol_is_judged_on_its_own() -> None:
    config = "router ospf 1\n area 0 authentication\nrouter eigrp 10\nrouter bgp 65000\n"

    assert _missing(Platform.IOS_XE, config) == ("BGP", "EIGRP")
