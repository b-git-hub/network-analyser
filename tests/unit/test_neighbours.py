"""Reading CDP and LLDP Neighbours, and their Platform hints (ticket #50; stories 60-65, 74).

Driven through `platforms`' public interface with synthetic text (tests/support/device_text).
The entries are `records.collected.Neighbour`s, the record the Topology reads (#52).
"""

from ipaddress import IPv4Address, IPv6Address

import pytest

from network_analyser import platforms
from network_analyser.platforms import NeighbourProtocol, Unsupported
from network_analyser.records import Platform
from network_analyser.records.collected import Neighbour
from network_analyser.records.interface_names import interface_name
from network_analyser.records.unknown import Unknown
from tests.support import device_text

CDP = NeighbourProtocol.CDP
LLDP = NeighbourProtocol.LLDP


def _read(platform: Platform, protocol: NeighbourProtocol, text: str) -> list[Neighbour]:
    found = platforms.read_neighbours(platform, protocol, text)
    assert not isinstance(found, Unknown), found
    return list(found)


def test_each_platform_asks_for_cdp_then_lldp_neighbour_detail_on_its_allow_list() -> None:
    assert platforms.neighbour_commands(Platform.IOS_XE) == (
        (CDP, "show cdp neighbors detail"),
        (LLDP, "show lldp neighbors detail"),
    )
    assert platforms.neighbour_commands(Platform.NX_OS) == (
        (CDP, "show cdp neighbors detail | json"),
        (LLDP, "show lldp neighbors detail | json"),
    )
    for platform in Platform:
        for _protocol, command in platforms.neighbour_commands(platform):
            assert platforms.permits(platform, command)


def test_ios_xe_cdp_detail_gives_ports_management_address_first_and_the_platform() -> None:
    switch, phone = _read(Platform.IOS_XE, CDP, device_text.IOS_XE_CDP_DETAIL)

    assert switch == Neighbour(
        local_port=interface_name("GigabitEthernet1/0/1"),
        name="sw-b.example.test",
        remote_port=interface_name("GigabitEthernet1/0/24"),
        addresses=(IPv4Address("192.0.2.2"), IPv4Address("198.51.100.2")),
        platform=(
            "cisco C9300-48P; Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
            "(CAT9K_IOSXE), Version 17.9.4a"
        ),
        ipv6_addresses=(IPv6Address("2001:db8::2"),),
        chassis_id=None,
        native_vlan=1,
    )
    assert phone.addresses == (IPv4Address("192.0.2.50"),)
    assert phone.remote_port == interface_name("Port 1")
    assert phone.native_vlan is None


def test_ios_xe_lldp_detail_gives_chassis_id_ports_and_the_system_description() -> None:
    nexus, host = _read(Platform.IOS_XE, LLDP, device_text.IOS_XE_LLDP_DETAIL)

    assert nexus == Neighbour(
        local_port=interface_name("Gi1/0/2"),
        name="nx-a",
        remote_port=interface_name("Eth1/1"),
        addresses=(IPv4Address("192.0.2.12"),),
        platform="Cisco Nexus Operating System (NX-OS) Software 9.3(8)",
        ipv6_addresses=(IPv6Address("2001:db8::12"),),
        chassis_id="5254.0012.3401",
    )
    assert host.addresses == ()
    assert isinstance(host.name, Unknown)
    assert isinstance(host.platform, Unknown)
    assert host.remote_port == interface_name("ens3")


def test_nxos_cdp_json_gives_management_address_first_and_ipv6_only_neighbours() -> None:
    catalyst, nexus = _read(Platform.NX_OS, CDP, device_text.NXOS_CDP_DETAIL_JSON)

    assert catalyst.local_port == interface_name("Ethernet1/1")
    assert catalyst.remote_port == interface_name("GigabitEthernet1/0/2")
    assert catalyst.addresses == (IPv4Address("192.0.2.1"), IPv4Address("198.51.100.1"))
    assert catalyst.name == "sw-a(TEST0000A01)"
    assert catalyst.native_vlan == 1
    assert isinstance(catalyst.platform, str)
    assert catalyst.platform.startswith("cisco C9300-48P; Cisco IOS Software")
    assert nexus.addresses == ()
    assert nexus.ipv6_addresses == (IPv6Address("2001:db8::22"),)


def test_nxos_lldp_json_with_a_single_row_gives_one_neighbour() -> None:
    (catalyst,) = _read(Platform.NX_OS, LLDP, device_text.NXOS_LLDP_DETAIL_JSON)

    assert catalyst.local_port == interface_name("Eth1/1")
    assert catalyst.remote_port == interface_name("Gi1/0/2")
    assert catalyst.addresses == (IPv4Address("192.0.2.1"),)
    assert catalyst.ipv6_addresses == ()
    assert catalyst.chassis_id == "5254.0012.3403"


@pytest.mark.parametrize(
    ("platform", "protocol", "text"),
    [
        (Platform.IOS_XE, CDP, ""),
        (Platform.IOS_XE, LLDP, "\nTotal entries displayed: 0\n"),
        (Platform.NX_OS, CDP, ""),
        (Platform.NX_OS, LLDP, ""),
    ],
)
def test_an_empty_table_is_no_neighbours(
    platform: Platform, protocol: NeighbourProtocol, text: str
) -> None:
    assert platforms.read_neighbours(platform, protocol, text) == ()


@pytest.mark.parametrize(
    ("platform", "protocol", "text"),
    [
        (Platform.IOS_XE, CDP, "% CDP is not enabled\n"),
        (Platform.IOS_XE, LLDP, "% LLDP is not enabled\n"),
        (Platform.IOS_XE, CDP, "                 ^\n% Invalid input detected.\n"),
        (Platform.NX_OS, CDP, "% Invalid command at '^' marker.\n"),
        (Platform.NX_OS, LLDP, '{"TABLE_nbor_detail": "oops"}'),
        (Platform.NX_OS, LLDP, "[1, 2]"),
    ],
)
def test_a_table_the_device_refused_or_that_is_not_understood_is_unknown(
    platform: Platform, protocol: NeighbourProtocol, text: str
) -> None:
    assert isinstance(platforms.read_neighbours(platform, protocol, text), Unknown)


def test_device_text_is_made_printable_and_capped() -> None:
    text = device_text.IOS_XE_CDP_DETAIL.replace("sw-b.example.test", "sw-\x1b[2Jb" + "x" * 300)

    switch = _read(Platform.IOS_XE, CDP, text)[0]

    assert isinstance(switch.name, str)
    assert "\x1b" not in switch.name
    assert len(switch.name) <= 255


def test_odd_addresses_are_kept_for_the_scope_to_refuse_and_junk_is_dropped() -> None:
    text = device_text.IOS_XE_CDP_DETAIL.replace("192.0.2.2", "127.0.0.1").replace(
        "198.51.100.2", "999.1.1.1"
    )

    switch = _read(Platform.IOS_XE, CDP, text)[0]

    assert switch.addresses == (IPv4Address("127.0.0.1"),)


# -- Platform hints (stories 62-63) ---------------------------------------------------------


def _neighbour(platform: str | None = None) -> Neighbour:
    return Neighbour(
        local_port=interface_name("Gi1/0/1"),
        name="sw-b",
        remote_port=interface_name("Gi1/0/2"),
        addresses=(IPv4Address("192.0.2.2"),),
        platform=Unknown("no Platform string was advertised") if platform is None else platform,
    )


@pytest.mark.parametrize(
    ("platform", "hint"),
    [
        ("cisco WS-C3750E; Cisco IOS Software, C3750E Software", Platform.IOS_XE),
        ("Cisco IOS XE Software, Version 17.09.04a", Platform.IOS_XE),
        ("Cisco Nexus Operating System (NX-OS) Software", Platform.NX_OS),
        ("N9K-C9300v", Platform.NX_OS),
        ("cisco Nexus9000 C9300v Chassis", Platform.NX_OS),
        (None, None),
        ("cisco C9300-48P", None),
        ("Some Other Operating System", None),
        (
            "Cisco IOS Software [Dublin], Linux Software (X86_64BI_LINUX_L2-ADVK9-M)",
            Platform.IOS_XE,
        ),
    ],
)
def test_a_supported_hint_or_none(platform: str | None, hint: Platform | None) -> None:
    assert platforms.neighbour_hint(_neighbour(platform)) == hint


@pytest.mark.parametrize(
    ("platform", "name"),
    [
        ("PA-3220; Palo Alto Networks PA-3200 series", "PAN-OS"),
        ("Cisco Adaptive Security Appliance Software 9.16", "ASA"),
        ("Cisco Firepower Threat Defense, Version 7.2", "FTD"),
        ("Cisco IOS XR Software, Version 7.5.2", "IOS-XR"),
        ("Meraki MS225-48LP Cloud Managed Switch", "Meraki"),
        ("Cisco IP Phone 8865; sip8845_65.14-1-1MN-36", "phone"),
        ("cisco AIR-AP2802I-E-K9; Cisco AP Software, ap3g3-k9w8 Version: 17.9.4a", "access point"),
        ("Cisco IOS Software, C3600 Software (AP3G2-K9W8-M)", "access point"),
        ("Ubuntu 22.04.3 LTS Linux 5.15.0-91-generic", "host"),
        ("VMware ESX", "host"),
    ],
)
def test_a_known_unsupported_platform_is_named(platform: str, name: str) -> None:
    assert platforms.neighbour_hint(_neighbour(platform)) == Unsupported(name)
