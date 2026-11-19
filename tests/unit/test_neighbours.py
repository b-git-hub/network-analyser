"""Reading CDP and LLDP Neighbours, and their Platform hints (ticket #50; stories 60-65, 74).

Driven through `platforms`' public interface with synthetic text (tests/support/device_text).
"""

from ipaddress import IPv4Address, IPv6Address

import pytest

from network_analyser import platforms
from network_analyser.platforms import Unsupported
from network_analyser.records import Platform
from network_analyser.records.neighbour import NeighbourProtocol, NeighbourRecord
from network_analyser.records.unknown import Unknown
from tests.support import device_text

CDP = NeighbourProtocol.CDP
LLDP = NeighbourProtocol.LLDP


def _read(platform: Platform, protocol: NeighbourProtocol, text: str) -> list[NeighbourRecord]:
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

    assert switch == NeighbourRecord(
        protocol=CDP,
        local_port="GigabitEthernet1/0/1",
        remote_port="GigabitEthernet1/0/24",
        management_addresses=(IPv4Address("192.0.2.2"),),
        other_addresses=(IPv4Address("198.51.100.2"), IPv6Address("2001:db8::2")),
        device_id="sw-b.example.test",
        platform="cisco C9300-48P",
        description=(
            "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), "
            "Version 17.9.4a"
        ),
        capabilities=("Switch", "IGMP"),
        chassis_id=None,
    )
    assert switch.addresses[0] == IPv4Address("192.0.2.2")
    assert phone.management_addresses == ()
    assert phone.other_addresses == (IPv4Address("192.0.2.50"),)
    assert phone.remote_port == "Port 1"
    assert phone.capabilities == ("Host", "Phone", "Two-port", "Mac", "Relay")


def test_ios_xe_lldp_detail_gives_chassis_id_ports_and_the_system_description() -> None:
    nexus, host = _read(Platform.IOS_XE, LLDP, device_text.IOS_XE_LLDP_DETAIL)

    assert nexus == NeighbourRecord(
        protocol=LLDP,
        local_port="Gi1/0/2",
        remote_port="Eth1/1",
        management_addresses=(IPv4Address("192.0.2.12"), IPv6Address("2001:db8::12")),
        other_addresses=(),
        device_id="nx-a",
        platform=None,
        description="Cisco Nexus Operating System (NX-OS) Software 9.3(8)",
        capabilities=("B", "R"),
        chassis_id="5254.0012.3401",
    )
    assert host.addresses == ()
    assert host.device_id is None
    assert host.description is None
    assert host.capabilities == ()
    assert host.remote_port == "ens3"


def test_nxos_cdp_json_gives_management_address_first_and_ipv6_only_neighbours() -> None:
    catalyst, nexus = _read(Platform.NX_OS, CDP, device_text.NXOS_CDP_DETAIL_JSON)

    assert catalyst.local_port == "Ethernet1/1"
    assert catalyst.remote_port == "GigabitEthernet1/0/2"
    assert catalyst.addresses == (IPv4Address("192.0.2.1"), IPv4Address("198.51.100.1"))
    assert catalyst.device_id == "sw-a(TEST0000A01)"
    assert catalyst.platform == "cisco C9300-48P"
    assert catalyst.capabilities == ("router", "switch", "IGMP_cnd_filtering")
    assert nexus.addresses == (IPv6Address("2001:db8::22"),)


def test_nxos_lldp_json_with_a_single_row_gives_one_neighbour() -> None:
    (catalyst,) = _read(Platform.NX_OS, LLDP, device_text.NXOS_LLDP_DETAIL_JSON)

    assert catalyst.local_port == "Eth1/1"
    assert catalyst.remote_port == "Gi1/0/2"
    assert catalyst.management_addresses == (IPv4Address("192.0.2.1"),)
    assert catalyst.chassis_id == "5254.0012.3403"
    assert catalyst.capabilities == ("B", "R")


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

    assert switch.device_id is not None
    assert "\x1b" not in switch.device_id
    assert len(switch.device_id) <= 255


def test_odd_addresses_are_kept_for_the_scope_to_refuse_and_junk_is_dropped() -> None:
    text = device_text.IOS_XE_CDP_DETAIL.replace("192.0.2.2", "127.0.0.1").replace(
        "198.51.100.2", "999.1.1.1"
    )

    switch = _read(Platform.IOS_XE, CDP, text)[0]

    assert switch.addresses == (IPv4Address("127.0.0.1"), IPv6Address("2001:db8::2"))


# -- Platform hints (stories 62-63) ---------------------------------------------------------


def _neighbour(
    *,
    platform: str | None = None,
    description: str | None = None,
    capabilities: tuple[str, ...] = (),
) -> NeighbourRecord:
    return NeighbourRecord(
        protocol=CDP,
        local_port="Gi1/0/1",
        remote_port="Gi1/0/2",
        management_addresses=(IPv4Address("192.0.2.2"),),
        other_addresses=(),
        device_id="sw-b",
        platform=platform,
        description=description,
        capabilities=capabilities,
        chassis_id=None,
    )


@pytest.mark.parametrize(
    ("neighbour", "hint"),
    [
        (_neighbour(description="Cisco IOS Software, C3750E Software"), Platform.IOS_XE),
        (_neighbour(description="Cisco IOS XE Software, Version 17.09.04a"), Platform.IOS_XE),
        (_neighbour(description="Cisco Nexus Operating System (NX-OS) Software"), Platform.NX_OS),
        (_neighbour(platform="N9K-C9300v"), Platform.NX_OS),
        (_neighbour(platform="cisco Nexus9000 C9300v Chassis"), Platform.NX_OS),
        (_neighbour(), None),
        (_neighbour(platform="cisco C9300-48P", capabilities=("Switch",)), None),
        (_neighbour(description="Some Other Operating System"), None),
    ],
)
def test_a_supported_hint_or_none(neighbour: NeighbourRecord, hint: Platform | None) -> None:
    assert platforms.neighbour_hint(neighbour) == hint


@pytest.mark.parametrize(
    ("neighbour", "name"),
    [
        (_neighbour(platform="PA-3220", description="Palo Alto Networks PA-3200 series"), "PAN-OS"),
        (_neighbour(description="Cisco Adaptive Security Appliance Software 9.16"), "ASA"),
        (_neighbour(description="Cisco Firepower Threat Defense, Version 7.2"), "FTD"),
        (_neighbour(description="Cisco IOS XR Software, Version 7.5.2"), "IOS-XR"),
        (_neighbour(platform="Meraki MS225-48LP Cloud Managed Switch"), "Meraki"),
        (_neighbour(platform="Cisco IP Phone 8865", capabilities=("Host", "Phone")), "phone"),
        (_neighbour(capabilities=("T",)), "phone"),
        (
            _neighbour(
                platform="cisco AIR-AP2802I-E-K9",
                description="Cisco AP Software, ap3g3-k9w8 Version: 17.9.4a",
            ),
            "access point",
        ),
        (
            _neighbour(description="Cisco IOS Software, C3600 Software (AP3G2-K9W8-M)"),
            "access point",
        ),
        (_neighbour(description="Ubuntu 22.04.3 LTS Linux 5.15.0-91-generic"), "host"),
        (_neighbour(platform="VMware ESX", capabilities=("Switch",)), "host"),
        (_neighbour(capabilities=("Host",)), "host"),
        (_neighbour(capabilities=("S",)), "host"),
    ],
)
def test_a_known_unsupported_platform_is_named(neighbour: NeighbourRecord, name: str) -> None:
    assert platforms.neighbour_hint(neighbour) == Unsupported(name)


def test_iol_on_linux_is_still_ios() -> None:
    neighbour = _neighbour(
        description="Cisco IOS Software [Dublin], Linux Software (X86_64BI_LINUX_L2-ADVK9-M)"
    )

    assert platforms.neighbour_hint(neighbour) is Platform.IOS_XE
