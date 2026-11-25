"""Devices in the Topology: Visited and Unvisited, their ids, and what is unknown (#52).

Stories 126, 138 and 140-141: synthetic records in, Topology out, with no device.
"""

from dataclasses import replace
from ipaddress import IPv4Address

from network_analyser import topology
from network_analyser.records import Platform
from network_analyser.records.collected import NOT_COLLECTED, Collected
from network_analyser.records.device import DeviceRecord, UnvisitedReason, VersionFacts
from network_analyser.records.events import DeviceOutcome
from network_analyser.records.topology import EvidenceSource, UnknownInterfaceName
from network_analyser.records.unknown import Unknown
from tests.support.topology_records import (
    CDP,
    NOT_IN_TEST,
    ip,
    neighbour,
    port,
    unvisited,
    visited,
)


def test_a_visited_device_keeps_its_identity_and_every_interface() -> None:
    record = visited(
        "192.0.2.1",
        "FOC1111A1AA",
        "sw-a",
        aliases=["192.0.2.65"],
        interfaces=[port("Gi1/0/1", stack_member=1), port("GigabitEthernet2/0/1", stack_member=2)],
    )

    (device,) = topology.build([record]).devices

    assert device.id == "dev-FOC1111A1AA"
    assert device.hostname == "sw-a"
    assert device.platform is Platform.IOS_XE
    assert device.model == "C9300-48P"
    assert device.software_version == "17.9.4"
    assert device.serials == ("FOC1111A1AA",)
    assert device.management_ip == IPv4Address("192.0.2.1")
    assert device.alias_ips == (IPv4Address("192.0.2.65"),)
    assert device.outcome is DeviceOutcome.VISITED
    assert isinstance(device.interfaces, tuple)
    assert [(i.name.short, i.stack_member) for i in device.interfaces] == [
        ("Gi1/0/1", 1),
        ("Gi2/0/1", 2),
    ]
    assert device.interfaces[1].name.reported == "GigabitEthernet2/0/1"


def test_a_device_with_no_serial_is_named_by_the_address_logged_into() -> None:
    (device,) = topology.build([visited("192.0.2.7", None)]).devices

    assert device.id == "dev-ip-192.0.2.7"
    assert device.serials == Unknown("serial not found in show version")


def test_interface_addresses_count_as_the_devices_aliases() -> None:
    record = visited("192.0.2.1", "S1", interfaces=[port("Vl10", ips=["198.51.100.1/24"])])

    (device,) = topology.build([record]).devices

    assert IPv4Address("198.51.100.1") in device.alias_ips


def test_data_not_collected_is_unknown_and_listed_as_a_skipped_check() -> None:
    record = visited("192.0.2.1", "S1", cdp=Unknown("show cdp neighbors detail: denied"))

    built = topology.build([record])

    assert built.devices[0].interfaces == Unknown(NOT_IN_TEST)
    skipped = {(s.device, s.data): s.reason for s in built.skipped}
    assert skipped[("dev-S1", "cdp")] == "show cdp neighbors detail: denied"
    assert skipped[("dev-S1", "interfaces")] == NOT_IN_TEST
    assert ("dev-S1", "lldp") not in skipped  # LLDP was read: it just heard no one


def test_a_visited_device_with_nothing_collected_lists_every_part_as_skipped() -> None:
    record = DeviceRecord(
        ip=ip("192.0.2.1"),
        outcome=DeviceOutcome.PARTIAL,
        partial_reason="a command timed out",
        platform=Platform.NX_OS,
        version=VersionFacts("sw-n", "N9K-C93180YC-FX", "10.3(4a)", ("FDO2222B2BB",)),
    )

    built = topology.build([record])

    (device,) = built.devices
    assert device.outcome is DeviceOutcome.PARTIAL
    assert device.partial_reason == "a command timed out"
    assert device.interfaces == Unknown(NOT_COLLECTED)
    assert device.stack_members == Unknown(NOT_COLLECTED)
    assert {s.data for s in built.skipped} == set(Collected.__dataclass_fields__)
    assert {s.reason for s in built.skipped} == {NOT_COLLECTED}


def test_a_routers_parts_that_do_not_apply_are_not_skipped_checks() -> None:
    record = visited("192.0.2.1", "S1", "rtr-c")
    assert record.collected is not None
    router = replace(
        record,
        collected=replace(record.collected, vlans=None, port_channels=None, mac=None),
    )

    built = topology.build([router])

    assert not {s.data for s in built.skipped} & {"vlans", "port_channels", "mac"}
    assert built.devices[0].vlan_database == Unknown("VLANs do not apply to a router")


def test_the_topology_holds_no_username() -> None:
    built = topology.build([visited("192.0.2.1", "S1")])

    assert "netops-ro" not in repr(built)


def test_a_neighbour_at_an_address_nobody_visited_is_an_unvisited_device() -> None:
    record = visited(
        "192.0.2.1",
        "S1",
        cdp=[neighbour("Gi1/0/1", "fw-a", "ethernet1/1", "192.0.2.9", platform="PA-440")],
    )

    built = topology.build([record])

    (device,) = built.unvisited
    assert device.id.startswith("unv-")
    assert device.label == "fw-a"
    assert device.advertised_platform == "PA-440"
    assert device.advertised_ips == (IPv4Address("192.0.2.9"),)
    assert device.chassis_id is None
    assert device.reason == Unknown("no crawl decision was recorded for it")
    (report,) = device.reported_by
    assert report.device == "dev-S1"
    assert report.interface is not None
    assert report.interface.short == "Gi1/0/1"
    assert report.evidence.command == CDP
    assert report.evidence.source is EvidenceSource.CDP


def test_an_unvisited_device_takes_the_reason_the_crawl_recorded_at_its_address() -> None:
    advertised = visited(
        "192.0.2.1", "S1", cdp=[neighbour("Gi1/0/1", "rtr-z", None, "203.0.113.5")]
    )
    not_tried = unvisited("203.0.113.5", UnvisitedReason.OUTSIDE_SCOPE)

    (device,) = topology.build([advertised, not_tried]).unvisited

    assert device.reason is UnvisitedReason.OUTSIDE_SCOPE
    assert device.label == "rtr-z"


def test_a_seed_that_could_not_be_reached_is_an_unvisited_device_with_its_reason() -> None:
    (device,) = topology.build([unvisited("192.0.2.3", UnvisitedReason.UNREACHABLE)]).unvisited

    assert device.reason is UnvisitedReason.UNREACHABLE
    assert device.advertised_ips == (IPv4Address("192.0.2.3"),)
    assert device.label == Unknown("no name was advertised")
    assert device.reported_by == ()


def test_an_ipv6_only_neighbour_is_recorded_as_ipv6_only() -> None:
    record = visited(
        "192.0.2.1", "S1", lldp=[neighbour("Gi1/0/2", "sw-v6", "Gi0/1", ipv6=["2001:db8::5"])]
    )

    (device,) = topology.build([record]).unvisited

    assert device.reason is UnvisitedReason.IPV6_ONLY


def test_advertisements_merge_on_a_shared_address_or_chassis_id_never_on_a_name() -> None:
    a = visited(
        "192.0.2.1",
        "S1",
        cdp=[neighbour("Gi1/0/1", "fw-a", "eth1/1", "192.0.2.9", "192.0.2.10")],
        lldp=[
            neighbour("Gi1/0/1", "fw-a", "eth1/1", "192.0.2.9", chassis="0000.5e00.5301"),
            neighbour("Gi1/0/3", "Switch", "Gi0/1", "192.0.2.30"),
        ],
    )
    b = visited(
        "192.0.2.2",
        "S2",
        "sw-b",
        lldp=[
            neighbour("Gi1/0/9", "fw-a-other-name", "eth1/2", chassis="0000.5e00.5301"),
            neighbour("Gi1/0/4", "Switch", "Gi0/1", "192.0.2.31"),
        ],
    )

    built = topology.build([a, b])

    by_label = sorted(built.unvisited, key=lambda d: d.advertised_ips)
    firewall, switch_30, switch_31 = by_label
    assert firewall.advertised_ips == (IPv4Address("192.0.2.9"), IPv4Address("192.0.2.10"))
    assert firewall.chassis_id == "0000.5e00.5301"
    assert firewall.label == "fw-a"
    assert {(r.device, r.evidence.source) for r in firewall.reported_by} == {
        ("dev-S1", EvidenceSource.CDP),
        ("dev-S1", EvidenceSource.LLDP),
        ("dev-S2", EvidenceSource.LLDP),
    }
    assert switch_30.id != switch_31.id  # same name, different addresses: two devices


def test_an_advertisement_of_a_visited_devices_address_is_folded_into_it() -> None:
    a = visited("192.0.2.1", "S1", cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", "192.0.2.66")])
    b = visited("192.0.2.2", "S2", "sw-b", aliases=["192.0.2.66"])
    tried_again = unvisited("192.0.2.66", UnvisitedReason.UNREACHABLE)

    built = topology.build([a, b, tried_again])

    assert built.unvisited == ()
    assert {end.device for end in built.links[0].ends} == {"dev-S1", "dev-S2"}


def test_an_advertisement_sharing_an_address_with_a_folded_one_is_folded_too() -> None:
    a = visited(
        "192.0.2.1",
        "S1",
        cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", "192.0.2.2", "198.51.100.2")],
        lldp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", "198.51.100.2")],
    )
    b = visited("192.0.2.2", "S2", "sw-b")

    assert topology.build([a, b]).unvisited == ()


def test_names_the_short_name_table_does_not_know_are_listed() -> None:
    record = visited(
        "192.0.2.1",
        "S1",
        interfaces=[port("Gi1/0/1"), port("WeirdPort7")],
        cdp=[neighbour("Gi1/0/1", "fw-a", "ae1", "192.0.2.9")],
    )

    built = topology.build([record])

    assert built.unknown_interface_names == (
        UnknownInterfaceName(device="dev-S1", reported="WeirdPort7"),
        UnknownInterfaceName(device=built.unvisited[0].id, reported="ae1"),
    )


def test_ids_do_not_depend_on_the_order_records_arrive_in() -> None:
    a = visited("192.0.2.1", "S1", cdp=[neighbour("Gi1/0/1", "fw-a", "eth1", "192.0.2.9")])
    b = visited("192.0.2.2", "S2", "sw-b", cdp=[neighbour("Gi1/0/2", "fw-a", "eth2", "192.0.2.9")])

    assert topology.build([a, b]) == topology.build([b, a])
