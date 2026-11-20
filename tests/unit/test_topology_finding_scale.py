"""v1's Finding kinds on the 0.2.0 scale (#93; stories 83-85).

Synthetic records in, a Topology out. Each v1 kind lands on its fixed level, Check identity,
advice and source, while v1's stable id, devices, items and evidence are unchanged.
"""

from dataclasses import replace

from network_analyser import topology
from network_analyser.records.collected import Interface, Neighbour, Reading, SwitchportMode, Vlan
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import (
    Check,
    CheckType,
    Finding,
    FindingKind,
    FindingLevel,
    Topology,
)
from network_analyser.records.unknown import Unknown
from tests.support.topology_records import neighbour, port, visited

A = "192.0.2.1"
B = "192.0.2.2"
SWITCHPORT = "show interfaces switchport"
VLAN_BRIEF = "show vlan brief"


def _db(*numbers: int) -> tuple[Vlan, ...]:
    return tuple(Vlan(number, f"vlan{number}", active=True) for number in numbers)


def _trunk(
    name: str,
    allowed: frozenset[int] | Unknown | None,
    native: int | Unknown | None,
    bundle: str | None = None,
) -> Interface:
    return replace(port(name, bundle=bundle), native_vlan=native, allowed_vlans=allowed)


def _access(name: str, vlan: int | Unknown | None) -> Interface:
    return replace(port(name, mode=SwitchportMode.ACCESS), access_vlan=vlan)


def _device(  # noqa: PLR0913, PLR0917 (a record's fields, by name)
    address: str,
    serial: str,
    hostname: str,
    interfaces: list[Interface],
    vlans: tuple[Vlan, ...],
    heard: list[Neighbour],
) -> DeviceRecord:
    record = visited(address, serial, hostname, cdp=heard, interfaces=interfaces)
    collected = record.collected
    assert collected is not None
    reading = collected.interfaces
    assert isinstance(reading, Reading)
    return replace(
        record,
        collected=replace(
            collected,
            interfaces=Reading((SWITCHPORT,), reading.value),
            vlans=Reading((VLAN_BRIEF,), vlans),
        ),
    )


def _vlan_pair(
    a_port: Interface, b_port: Interface, *, a_db: tuple[Vlan, ...], b_db: tuple[Vlan, ...]
) -> Topology:
    a = _device(A, "S1", "sw-a", [a_port], a_db, [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)])
    b = _device(B, "S2", "sw-b", [b_port], b_db, [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)])
    return topology.build([a, b])


def _only(built: Topology, kind: FindingKind) -> Finding:
    found = [finding for finding in built.findings if finding.kind is kind]
    assert len(found) == 1
    return found[0]


def test_vlan_on_one_end_only_is_low_and_soft() -> None:
    built = _vlan_pair(
        _trunk("Gi1/0/1", frozenset({10, 30}), 1),
        _trunk("Gi1/0/1", frozenset({10}), 1),
        a_db=_db(1, 10, 30),
        b_db=_db(1, 10),
    )

    finding = _only(built, FindingKind.VLAN_ON_ONE_END)

    assert finding.level is FindingLevel.LOW
    assert finding.check.id == "topology-vlan-on-one-end"
    assert finding.check.name == "VLAN on one end only"
    assert finding.check.type is CheckType.TOPOLOGY
    assert finding.check.soft is True  # drawn fainter and listed last in its Low group (story 85)
    assert finding.source == "config"
    assert "30 on sw-a Gi1/0/1 only" in finding.what_was_found
    assert finding.what_to_do == "Add the VLAN to the other end, or prune it from this end."
    assert finding.what_was_found == finding.summary


def test_differing_native_vlan_is_medium() -> None:
    built = _vlan_pair(
        _trunk("Gi1/0/1", frozenset({10}), 1),
        _trunk("Gi1/0/1", frozenset({10}), 99),
        a_db=_db(1, 10),
        b_db=_db(1, 10),
    )

    finding = _only(built, FindingKind.DIFFERING_NATIVE_VLAN)

    assert finding.level is FindingLevel.MEDIUM
    assert finding.check.id == "topology-differing-native-vlan"
    assert finding.check.type is CheckType.TOPOLOGY
    assert finding.check.soft is False
    assert finding.source == "config"
    assert finding.what_to_do == "Set the same native VLAN on both ends."


def test_trunk_facing_access_is_medium() -> None:
    built = _vlan_pair(
        _trunk("Gi1/0/1", frozenset({10, 20}), 1),
        _access("Gi1/0/1", 10),
        a_db=_db(1, 10, 20),
        b_db=_db(1, 10),
    )

    finding = _only(built, FindingKind.TRUNK_FACING_ACCESS)

    assert finding.level is FindingLevel.MEDIUM
    assert finding.check.id == "topology-trunk-facing-access"
    assert finding.source == "config"
    assert finding.what_to_do == "Make both ends a trunk, or both an access port."


def test_differing_access_vlans_is_medium() -> None:
    built = _vlan_pair(
        _access("Gi1/0/1", 10),
        _access("Gi1/0/1", 20),
        a_db=_db(10, 20),
        b_db=_db(10, 20),
    )

    finding = _only(built, FindingKind.DIFFERING_ACCESS_VLANS)

    assert finding.level is FindingLevel.MEDIUM
    assert finding.check.id == "topology-differing-access-vlans"
    assert finding.source == "config"
    assert finding.what_to_do == "Set the same access VLAN on both ends."


def test_conflicting_evidence_is_low() -> None:
    a = visited(A, "S1", cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/2", B)])
    b = visited(B, "S2", "sw-b", cdp=[neighbour("Gi1/0/2", "sw-a", "Gi1/0/5", A)])

    finding = _only(topology.build([a, b]), FindingKind.CONFLICTING_EVIDENCE)

    assert finding.level is FindingLevel.LOW
    assert finding.check.id == "topology-conflicting-evidence"
    assert finding.check.type is CheckType.TOPOLOGY
    assert finding.source == "device reports"
    assert finding.what_to_do == (
        "Check both reports for the port and correct the cabling or the report that disagrees."
    )


def test_bundle_member_mismatch_is_medium() -> None:
    a = visited(
        A,
        "S1",
        cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
        interfaces=[port("Gi1/0/1", bundle="Po10")],
    )
    b = visited(
        B,
        "S2",
        "sw-b",
        cdp=[neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
        interfaces=[port("Gi1/0/1")],
    )

    finding = _only(topology.build([a, b]), FindingKind.BUNDLE_MEMBER_MISMATCH)

    assert finding.level is FindingLevel.MEDIUM
    assert finding.check.id == "topology-bundle-member-mismatch"
    assert finding.source == "config"
    assert finding.what_to_do == (
        "Put the member Link in the same port-channel at both ends, or remove it from the Bundle."
    )


def test_the_v1_finding_keeps_its_stable_id_devices_items_and_evidence() -> None:
    built = _vlan_pair(
        _trunk("Gi1/0/1", frozenset({10, 30}), 1),
        _trunk("Gi1/0/1", frozenset({10}), 1),
        a_db=_db(1, 10, 30),
        b_db=_db(1, 10),
    )

    finding = _only(built, FindingKind.VLAN_ON_ONE_END)

    # The id the same scenario had before #93: the scale fields take no part in it.
    assert finding.id == "finding-4abfa1f8ccf7"
    assert finding.devices == ("dev-S1", "dev-S2")
    assert finding.items == (built.links[0].id,)
    assert finding.evidence


def test_the_levels_sort_critical_first_with_no_info_level() -> None:
    ordered = sorted(FindingLevel, key=lambda level: level.rank)

    assert [level.value for level in ordered] == ["Critical", "High", "Medium", "Low"]


def _made(ident: str, level: FindingLevel, check_id: str, *, soft: bool = False) -> Finding:
    return Finding(
        id=ident,
        devices=(),
        items=(),
        evidence=(),
        level=level,
        check=Check(check_id, check_id, CheckType.TOPOLOGY, soft=soft),
        what_was_found="something",
        what_to_do="fix it",
        source="config",
        summary="something",
    )


def test_a_soft_check_is_listed_last_within_its_level() -> None:
    conflict = _made("finding-000000000001", FindingLevel.LOW, "topology-conflicting-evidence")
    one_end = _made("finding-000000000002", FindingLevel.LOW, "topology-vlan-on-one-end", soft=True)
    native = _made("finding-000000000003", FindingLevel.MEDIUM, "topology-differing-native-vlan")

    ordered = sorted([one_end, native, conflict], key=lambda finding: finding.order)

    assert [finding.check.id for finding in ordered] == [
        "topology-differing-native-vlan",
        "topology-conflicting-evidence",
        "topology-vlan-on-one-end",
    ]
