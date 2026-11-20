"""`topology.json`'s content: plain JSON data with a format version and no username (#52)."""

import json
from dataclasses import replace
from typing import Any

from network_analyser import topology
from network_analyser.records.collected import ALL_VLANS, Reading, SwitchportMode, Vlan
from network_analyser.records.topology import (
    AdvisoryDetail,
    Check,
    CheckType,
    Finding,
    FindingLevel,
)
from network_analyser.records.unknown import Unknown
from tests.support.topology_records import neighbour, port, visited

A = "192.0.2.1"
B = "192.0.2.2"


def _document() -> Any:  # noqa: ANN401 (JSON data, read by key in each test)
    trunk = port("Gi1/0/1")
    a = visited(
        A,
        "S1",
        cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
        interfaces=[trunk],
    )
    b = visited(B, "S2", "sw-b", cdp=[neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)])
    return json.loads(json.dumps(topology.to_document(topology.build([a, b]))))


def test_the_document_starts_with_a_single_integer_format_version() -> None:
    document = _document()

    assert next(iter(document)) == "format_version"
    assert document["format_version"] == topology.FORMAT_VERSION == 1


def test_the_document_is_plain_json_and_holds_no_username() -> None:
    text = json.dumps(_document())

    assert json.loads(text) == _document()
    assert "netops-ro" not in text


def test_records_become_objects_with_their_field_names() -> None:
    document = _document()

    first = document["devices"][0]
    assert first["id"] == "dev-S1"
    assert first["platform"] == "IOS/IOS-XE"
    assert first["outcome"] == "visited"
    assert first["management_ip"] == "192.0.2.1"
    assert first["interfaces"][0]["name"] == {
        "short": "Gi1/0/1",
        "reported": "Gi1/0/1",
        "known": True,
    }
    links = document["links"]
    assert links[0]["status"] == "confirmed"
    assert {e["source"] for e in links[0]["evidence"]} == {"CDP"}
    assert set(document) == {
        "format_version",
        "devices",
        "unvisited",
        "links",
        "segments",
        "bundles",
        "findings",
        "skipped",
        "unknown_interface_names",
        "adjacencies",
        "subnets",
        "unplaced_next_hops",
    }


def test_an_unknown_value_is_an_object_naming_its_reason_never_null() -> None:
    document = _document()

    assert document["devices"][1]["interfaces"] == {"unknown": "not collected in this test"}


def test_vlan_sets_are_written_as_ranges() -> None:
    trunk = replace(port("Gi1/0/1"), allowed_vlans=frozenset({1, 2, 3, 10, 20, 21}))
    every = replace(port("Gi1/0/2"), allowed_vlans=ALL_VLANS)
    access = replace(
        port("Gi1/0/3", mode=SwitchportMode.ACCESS),
        access_vlan=Unknown("show interfaces switchport: denied"),
    )
    record = visited(A, "S1", interfaces=[trunk, every, access])

    document: Any = topology.to_document(topology.build([record]))
    (device,) = document["devices"]

    interfaces = device["interfaces"]
    assert interfaces[0]["allowed_vlans"] == [[1, 3], [10, 10], [20, 21]]
    assert interfaces[1]["allowed_vlans"] == [[1, 4094]]
    assert interfaces[2]["mode"] == "access"
    assert interfaces[2]["access_vlan"] == {"unknown": "show interfaces switchport: denied"}


def _with_vlans(vlans: Reading[tuple[Vlan, ...]] | Unknown) -> Any:  # noqa: ANN401 (JSON data)
    record = visited(A, "S1")
    assert record.collected is not None
    record = replace(record, collected=replace(record.collected, vlans=vlans))
    document: Any = topology.to_document(topology.build([record]))
    return document["devices"][0]["vlan_database"]


def test_the_vlan_database_is_written_as_ranges_for_the_diagram_s_vlan_view() -> None:
    database = (Vlan(1, "default", active=True), Vlan(10, "users", active=True))
    shut = (Vlan(11, "spare", active=False),)

    written = _with_vlans(Reading(("show vlan brief",), database + shut))

    assert written == [[1, 1], [10, 11]]  # present counts, active or not (#61)


def test_a_vlan_database_not_collected_or_incomplete_is_unknown() -> None:
    partial = Reading(("show vlan brief",), (Vlan(1, "default", active=True),), (Unknown("x"),))

    assert _with_vlans(Unknown("show vlan brief: denied")) == {"unknown": "show vlan brief: denied"}
    assert _with_vlans(partial) == {"unknown": "the VLAN database is incomplete"}


def _vlan_finding_document() -> Any:  # noqa: ANN401 (JSON data, read by key)
    a = visited(
        A,
        "S1",
        cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
        interfaces=[replace(port("Gi1/0/1"), native_vlan=1, allowed_vlans=frozenset({10}))],
    )
    b = visited(
        B,
        "S2",
        "sw-b",
        cdp=[neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
        interfaces=[replace(port("Gi1/0/1"), native_vlan=99, allowed_vlans=frozenset({10}))],
    )
    return json.loads(json.dumps(topology.to_document(topology.build([a, b]))))


def test_a_finding_carries_its_level_check_advice_and_source() -> None:
    document = _vlan_finding_document()

    (finding,) = document["findings"]
    assert finding["level"] == "Medium"
    assert finding["check"] == {
        "id": "topology-differing-native-vlan",
        "name": "Differing native VLAN",
        "type": "Topology",
        "soft": False,
    }
    assert finding["what_was_found"] == finding["summary"]
    assert finding["what_to_do"] == "Set the same native VLAN on both ends."
    assert finding["source"] == "config"
    assert finding["cisco_detail"] is None
    assert finding["also_flagged_by_cisco"] is False
    assert document["format_version"] == 1  # an older render drops keys it does not know


def test_an_advisory_detail_is_written_as_its_own_object() -> None:
    detail = AdvisoryDetail(
        id="cisco-sa-example-abc123",
        title="Cisco IOS XE Software Example Vulnerability",
        sir="High",
        cvss="8.6",
        cves=("CVE-2099-0001",),
        published="2026-01-02T16:00:00",
        updated="2026-02-03T16:00:00",
        first_fixed="17.9.10",
        hardware_family_not_confirmed=True,
    )
    finding = Finding(
        id="finding-0123456789ab",
        devices=("dev-S1",),
        items=(),
        evidence=(),
        level=FindingLevel.HIGH,
        check=Check("advisory-cisco-sa-example-abc123", "Example Advisory", CheckType.ADVISORY),
        what_was_found="Affected release 17.9.4",
        what_to_do="Upgrade to 17.9.10 or later.",
        source="Cisco openVuln",
        summary="Affected release 17.9.4",
        cisco_detail=detail,
        also_flagged_by_cisco=True,
    )

    document: Any = topology.to_document(replace(topology.build(()), findings=(finding,)))

    (written,) = document["findings"]
    assert written["cisco_detail"] == {
        "id": "cisco-sa-example-abc123",
        "title": "Cisco IOS XE Software Example Vulnerability",
        "sir": "High",
        "cvss": "8.6",
        "cves": ["CVE-2099-0001"],
        "published": "2026-01-02T16:00:00",
        "updated": "2026-02-03T16:00:00",
        "first_fixed": "17.9.10",
        "hardware_family_not_confirmed": True,
    }
    assert written["also_flagged_by_cisco"] is True
    assert written["kind"] is None
    assert written["summary"] == "Affected release 17.9.4"
