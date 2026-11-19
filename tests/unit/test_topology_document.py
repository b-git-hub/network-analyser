"""`topology.json`'s content: plain JSON data with a format version and no username (#52)."""

import json
from typing import Any

from network_analyser import topology
from network_analyser.records.collected import ALL_VLANS, SwitchportMode
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
    }


def test_an_unknown_value_is_an_object_naming_its_reason_never_null() -> None:
    document = _document()

    assert document["devices"][1]["interfaces"] == {"unknown": "not collected in this test"}


def test_vlan_sets_are_written_as_ranges() -> None:
    from dataclasses import replace  # noqa: PLC0415 (only here)

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
