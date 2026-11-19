"""`render` reads `topology.json` alone: older versions read, newer refused (#63, story 155).

Synthetic Topology in, through the same `topology.build` and `to_document` a Run uses.
"""

import json
from typing import Any

import pytest

from network_analyser import diagram, topology
from network_analyser.records.device import UnvisitedReason
from tests.support.topology_records import neighbour, port, unvisited, visited

A = "192.0.2.1"
B = "192.0.2.2"


def _document() -> Any:  # noqa: ANN401 (JSON data, changed by key in each test)
    a = visited(
        A,
        "S1",
        cdp=[
            neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B),
            neighbour("Gi1/0/2", "ap-1", "Gi0", "198.51.100.7", platform="cisco AIR"),
        ],
        interfaces=[port("Gi1/0/1")],
    )
    b = visited(B, "S2", "sw-b", cdp=[neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)])
    gone = unvisited("198.51.100.7", UnvisitedReason.OUTSIDE_SCOPE)
    return json.loads(json.dumps(topology.to_document(topology.build([a, b, gone]))))


def _text(document: object) -> str:
    return json.dumps(document)


def _content(document: object) -> Any:  # noqa: ANN401 (read-only JSON data, read by key)
    return diagram.read_topology(_text(document)).content


def test_a_run_s_topology_json_is_read() -> None:
    read = diagram.read_topology(_text(_document()))

    assert read.format_version == 1
    content: Any = read.content
    devices = content["devices"]
    assert isinstance(devices, tuple)
    assert [d["id"] for d in devices] == ["dev-S1", "dev-S2"]
    assert content["links"][0]["status"] == "confirmed"


def test_a_newer_format_version_is_refused() -> None:
    document = _document()
    document["format_version"] = 2

    with pytest.raises(diagram.NewerFormatError):
        diagram.read_topology(_text(document))


@pytest.mark.parametrize("version", [0, -1, "1", True, None, 1.0])
def test_a_format_version_that_never_existed_is_refused(version: object) -> None:
    document = _document()
    document["format_version"] = version

    with pytest.raises(diagram.TopologyFileError):
        diagram.read_topology(_text(document))


@pytest.mark.parametrize("text", ["", "not json", "[]", '{"devices": []}', "NaN"])
def test_text_that_is_not_a_topology_file_is_refused(text: str) -> None:
    with pytest.raises(diagram.TopologyFileError):
        diagram.read_topology(text)


def test_the_refusal_never_quotes_the_file() -> None:
    with pytest.raises(diagram.TopologyFileError) as refused:
        diagram.read_topology('{"format_version": 1, "devices": "CANARY-pw-7f3a"}')

    assert "CANARY" not in str(refused.value)


def test_fields_it_does_not_know_are_ignored() -> None:
    document = _document()
    document["subnets_from_a_later_version"] = [{"id": "x"}]
    document["devices"][0]["colour"] = "teal"

    content = _content(document)

    assert "subnets_from_a_later_version" not in content
    assert "colour" not in content["devices"][0]


def test_unknown_stays_unknown_and_a_missing_field_reads_as_unknown() -> None:
    document = _document()
    document["devices"][0]["model"] = {"unknown": "show version refused"}
    del document["devices"][1]["model"]

    first, second = _content(document)["devices"]
    assert first["model"] == {"unknown": "show version refused"}
    assert set(second["model"]) == {"unknown"}


@pytest.mark.parametrize("bad_id", ["dev S1", "<b>", "", 7, None])
def test_an_id_that_is_not_a_plain_id_is_refused(bad_id: object) -> None:
    document = _document()
    document["devices"][0]["id"] = bad_id

    with pytest.raises(diagram.TopologyFileError):
        diagram.read_topology(_text(document))


def test_a_list_where_a_record_belongs_is_refused() -> None:
    document = _document()
    document["links"][0]["ends"] = "sw-a"

    with pytest.raises(diagram.TopologyFileError):
        diagram.read_topology(_text(document))


def test_what_is_read_cannot_be_changed() -> None:
    content = _content(_document())

    with pytest.raises(TypeError):
        content["devices"][0]["id"] = "dev-other"
