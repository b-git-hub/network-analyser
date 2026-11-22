"""`render` reads `topology.json` alone: older versions read, newer refused (#63, story 155).

Synthetic Topology in, through the same `topology.build` and `to_document` a Run uses.
"""

import json
from typing import Any

import pytest

from network_analyser import diagram, topology
from network_analyser.diagram import topology_file
from network_analyser.records.collected import SwitchportMode
from network_analyser.records.device import UnvisitedReason
from tests.support.topology_records import neighbour, port, unvisited, visited

A = "192.0.2.1"
B = "192.0.2.2"
ROUTED = SwitchportMode.ROUTED


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

    assert read.format_version == 3
    content: Any = read.content
    devices = content["devices"]
    assert isinstance(devices, tuple)
    assert [d["id"] for d in devices] == ["dev-S1", "dev-S2"]
    assert content["links"][0]["status"] == "confirmed"


def test_a_format_version_1_file_from_an_older_run_is_still_read() -> None:
    document = _document()
    document["format_version"] = 1

    read = diagram.read_topology(_text(document))

    assert read.format_version == 1
    content: Any = read.content
    assert [d["id"] for d in content["devices"]] == ["dev-S1", "dev-S2"]


def test_a_newer_format_version_is_refused() -> None:
    document = _document()
    document["format_version"] = 4

    with pytest.raises(diagram.NewerFormatError):
        diagram.read_topology(_text(document))


def test_a_0_2_0_reader_refuses_a_format_version_3_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Story 113: an older `render` (which knew only versions 1 and 2) refuses a newer file."""
    monkeypatch.setattr(topology_file, "KNOWN_FORMAT_VERSION", 2)
    document = _document()

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


@pytest.mark.parametrize("depth", [10_000])
def test_a_deeply_nested_file_is_refused_rather_than_crashing(depth: int) -> None:
    """A file nested past Python's limit is a refusal (exit 2), never a `RecursionError`."""
    nested = "[" * depth + "]" * depth
    for text in (
        f'{{"format_version": 3, "devices": {nested}}}',
        f'{{"format_version": 3, "devices": [{{"id": "dev-S1", "model": {nested}}}]}}',
    ):
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


def _routed_pair() -> Any:  # noqa: ANN401 (JSON data)
    a = visited(A, "S1", interfaces=[port("Gi1/0/1", mode=ROUTED, ips=["192.0.2.9/30"])])
    b = visited(B, "S2", "sw-b", interfaces=[port("Gi1/0/1", mode=ROUTED, ips=["192.0.2.10/30"])])
    return json.loads(json.dumps(topology.to_document(topology.build([a, b]))))


def test_l3_adjacencies_subnets_and_skipped_checks_are_read_for_the_routing_view() -> None:
    content = _content(_routed_pair())

    (adjacency,) = content["adjacencies"]
    assert adjacency["kind"] == "shared subnet"
    assert adjacency["prefix"] == "192.0.2.8/30"
    assert [end["device"] for end in adjacency["ends"]] == ["dev-S1", "dev-S2"]
    assert adjacency["ends"][0]["interfaces"][0]["short"] == "Gi1/0/1"
    assert content["subnets"] == ()
    assert {row["data"] for row in content["skipped"]} >= {"vlans"}
    assert set(content["devices"][0]["vlan_database"]) == {"unknown"}


def test_a_file_from_before_l3_data_reads_its_routing_parts_as_unknown() -> None:
    document = _document()
    del document["adjacencies"]
    del document["subnets"]

    content = _content(document)

    assert set(content["adjacencies"]) == {"unknown"}
    assert set(content["subnets"]) == {"unknown"}


@pytest.mark.parametrize("part", ["adjacencies", "subnets"])
def test_an_l3_item_needs_a_plain_id(part: str) -> None:
    document = _document()
    document[part] = [{"id": "<b>"}]

    with pytest.raises(diagram.TopologyFileError):
        diagram.read_topology(_text(document))


def test_a_finding_from_before_the_scale_reads_its_new_fields_as_unknown() -> None:
    document = _document()
    document["findings"] = [
        {
            "id": "finding-0123456789ab",
            "kind": "conflicting evidence",
            "summary": "Reports disagree about Gi1/0/1",
            "devices": [],
            "items": [],
            "evidence": [],
        }
    ]

    (finding,) = _content(document)["findings"]

    assert finding["kind"] == "conflicting evidence"  # the v1 page still draws it
    assert finding["summary"] == "Reports disagree about Gi1/0/1"
    for field in (
        "level",
        "check",
        "what_was_found",
        "what_to_do",
        "source",
        "cisco_detail",
        "also_flagged_by_cisco",
    ):
        assert set(finding[field]) == {"unknown"}, field


def test_a_finding_s_level_and_check_are_read_for_drawing() -> None:
    document = _document()
    document["findings"] = [
        {
            "id": "finding-0123456789ab",
            "level": "Low",
            "check": {
                "id": "topology-vlan-on-one-end",
                "name": "VLAN on one end only",
                "type": "Topology",
                "soft": True,
            },
            "what_was_found": "VLAN 30 on sw-a Gi1/0/1 only",
            "what_to_do": "Add the VLAN to the other end, or prune it from this end.",
            "source": "config",
            "also_flagged_by_cisco": False,
        }
    ]

    (finding,) = _content(document)["findings"]

    assert finding["level"] == "Low"
    assert finding["check"]["id"] == "topology-vlan-on-one-end"
    assert finding["check"]["soft"] is True
    assert finding["what_was_found"] == "VLAN 30 on sw-a Gi1/0/1 only"
    assert finding["also_flagged_by_cisco"] is False


def test_an_advisory_cisco_detail_reads_its_discriminator() -> None:
    document = _document()
    document["findings"] = [
        {
            "id": "finding-0123456789ab",
            "cisco_detail": {
                "kind": "Advisory",
                "id": "cisco-sa-example-abc123",
                "title": "Example Advisory",
                "sir": "High",
                "cvss": "8.6",
                "cves": ["CVE-2099-0001"],
                "published": "2026-01-02T16:00:00",
                "updated": "2026-02-03T16:00:00",
                "first_fixed": "17.9.10",
                "status": "Affected release",
                "fixed_line": "Matched on software release only.",
                "hardware_family_not_confirmed": False,
            },
        }
    ]

    (finding,) = _content(document)["findings"]
    detail = finding["cisco_detail"]

    assert detail["kind"] == "Advisory"
    assert detail["id"] == "cisco-sa-example-abc123"
    assert detail["sir"] == "High"
    assert detail["status"] == "Affected release"
    assert set(detail["items"]) == {"unknown"}  # no EoX items on an Advisory


def test_an_eox_cisco_detail_reads_its_discriminator_and_item_kinds() -> None:
    document = _document()
    document["findings"] = [
        {
            "id": "finding-0123456789ab",
            "cisco_detail": {
                "kind": "EoX",
                "items": [
                    {"kind": "hardware", "name": "C9300-48P", "replacement": "C9300-48P"},
                    {"kind": "software", "name": "17.9.4"},
                ],
            },
        }
    ]

    (finding,) = _content(document)["findings"]
    detail = finding["cisco_detail"]

    assert detail["kind"] == "EoX"
    assert [item["kind"] for item in detail["items"]] == ["hardware", "software"]
    assert set(detail["id"]) == {"unknown"}  # no Advisory id on an EoX detail


def test_what_is_read_cannot_be_changed() -> None:
    content = _content(_document())

    with pytest.raises(TypeError):
        content["devices"][0]["id"] = "dev-other"


def test_cisco_lookups_are_read_when_the_file_records_them() -> None:
    document = _document()
    document["cisco_lookups"] = {"ran": True, "when": "2026-11-20T14:02:00+00:00"}

    lookups = diagram.cisco_lookups(diagram.read_topology(_text(document)))

    assert lookups.ran is True
    assert lookups.when == "2026-11-20T14:02:00+00:00"


@pytest.mark.parametrize(
    "recorded",
    [None, {}, {"ran": False, "when": None}, {"ran": "yes", "when": 7}],
)
def test_a_missing_or_unreadable_lookup_record_reads_as_did_not_run(recorded: object) -> None:
    document = _document()
    if recorded is not None:
        document["cisco_lookups"] = recorded

    lookups = diagram.cisco_lookups(diagram.read_topology(_text(document)))

    assert lookups.ran is False
    assert lookups.when is None


def test_a_device_s_advice_is_read_for_the_advisory_pane() -> None:
    document = _document()
    document["devices"][0]["advice"] = {
        "outcome": "1 Advisory matches",
        "upgrade_target": "17.12.8",
        "latest_release": "17.12.10",
        "latest_in_train": "17.12.10",
        "latest_release_lifecycle": "ED",
        "latest_in_train_lifecycle": "MD",
    }

    advice = diagram.device_advice(_content(document)["devices"][0])

    assert advice.known is True
    assert advice.outcome == "1 Advisory matches"
    assert (advice.upgrade_target, advice.target_recorded) == ("17.12.8", True)
    assert advice.latest_release == "17.12.10"
    assert advice.latest_in_train == "17.12.10"
    assert advice.latest_release_lifecycle == "ED"
    assert advice.latest_in_train_lifecycle == "MD"


def test_a_device_from_before_advice_reads_it_as_not_known() -> None:
    advice = diagram.device_advice(_content(_document())["devices"][0])

    assert advice.known is False
    assert (advice.outcome, advice.upgrade_target, advice.latest_release) == (None, None, None)


def test_a_null_upgrade_target_is_recorded_but_an_unknown_one_is_not() -> None:
    document = _document()
    document["devices"][0]["advice"] = {"outcome": "1 Advisory matches", "upgrade_target": None}
    document["devices"][1]["advice"] = {
        "outcome": "1 Advisory matches",
        "upgrade_target": {"unknown": "no source for the NX-OS Upgrade Target"},
    }

    first, second = _content(document)["devices"]

    assert diagram.device_advice(first).target_recorded is True
    assert diagram.device_advice(second).target_recorded is False


def test_a_missing_upgrade_target_is_not_read_as_a_null_one() -> None:
    document = _document()
    document["devices"][0]["advice"] = {"outcome": "1 Advisory matches"}

    advice = diagram.device_advice(_content(document)["devices"][0])

    assert (advice.upgrade_target, advice.target_recorded) == (None, False)


def test_a_null_advice_record_reads_as_not_known() -> None:
    document = _document()
    document["devices"][0]["advice"] = None

    assert diagram.device_advice(_content(document)["devices"][0]).known is False


def test_not_cleared_is_a_count_or_not_recorded_but_never_a_zero_guess() -> None:
    """A count the file does not hold is unknown, never 0: 0 claims a complete target (#146)."""
    recorded: dict[int, int | None] = {}

    for value in (0, 3):
        document = _document()
        document["format_version"] = 3
        document["devices"][0]["advice"] = {
            "outcome": "3 Advisories match",
            "upgrade_target": "17.12.8",
            "not_cleared": value,
        }
        recorded[value] = diagram.device_advice(_content(document)["devices"][0]).not_cleared

    assert recorded == {0: 0, 3: 3}

    invalid: tuple[object, ...] = (None, True, False, -2, 2.0, "3", [])
    for missing in invalid:
        document = _document()
        document["format_version"] = 3
        advice: dict[str, object] = {"outcome": "3 Advisories match", "upgrade_target": "17.12.8"}
        if missing is not None:
            advice["not_cleared"] = missing
        document["devices"][0]["advice"] = advice

        assert diagram.device_advice(_content(document)["devices"][0]).not_cleared is None, missing
