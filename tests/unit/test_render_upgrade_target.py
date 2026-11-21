"""The Upgrade Target at Seam 3: `topology.json` in, every rendered surface out (#124).

Synthetic `topology.json` documents in, pages and marker models out. The partial target and the
count of Advisories it leaves open must read the same on the Findings report, the Map tag, its
legend and the Advisory detail pane. `format_version` is bumped, so an older `render` refuses
the file. Every name and address is synthetic (RFC 5737 addresses, hostnames like `sw-a`).
"""

import json
from dataclasses import replace
from typing import Any

import pytest

from network_analyser import diagram, topology
from network_analyser.diagram import topology_file
from network_analyser.diagram.findings import findings_tab
from network_analyser.diagram.topology_file import device_advice
from network_analyser.records.topology import (
    AdvisoryOutcome,
    AdvisoryOutcomeKind,
    AnalysisSummary,
    DeviceAdvice,
)
from tests.support.topology_documents import device, document, read
from tests.support.topology_records import visited

RUN_TIME = "2026-11-21 09:30:00Z"
ADVISORY_ID = "cisco-sa-example-abc123"
HOSTILE = "</script><img src=x onerror=alert(1)>"


def _advised(ident: str, hostname: str, address: str, **advice: object) -> Any:  # noqa: ANN401
    fields: dict[str, object] = {
        "outcome": "3 Advisories match",
        "upgrade_target": "17.12.8",
        "latest_release": "17.12.10",
        "latest_in_train": "17.12.10",
        "train": "17.12",
        "not_cleared": 1,
    }
    fields.update(advice)
    return device(ident, hostname, address, software_version="17.12.4", advice=fields)


def _advisory_finding(device_id: str = "dev-S1") -> dict[str, object]:
    return {
        "id": "finding-0123456789ab",
        "devices": [device_id],
        "items": [],
        "evidence": [],
        "level": "High",
        "check": {
            "id": f"advisory-{ADVISORY_ID}",
            "name": "Example Advisory",
            "type": "Advisory",
            "soft": False,
        },
        "what_was_found": "Affected release 17.12.4",
        "what_to_do": "Upgrade the device.",
        "source": "Cisco openVuln",
        "summary": "An Advisory affects release 17.12.4.",
        "cisco_detail": {
            "kind": "Advisory",
            "id": ADVISORY_ID,
            "title": "Cisco IOS XE Software Example Vulnerability",
            "sir": "High",
            "cvss": "8.1",
            "cves": ["CVE-2099-0001"],
            "published": "2026-01-02",
            "updated": "2026-02-03",
            "first_fixed": "17.12.8",
            "status": "Affected release",
            "fixed_line": "Matched on software release only.",
        },
    }


def _partial_document(**advice: object) -> Any:  # noqa: ANN401
    made = document(
        [_advised("dev-S1", "sw-a", "192.0.2.1", **advice)],
        findings=[_advisory_finding()],
    )
    made["format_version"] = topology.FORMAT_VERSION
    return made


def _page(data: object) -> str:
    return diagram.draw_findings_report(read(data), lambda text: text, run_time=RUN_TIME)


def _marker(data: object) -> Any:  # noqa: ANN401
    markers = diagram.map_markers(read(data))
    (marker,) = markers.devices
    return markers, marker


def test_the_findings_report_callout_names_the_partial_target_and_what_it_leaves_open() -> None:
    page = _page(_partial_document())

    assert (
        "Upgrade to 17.12.8 or later (does not clear 1 Advisories: no fix in Train 17.12)" in page
    )


def test_a_target_that_clears_every_advisory_carries_no_partial_note() -> None:
    page = _page(_partial_document(not_cleared=0))

    assert "Upgrade to 17.12.8 or later" in page
    assert "does not clear" not in page


def test_the_map_tag_adds_no_fix_in_train_when_the_target_leaves_advisories_open() -> None:
    markers, marker = _marker(_partial_document())

    assert (marker.tag, marker.tag_kind) == ("\u2191 17.12.8 (no fix in Train)", "target")
    assert "(no fix in Train)" in markers.legend.target_partial
    assert "does not clear" in markers.legend.target_partial


def test_the_map_tag_is_plain_for_a_complete_target() -> None:
    _markers, marker = _marker(_partial_document(not_cleared=0))

    assert (marker.tag, marker.tag_kind) == ("\u2191 17.12.8", "target")


def test_the_advisory_detail_pane_shows_the_not_cleared_count() -> None:
    tab = findings_tab(read(_partial_document()))
    (high,) = [group for group in tab.levels if group.level == "High"]
    (advisory,) = high.checks
    assert advisory.advisory is not None
    (row,) = advisory.advisory.devices
    assert row.not_cleared == 1

    page = diagram.draw_html(read(_partial_document()), lambda text: text)
    assert "Not cleared" in page


def test_a_hostile_partial_target_is_escaped_on_every_surface() -> None:
    data = _partial_document(upgrade_target=HOSTILE)

    page = _page(data)
    assert "<img" not in page
    assert "&lt;/script&gt;" in page

    _markers, marker = _marker(data)
    assert marker.tag is not None
    assert "no fix in Train" in marker.tag


def test_topology_json_carries_each_devices_advice_and_the_new_count() -> None:
    built = topology.build((visited("192.0.2.1", "S1", "sw-a"),))
    advice = DeviceAdvice(
        device="dev-S1",
        advisory_outcome=AdvisoryOutcome(
            AdvisoryOutcomeKind.MATCHES,
            matched=3,
            release="17.12.4",
        ),
        upgrade_target="17.12.8",
        latest_release_in_train="17.12.10",
        latest_release="17.15.1",
        train="17.12",
        not_cleared=1,
    )
    built = replace(built, analysis=AnalysisSummary(advice=(advice,), checks=()))

    written: Any = topology.to_document(built)
    record = written["devices"][0]["advice"]

    assert written["format_version"] == topology.FORMAT_VERSION == 3
    assert record == {
        "outcome": "3 Advisories match",
        "upgrade_target": "17.12.8",
        "latest_release": "17.15.1",
        "latest_in_train": "17.12.10",
        "train": "17.12",
        "not_cleared": 1,
    }
    read_back = diagram.read_topology(json.dumps(written))
    content: Any = read_back.content
    assert device_advice(content["devices"][0]).not_cleared == 1


def test_the_format_version_is_bumped_for_the_partial_target() -> None:
    assert diagram.KNOWN_FORMAT_VERSION == topology.FORMAT_VERSION == 3


def test_a_newer_render_refuses_the_bumped_file() -> None:
    fore = _partial_document()
    fore["format_version"] = 4

    with pytest.raises(diagram.NewerFormatError):
        diagram.read_topology(json.dumps(fore))


def test_an_older_render_refuses_the_bumped_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(topology_file, "KNOWN_FORMAT_VERSION", 2)

    with pytest.raises(diagram.NewerFormatError):
        diagram.read_topology(json.dumps(_partial_document()))


def test_a_format_version_2_file_is_still_read() -> None:
    old = document([device("dev-S1", "sw-a")])
    old["format_version"] = 2

    assert diagram.read_topology(json.dumps(old)).format_version == 2
