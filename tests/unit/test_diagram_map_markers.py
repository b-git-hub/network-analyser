"""The Map's markers: a count badge and an Upgrade Target tag (#109, stories 96-98).

The page's own JavaScript draws the Map markers from the data block. These tests read that
model back out of the block through the public `draw_html` entry point, and check the page
and the script around it; how the drawing looks is checked by hand in a browser.
"""

import base64
import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from network_analyser import diagram
from network_analyser.cli import ExitCode, main
from tests.support.topology_documents import device, document, link, read

HOSTILE = "</script><img src=x onerror=alert(1)>\"'&\u2028"
DATA_OPEN = '<script type="application/json" id="topology-data">'
BADGE_LEGEND = "Badge = number of Findings on the device, coloured by its worst level"
TARGET_LEGEND = "\u2191 17.12.8 = the Upgrade Target to move to"
TARGET_PARTIAL_LEGEND = (
    "\u2191 17.12.8 (no fix in Train) = the target still does not clear every Advisory"
)
NO_FIX_LEGEND = "no fix in Train = no release in its Train clears its Advisories"
COULD_NOT_CHECK_LEGEND = "? could not check = its Advisories could not be checked"


def _page(data: object, redact: Callable[[str], str] = lambda text: text) -> str:
    return diagram.draw_html(read(data), redact)


def _data(page: str) -> Any:  # noqa: ANN401 (JSON data, read by key)
    start = page.index(DATA_OPEN) + len(DATA_OPEN)
    return json.loads(page[start : page.index("</script>", start)])


def _markers(data: object) -> Any:  # noqa: ANN401 (the model, read by key)
    return _data(_page(data))["markers"]


def _marker(data: object, ident: str) -> Any:  # noqa: ANN401 (the model, read by key)
    return next(marker for marker in _markers(data)["devices"] if marker["device"] == ident)


def _script(page: str) -> str:
    found = re.search(r"<script>(.*?)</script>", page, re.DOTALL)
    assert found is not None
    return found.group(1)


def _finding(ident: str, level: str, *devices: str) -> dict[str, object]:
    return {
        "id": ident,
        "devices": list(devices),
        "items": [],
        "evidence": [],
        "level": level,
        "check": {"id": f"check-{level.lower()}", "name": "A Check", "type": "Configuration"},
        "what_was_found": "what was found",
        "what_to_do": "what to do",
        "source": "config",
        "summary": "what was found",
        "kind": None,
    }


def _advised(ident: str, hostname: str, address: str = "192.0.2.1", /, **advice: object) -> Any:  # noqa: ANN401
    return device(ident, hostname, address, software_version="17.12.4", advice=advice)


def _switches() -> object:
    return document(
        [
            _advised("dev-S1", "sw-a"),
            _advised("dev-S2", "sw-b", "192.0.2.2"),
            _advised("dev-S3", "sw-c", "192.0.2.3"),
        ],
        [
            link("link-1", "dev-S1", "Gi1/0/1", "dev-S2", "Gi1/0/1"),
            link("link-2", "dev-S2", "Gi1/0/2", "dev-S3", "Gi1/0/2"),
        ],
    )


def test_a_badge_counts_a_device_s_findings_and_takes_its_worst_level() -> None:
    data = _switches()
    data["findings"] = [  # type: ignore[index]
        _finding("finding-1", "Medium", "dev-S1"),
        _finding("finding-2", "Critical", "dev-S1"),
        _finding("finding-3", "Low", "dev-S2"),
        _finding("finding-4", "Low", "dev-S1", "dev-S2"),
    ]

    assert [(m["device"], m["count"], m["level"]) for m in _markers(data)["devices"]] == [
        ("dev-S1", 3, "Critical"),
        ("dev-S2", 2, "Low"),
        ("dev-S3", 0, ""),
    ]


def test_the_badge_colour_follows_the_device_s_worst_level() -> None:
    data = _switches()
    data["findings"] = [  # type: ignore[index]
        _finding("finding-1", "Low", "dev-S1"),
        _finding("finding-2", "High", "dev-S1"),
    ]

    page = _page(data)

    assert _marker(data, "dev-S1")["level"] == "High"
    assert "levelClass(m.level)" in _script(page)
    for level in ("critical", "high", "medium", "low"):
        assert f".marker.count.{level} rect" in page


def test_a_device_with_no_findings_gets_no_badge() -> None:
    data = _switches()
    data["findings"] = [_finding("finding-1", "High", "dev-S1")]  # type: ignore[index]

    clean = _marker(data, "dev-S3")

    assert (clean["count"], clean["level"]) == (0, "")
    assert "count > 0" in _script(_page(data))  # a badge is drawn only for a positive count


def test_a_finding_from_before_the_scale_does_not_count_towards_a_badge() -> None:
    data = _switches()
    data["findings"] = [  # type: ignore[index]
        {
            "id": "finding-0123456789ab",
            "kind": "conflicting evidence",
            "summary": "Reports disagree about Gi1/0/1",
            "devices": ["dev-S1"],
            "items": [],
            "evidence": [],
        }
    ]

    assert _marker(data, "dev-S1")["count"] == 0


@pytest.mark.parametrize(
    ("advice", "tag", "kind"),
    [
        (
            {"outcome": "1 Advisory matches", "upgrade_target": "17.12.8", "not_cleared": 0},
            "\u2191 17.12.8",
            "target",
        ),
        (
            {
                "outcome": "3 Advisories match",
                "upgrade_target": "17.12.8",
                "not_cleared": 1,
            },
            "\u2191 17.12.8 (no fix in Train)",
            "target-partial",
        ),
        (
            {"outcome": "3 Advisories match", "upgrade_target": "17.12.8"},
            "\u2191 17.12.8 (count not recorded)",
            "target-partial",
        ),
        (
            {
                "outcome": "3 Advisories match",
                "upgrade_target": "17.12.8",
                "not_cleared": True,
            },
            "\u2191 17.12.8 (count not recorded)",
            "target-partial",
        ),
        (
            {"outcome": "2 Advisories match", "upgrade_target": None, "not_cleared": 2},
            "no fix in Train",
            "no-fix",
        ),
        (
            {"outcome": "could not check: show version was not read", "upgrade_target": None},
            "? could not check",
            "could-not-check",
        ),
        (
            {
                "outcome": "no known Critical/High Advisories for release 17.12.4",
                "upgrade_target": None,
            },
            None,
            "",
        ),
        (
            {"outcome": "no Critical/High Advisories", "upgrade_target": None},
            None,
            "",
        ),
        (
            {
                "outcome": "1 Advisory matches",
                "upgrade_target": "no fix in Train 17.9",
            },
            "no fix in Train",
            "no-fix",
        ),
        (
            {"outcome": "1 Advisory matches", "upgrade_target": "not available"},
            None,
            "",
        ),
        (
            {
                "outcome": "no Critical/High Advisories",
                "upgrade_target": "no Critical/High Advisories",
            },
            None,
            "",
        ),
        ({"outcome": "1 Advisory matches"}, None, ""),
    ],
)
def test_a_device_s_tag_shows_its_upgrade_path(
    advice: dict[str, object], tag: str | None, kind: str
) -> None:
    data = document([_advised("dev-S1", "sw-a", **advice)])

    marker = _marker(data, "dev-S1")

    assert (marker["tag"], marker["tag_kind"]) == (tag, kind)


def test_a_partial_target_carries_its_gap_as_a_second_line_in_the_warn_colour() -> None:
    data = document(
        [
            _advised(
                "dev-S1",
                "sw-a",
                outcome="3 Advisories match",
                upgrade_target="15.2(7)E10",
                not_cleared=1,
            )
        ]
    )

    marker = _marker(data, "dev-S1")
    page = _page(data)
    script = _script(page)

    assert marker["tag"] == "\u2191 15.2(7)E10 (no fix in Train)"
    assert marker["tag_kind"] == "target-partial"
    assert marker["tag_note"] == "(no fix in Train)"
    assert "short(tag" not in script  # the gap is never truncated away
    assert "tag_note" in script
    assert ".marker.tag.target-partial{color:var(--warn)}" in page
    assert ".marker-key.target-partial{color:var(--warn)}" in page
    assert "marker-key target-partial" in script  # the legend uses the warn key


def test_a_complete_target_carries_no_second_line() -> None:
    data = document(
        [
            _advised(
                "dev-S1",
                "sw-a",
                outcome="1 Advisory matches",
                upgrade_target="17.12.8",
                not_cleared=0,
            )
        ]
    )

    marker = _marker(data, "dev-S1")

    assert (marker["tag"], marker["tag_kind"], marker["tag_note"]) == (
        "\u2191 17.12.8",
        "target",
        None,
    )


def test_a_device_with_no_advice_gets_no_tag() -> None:
    data = document([device("dev-S1", "sw-a")])

    marker = _marker(data, "dev-S1")

    assert (marker["tag"], marker["tag_kind"]) == (None, "")


def test_an_upgrade_target_the_file_does_not_hold_is_not_guessed() -> None:
    data = _switches()
    data["devices"][0]["advice"] = {  # type: ignore[index]
        "outcome": "1 Advisory matches",
        "upgrade_target": {"unknown": "no source for the NX-OS Upgrade Target"},
    }

    marker = _marker(data, "dev-S1")

    assert (marker["tag"], marker["tag_kind"]) == (None, "")


def test_the_legend_explains_the_badge_and_every_tag() -> None:
    legend = _markers(_switches())["legend"]

    assert legend["badge"] == BADGE_LEGEND
    assert legend["levels"] == ["Critical", "High", "Medium", "Low"]
    assert legend["target"] == TARGET_LEGEND
    assert legend["target_partial"] == TARGET_PARTIAL_LEGEND
    assert legend["no_fix"] == NO_FIX_LEGEND
    assert legend["could_not_check"] == COULD_NOT_CHECK_LEGEND
    assert "markerLegend" in _script(_page(_switches()))


def test_hostile_device_and_advice_text_never_reaches_the_page_as_markup() -> None:
    data = document(
        [
            _advised(
                "dev-S1",
                HOSTILE,
                outcome=HOSTILE,
                upgrade_target=HOSTILE,
                latest_release=HOSTILE,
                not_cleared=0,
            )
        ],
        findings=[_finding("finding-1", "High", "dev-S1")],
    )

    page = _page(data)

    assert "<img" not in page
    assert page.count("</script>") == 2
    assert _marker(data, "dev-S1")["tag"] == "\u2191 " + HOSTILE


def test_the_markers_need_no_script_from_outside_and_make_no_request() -> None:
    page = _page(_switches())
    script = _script(page)

    for call in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "import("):
        assert call not in script
    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page)
    assert policy is not None
    assert "default-src 'none'" in policy.group(1)
    assert f"script-src 'sha256-{_digest(script)}'" in policy.group(1)


def test_badges_and_tags_do_not_move_any_device() -> None:
    quiet = _switches()
    marked = _switches()
    marked["findings"] = [_finding("finding-1", "Critical", "dev-S1")]  # type: ignore[index]
    marked["devices"][0]["advice"] = {  # type: ignore[index]
        "outcome": "1 Advisory matches",
        "upgrade_target": "17.12.8",
    }

    assert _data(_page(quiet))["layout"]["positions"] == _data(_page(marked))["layout"]["positions"]


def test_render_redraws_the_markers_from_topology_json(tmp_path: Path) -> None:
    data = _switches()
    data["devices"][0]["hostname"] = HOSTILE  # type: ignore[index]
    data["findings"] = [_finding("finding-1", "Critical", "dev-S1")]  # type: ignore[index]
    data["devices"][0]["advice"] = {  # type: ignore[index]
        "outcome": "1 Advisory matches",
        "upgrade_target": "17.12.8",
        "not_cleared": 0,
    }
    data["devices"][1]["advice"] = {  # type: ignore[index]
        "outcome": "2 Advisories match",
        "upgrade_target": None,
    }
    data["devices"][2]["advice"] = {  # type: ignore[index]
        "outcome": "could not check: show version was not read",
        "upgrade_target": None,
    }
    (tmp_path / "topology.json").write_text(json.dumps(data), encoding="utf-8")

    assert main(["render", str(tmp_path)], elevated=lambda: False) == ExitCode.CLEAN

    page = (tmp_path / "diagram.html").read_text(encoding="utf-8")
    markers = _data(page)["markers"]
    assert [(m["device"], m["count"], m["level"], m["tag"]) for m in markers["devices"]] == [
        ("dev-S1", 1, "Critical", "\u2191 17.12.8"),
        ("dev-S2", 0, "", "no fix in Train"),
        ("dev-S3", 0, "", "? could not check"),
    ]
    assert markers["legend"]["badge"] == BADGE_LEGEND
    assert markers["legend"]["target"] == TARGET_LEGEND
    assert markers["legend"]["no_fix"] == NO_FIX_LEGEND
    assert markers["legend"]["could_not_check"] == COULD_NOT_CHECK_LEGEND
    for level in ("critical", "high", "medium", "low"):
        assert f".marker.count.{level} rect" in page
    assert "<img" not in page
    script = _script(page)
    assert page.count("</script>") == 2
    assert "default-src 'none'" in page
    assert f"script-src 'sha256-{_digest(script)}'" in page
    for call in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "import("):
        assert call not in script


def test_render_keeps_every_device_in_place_when_it_adds_markers(tmp_path: Path) -> None:
    quiet, marked = tmp_path / "quiet", tmp_path / "marked"
    quiet.mkdir()
    marked.mkdir()
    data = _switches()
    (quiet / "topology.json").write_text(json.dumps(data), encoding="utf-8")
    data["findings"] = [_finding("finding-1", "Critical", "dev-S1")]  # type: ignore[index]
    data["devices"][0]["advice"] = {  # type: ignore[index]
        "outcome": "1 Advisory matches",
        "upgrade_target": "17.12.8",
    }
    (marked / "topology.json").write_text(json.dumps(data), encoding="utf-8")

    for folder in (quiet, marked):
        assert main(["render", str(folder)], elevated=lambda: False) == ExitCode.CLEAN

    positions = [
        _data((folder / "diagram.html").read_text(encoding="utf-8"))["layout"]["positions"]
        for folder in (quiet, marked)
    ]
    assert positions[0] == positions[1]


def test_markers_are_drawn_on_the_map_only() -> None:
    script = _script(_page(_switches()))

    assert "function nodeMarkers" in script
    assert "S.tab === 'map' &&" in script


def _digest(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")
