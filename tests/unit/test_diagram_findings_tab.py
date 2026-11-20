"""The Findings tab: by level, then one row per Check (#108, stories 86-95).

The page's own JavaScript draws the tab from the data block. These tests read the model back
out of that block through the public `draw_html` entry point, and check the page and the
script around it; how the drawing looks is checked by hand in a browser.
"""

import json
import re
from collections.abc import Callable
from typing import Any

from network_analyser import diagram
from tests.support.topology_documents import (
    device,
    document,
    link,
    read,
    unvisited_device,
)

HOSTILE = "</script><img src=x onerror=alert(1)>\"'&\u2028"
DATA_OPEN = '<script type="application/json" id="topology-data">'
FIXED = (
    "Matched on software release only. Cisco may limit this Advisory to devices that use a "
    "particular feature; see 'Vulnerable Products' on Cisco's page."
)
ADVISORY_ID = "cisco-sa-example-abc123"


def _page(data: object, redact: Callable[[str], str] = lambda text: text) -> str:
    return diagram.draw_html(read(data), redact)


def _data(page: str) -> Any:  # noqa: ANN401 (JSON data, read by key)
    start = page.index(DATA_OPEN) + len(DATA_OPEN)
    return json.loads(page[start : page.index("</script>", start)])


def _tab(data: object) -> Any:  # noqa: ANN401 (the model, read by key)
    return _data(_page(data))["findings"]


def _script(page: str) -> str:
    found = re.search(r"<script>(.*?)</script>", page, re.DOTALL)
    assert found is not None
    return found.group(1)


def _finding(  # noqa: PLR0913 (each field of a Finding, by name)
    ident: str,
    level: str,
    check_id: str,
    check_name: str,
    check_type: str,
    *,
    devices: tuple[str, ...] = (),
    items: tuple[str, ...] = (),
    what_was_found: str = "what was found",
    what_to_do: str = "what to do",
    source: str = "config",
    soft: bool = False,
    cisco_detail: object = None,
) -> dict[str, object]:
    return {
        "id": ident,
        "devices": list(devices),
        "items": list(items),
        "evidence": [],
        "level": level,
        "check": {"id": check_id, "name": check_name, "type": check_type, "soft": soft},
        "what_was_found": what_was_found,
        "what_to_do": what_to_do,
        "source": source,
        "summary": what_was_found,
        "kind": None,
        "cisco_detail": cisco_detail,
        "also_flagged_by_cisco": False,
    }


def _advisory_detail(  # noqa: PLR0913, PLR0917 (each field of Cisco's detail, by name)
    ident: str = ADVISORY_ID,
    title: str = "Cisco IOS XE Software Example Vulnerability",
    sir: str = "High",
    cves: tuple[str, ...] = ("CVE-2099-0001", "CVE-2099-0002"),
    published: str = "2026-01-02",
    updated: str = "2026-02-03",
) -> dict[str, object]:
    return {
        "id": ident,
        "title": title,
        "sir": sir,
        "cvss": "8.6",
        "cves": list(cves),
        "published": published,
        "updated": updated,
        "first_fixed": "17.12.8",
        "hardware_family_not_confirmed": False,
    }


def _advised(ident: str, hostname: str, address: str, **advice: object) -> Any:  # noqa: ANN401
    return device(
        ident,
        hostname,
        address,
        software_version="17.12.4",
        advice={
            "outcome": "1 Advisory matches",
            "upgrade_target": "17.12.8",
            "latest_release": "17.12.10",
            "latest_in_train": "17.12.10",
            **advice,
        },
    )


def _topology() -> object:
    return document(
        [
            _advised("dev-S1", "sw-a", "192.0.2.1"),
            _advised("dev-S2", "sw-b", "192.0.2.2"),
            _advised("dev-S3", "sw-c", "192.0.2.3"),
        ],
        [
            link("link-1", "dev-S1", "Gi1/0/1", "dev-S2", "Gi1/0/1"),
            link("link-2", "dev-S2", "Gi1/0/2", "dev-S3", "Gi1/0/2"),
        ],
    )


def _levels_of_findings() -> object:
    data = _topology()
    data["findings"] = [  # type: ignore[index]
        _finding(
            "finding-adv-high",
            "High",
            ADVISORY_ID,
            "Cisco IOS XE Software Example Vulnerability",
            "Advisory",
            devices=("dev-S1", "dev-S2"),
            cisco_detail=_advisory_detail(),
        ),
        _finding(
            "finding-cfg-critical",
            "Critical",
            "cfg-snmpv2c-default-community",
            "SNMPv1/v2c with a default community",
            "Configuration",
            devices=("dev-S3",),
        ),
        _finding(
            "finding-native-medium",
            "Medium",
            "topology-differing-native-vlan",
            "Differing native VLAN",
            "Topology",
            devices=("dev-S1", "dev-S2"),
            items=("link-1",),
            source="config",
        ),
        _finding(
            "finding-drift-low",
            "Low",
            "consistency-model-drift",
            "Same model on different releases",
            "Consistency",
            devices=("dev-S1", "dev-S2", "dev-S3"),
            source="tool policy, not a Cisco rule",
        ),
    ]
    return data


def test_findings_are_grouped_by_level_worst_first_with_only_low_closed() -> None:
    levels = _tab(_levels_of_findings())["levels"]

    assert [group["level"] for group in levels] == ["Critical", "High", "Medium", "Low"]
    assert [group["open"] for group in levels] == [True, True, True, False]
    assert [group["findings"] for group in levels] == [1, 1, 1, 1]


def test_one_row_per_check_with_a_count_of_devices_or_links() -> None:
    data = _topology()
    data["findings"] = [  # type: ignore[index]
        _finding(
            "finding-1",
            "High",
            "adv-x",
            "Advisory X",
            "Advisory",
            devices=("dev-S1",),
            cisco_detail=_advisory_detail(),
        ),
        _finding(
            "finding-2",
            "High",
            "adv-x",
            "Advisory X",
            "Advisory",
            devices=("dev-S2",),
            cisco_detail=_advisory_detail(),
        ),
        _finding(
            "finding-3",
            "Medium",
            "topology-native",
            "Differing native VLAN",
            "Topology",
            devices=("dev-S1", "dev-S2"),
            items=("link-1",),
        ),
        _finding(
            "finding-4",
            "Medium",
            "topology-native",
            "Differing native VLAN",
            "Topology",
            devices=("dev-S2", "dev-S3"),
            items=("link-2",),
        ),
    ]

    high, medium = _tab(data)["levels"]

    (advisory,) = high["checks"]
    assert (advisory["findings"], advisory["count"], advisory["count_label"]) == (2, 2, "2 devices")
    (link_check,) = medium["checks"]
    assert (link_check["findings"], link_check["count"], link_check["count_label"]) == (
        2,
        2,
        "2 Links",
    )


def test_a_check_whose_findings_differ_in_level_appears_under_each_level() -> None:
    data = _topology()
    data["findings"] = [  # type: ignore[index]
        _finding(
            "finding-eox-high",
            "High",
            "lifecycle-software-eox",
            "Software EoX",
            "Lifecycle",
            devices=("dev-S1",),
        ),
        _finding(
            "finding-eox-low",
            "Low",
            "lifecycle-software-eox",
            "Software EoX",
            "Lifecycle",
            devices=("dev-S3",),
        ),
    ]

    levels = _tab(data)["levels"]

    assert [group["level"] for group in levels] == ["High", "Low"]
    assert [row["name"] for group in levels for row in group["checks"]] == [
        "Software EoX",
        "Software EoX",
    ]
    assert [group["checks"][0]["devices"] for group in levels] == [["dev-S1"], ["dev-S3"]]


def test_an_advisory_row_shows_its_id_title_and_sir() -> None:
    levels = {group["level"]: group for group in _tab(_levels_of_findings())["levels"]}

    (advisory,) = levels["High"]["checks"]
    assert advisory["type"] == "Advisory"
    assert advisory["title"] == ADVISORY_ID
    assert "Cisco IOS XE Software Example Vulnerability" in advisory["subtitle"]
    assert "SIR High" in advisory["subtitle"]


def test_another_row_shows_the_check_s_name_and_type() -> None:
    levels = {group["level"]: group for group in _tab(_levels_of_findings())["levels"]}

    (configuration,) = levels["Critical"]["checks"]
    assert configuration["title"] == "SNMPv1/v2c with a default community"
    assert configuration["subtitle"] == "Configuration"


def test_the_filter_chips_name_every_check_type() -> None:
    tab = _tab(_levels_of_findings())

    assert [chip["type"] for chip in tab["chips"]] == [
        "All",
        "Advisory",
        "Configuration",
        "Lifecycle",
        "Consistency",
        "Topology",
    ]
    assert "data-type" in _script(_page(_levels_of_findings()))


def test_picking_a_check_gives_only_the_devices_and_links_it_hit() -> None:
    levels = {group["level"]: group for group in _tab(_levels_of_findings())["levels"]}

    (native,) = levels["Medium"]["checks"]
    assert native["devices"] == ["dev-S1", "dev-S2"]
    assert native["items"] == ["link-1"]
    assert native["finding_ids"] == ["finding-native-medium"]

    script = _script(_page(_levels_of_findings()))
    assert "function findingsScene" in script
    assert "hot" in script
    assert "dim" in script
    assert "ALL_NODES" in script  # every device stays where the Map puts it


def test_a_network_wide_finding_lights_every_device_it_names() -> None:
    levels = {group["level"]: group for group in _tab(_levels_of_findings())["levels"]}

    (drift,) = levels["Low"]["checks"]
    assert drift["devices"] == ["dev-S1", "dev-S2", "dev-S3"]
    assert drift["items"] == []


def test_an_advisory_pane_has_cisco_detail_the_fixed_line_and_affected_devices() -> None:
    levels = _tab(_levels_of_findings())["levels"]
    (advisory,) = levels[1]["checks"]
    pane = advisory["advisory"]

    assert pane["id"] == ADVISORY_ID
    assert pane["href"] == (
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
        f"{ADVISORY_ID}"
    )
    assert pane["title"] == "Cisco IOS XE Software Example Vulnerability"
    assert pane["sir"] == "High"
    assert pane["cves"] == ["CVE-2099-0001", "CVE-2099-0002"]
    assert (pane["published"], pane["updated"]) == ("2026-01-02", "2026-02-03")
    assert pane["status"] == "Affected release"
    assert pane["note"] == FIXED
    assert pane["devices"] == [
        {
            "hostname": "sw-a",
            "management_ip": "192.0.2.1",
            "model": "C9300-48P",
            "release": "17.12.4",
            "upgrade_target": "17.12.8",
            "latest_release": "17.12.10",
        },
        {
            "hostname": "sw-b",
            "management_ip": "192.0.2.2",
            "model": "C9300-48P",
            "release": "17.12.4",
            "upgrade_target": "17.12.8",
            "latest_release": "17.12.10",
        },
    ]

    script = _script(_page(_levels_of_findings()))
    assert 'rel="noopener noreferrer"' in script
    assert "Management IP" in script
    assert "Upgrade Target" in script
    assert "Latest Release" in script


def test_an_advisory_id_outside_the_pattern_gets_no_link() -> None:
    data = _topology()
    data["findings"] = [  # type: ignore[index]
        _finding(
            "finding-hostile",
            "High",
            "advisory-hostile",
            "Hostile",
            "Advisory",
            devices=("dev-S1",),
            cisco_detail=_advisory_detail(ident='cisco-sa-x"><img src=x onerror=alert(1)>'),
        )
    ]

    page = _page(data)
    (advisory,) = _tab(data)["levels"][0]["checks"]

    assert advisory["advisory"]["href"] is None
    assert "<img" not in page


def test_advice_this_file_does_not_hold_reads_as_not_available() -> None:
    data = _topology()
    data["devices"][0].pop("advice")  # type: ignore[index]
    data["devices"][1]["advice"] = {  # type: ignore[index]
        "upgrade_target": None,
        "latest_release": {"unknown": "no Suggestion answer"},
    }
    data["findings"] = [  # type: ignore[index]
        _finding(
            "finding-adv",
            "High",
            "adv-x",
            "Advisory X",
            "Advisory",
            devices=("dev-S1", "dev-S2"),
            cisco_detail=_advisory_detail(),
        )
    ]

    (advisory,) = _tab(data)["levels"][0]["checks"]
    first, second = advisory["advisory"]["devices"]

    assert (first["upgrade_target"], first["latest_release"]) == ("not available", "not available")
    assert (second["upgrade_target"], second["latest_release"]) == (
        "no fix in Train",
        "not available",
    )


def test_another_check_s_pane_has_level_type_source_advice_and_where_it_was_found() -> None:
    data = _levels_of_findings()
    data["findings"] = [  # type: ignore[index]
        _finding(
            "finding-telnet",
            "High",
            "cfg-telnet",
            "Telnet allowed",
            "Configuration",
            devices=("dev-S1",),
            what_was_found="Telnet enabled on line vty 0 4",
            what_to_do="Set transport input ssh on every vty line.",
            source="config",
        )
    ]

    levels = _tab(data)["levels"]
    (telnet,) = levels[0]["checks"]

    assert telnet["advisory"] is None
    assert telnet["level"] == "High"
    assert telnet["type"] == "Configuration"
    assert telnet["source"] == "config"
    assert telnet["what_to_do"] == "Set transport input ssh on every vty line."
    assert telnet["rows"] == [{"where": "sw-a", "what_was_found": "Telnet enabled on line vty 0 4"}]
    assert "What to do" in _script(_page(data))


def test_the_header_says_whether_cisco_lookups_ran_and_when() -> None:
    ran = _levels_of_findings()
    ran["cisco_lookups"] = {"ran": True, "when": "2026-11-20T14:02:00+00:00"}  # type: ignore[index]
    not_run = _levels_of_findings()

    assert _tab(ran)["lookups"]["text"] == "Cisco lookups ran on 2026-11-20T14:02:00+00:00."
    assert _tab(not_run)["lookups"]["text"] == "Cisco lookups did not run."
    assert _tab(not_run)["lookups"]["ran"] is False
    assert "FT.lookups" in _script(_page(not_run))


def test_a_network_wide_finding_on_an_unvisited_device_does_not_break_the_tab() -> None:
    data = document(
        [_advised("dev-S1", "sw-a", "192.0.2.1")],
        unvisited=[unvisited_device("unv-0123456789ab", "ap-1", "outside Scope", "dev-S1")],
        findings=[
            _finding(
                "finding-link",
                "Low",
                "topology-conflict",
                "Conflicting evidence",
                "Topology",
                items=("link-1",),
                soft=True,
            )
        ],
    )

    levels = _tab(data)["levels"]

    (low,) = levels
    assert low["checks"][0]["rows"][0]["where"] == "link-1"


def test_device_and_cisco_text_never_reaches_the_page_as_markup() -> None:
    data = _topology()
    data["devices"][0]["hostname"] = HOSTILE  # type: ignore[index]
    data["devices"][0]["advice"] = {"upgrade_target": HOSTILE, "latest_release": HOSTILE}  # type: ignore[index]
    data["findings"] = [  # type: ignore[index]
        _finding(
            "finding-adv",
            "High",
            "adv-x",
            HOSTILE,
            "Advisory",
            devices=("dev-S1",),
            cisco_detail=_advisory_detail(title=HOSTILE, published=HOSTILE, updated=HOSTILE),
        )
    ]

    page = _page(data)

    assert "<img" not in page
    assert page.count("</script>") == 2
    pane = _tab(data)["levels"][0]["checks"][0]["advisory"]
    assert pane["title"] == HOSTILE
    assert pane["devices"][0]["hostname"] == HOSTILE


def test_a_finding_from_before_the_scale_is_left_out_of_the_tab() -> None:
    data = _topology()
    data["findings"] = [  # type: ignore[index]
        {
            "id": "finding-0123456789ab",
            "kind": "conflicting evidence",
            "summary": "Reports disagree about Gi1/0/1",
            "devices": [],
            "items": [],
            "evidence": [],
        }
    ]

    tab = _tab(data)

    assert tab["total"] == 0
    assert tab["levels"] == []


def test_the_reworked_tab_needs_no_script_from_outside_and_makes_no_request() -> None:
    page = _page(_levels_of_findings())
    script = _script(page)

    for call in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "import("):
        assert call not in script
    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page)
    assert policy is not None
    assert "default-src 'none'" in policy.group(1)
