"""`findings.html`: one sheet per device, worst first (#107, stories 103-111 and 117).

Synthetic `topology.json` documents in, one static page out. The page is built from the file
alone, so `render` redraws it without a Run; only the Run time comes from the Run folder's
name, which is the Run's UTC start (story 118).

These tests read the page the operator gets: its order, its callouts, its `<details>` and its
tables. Every name and address is synthetic (RFC 5737 addresses, hostnames like `sw-a`).
"""

import json
import re
from pathlib import Path

import pytest

from network_analyser import diagram
from network_analyser.cli.findings_file import FINDINGS_FILE, write_findings
from network_analyser.credentials import Secret, SecretScan
from network_analyser.diagram.findings_report import DEVICE_ROLE_CHECK as REPORTED_ROLE_CHECK
from network_analyser.platforms.collection import DEVICE_ROLE_CHECK as RAISED_ROLE_CHECK
from network_analyser.run_output import RunFolder
from tests.support import fake_age
from tests.support.run_driver import (
    BACKUP_CANARY,
    DEVICE_CANARY,
    FLAGS,
    Runner,
    data_folder,
    first_run,
)
from tests.support.topology_documents import (
    device,
    document,
    link,
    read,
    unvisited_device,
)

RUN_TIME = "2026-11-20 14:02:00Z"
HOSTILE = "</script><img src=x onerror=alert(1)>\"'&\u2028"
ADVISORY_ID = "cisco-sa-example-abc123"
ADVISORY_HREF = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
FIXED = (
    "Matched on software release only. Cisco may limit this Advisory to devices that use a "
    "particular feature; see 'Vulnerable Products' on Cisco's page."
)
ROLE_CHECK = "Device Role out of date"


def _page(data: object, run_time: str = RUN_TIME) -> str:
    return diagram.draw_findings_report(read(data), lambda text: text, run_time=run_time)


def _advisory_detail(ident: str = ADVISORY_ID, **fields: object) -> dict[str, object]:
    return {
        "id": ident,
        "title": "Cisco IOS XE Software Example Vulnerability",
        "sir": "High",
        "cvss": "8.6",
        "cves": ["CVE-2099-0001", "CVE-2099-0002"],
        "published": "2026-01-02",
        "updated": "2026-02-03",
        "first_fixed": "17.12.8",
        "hardware_family_not_confirmed": False,
        **fields,
    }


def _finding(  # noqa: PLR0913 (each field of a Finding, by name)
    ident: str,
    level: str,
    check_name: str,
    *,
    check_id: str | None = None,
    check_type: str = "Configuration",
    devices: tuple[str, ...] = (),
    items: tuple[str, ...] = (),
    what_was_found: str = "what was found",
    what_to_do: str = "what to do",
    cisco_detail: object = None,
    soft: bool = False,
) -> dict[str, object]:
    return {
        "id": ident,
        "devices": list(devices),
        "items": list(items),
        "evidence": [],
        "level": level,
        "check": {
            "id": check_id or f"check-{ident}",
            "name": check_name,
            "type": check_type,
            "soft": soft,
        },
        "what_was_found": what_was_found,
        "what_to_do": what_to_do,
        "source": "config",
        "summary": what_was_found,
        "kind": None,
        "cisco_detail": cisco_detail,
        "also_flagged_by_cisco": False,
    }


def _advisory(
    ident: str,
    level: str,
    *devices: str,
    detail: dict[str, object] | None = None,
    what_was_found: str = "Affected release 17.12.4",
) -> dict[str, object]:
    return _finding(
        f"finding-{ident}",
        level,
        "Advisory",
        check_id=f"advisory-{ident}",
        check_type="Advisory",
        devices=devices,
        what_was_found=what_was_found,
        what_to_do="Upgrade the device.",
        cisco_detail=_advisory_detail(ident) if detail is None else detail,
    )


def _advised(  # noqa: PLR0913 (each part of the advice, by name)
    ident: str,
    hostname: str,
    address: str,
    *,
    release: str | None = "17.12.4",
    outcome: str | None = "1 Advisory matches",
    upgrade_target: str | None = "17.12.8",
    latest_release: str | None = "17.12.10",
    latest_in_train: str | None = "17.12.10",
    latest_release_lifecycle: str | None = None,
    latest_in_train_lifecycle: str | None = None,
    train: str | None = "17.12",
    **fields: object,
) -> object:
    return device(
        ident,
        hostname,
        address,
        software_version=release,
        advice={
            "outcome": outcome,
            "upgrade_target": upgrade_target,
            "latest_release": latest_release,
            "latest_in_train": latest_in_train,
            "latest_release_lifecycle": latest_release_lifecycle,
            "latest_in_train_lifecycle": latest_in_train_lifecycle,
            "train": train,
        },
        **fields,
    )


def _three_devices() -> object:
    return document(
        [
            _advised("dev-S1", "sw-a", "192.0.2.1"),
            _advised("dev-S2", "sw-b", "192.0.2.2"),
            _advised("dev-S3", "sw-c", "192.0.2.3"),
        ],
        [link("link-1", "dev-S1", "Gi1/0/1", "dev-S2", "Gi1/0/2")],
        findings=[
            _advisory(ADVISORY_ID, "High", "dev-S1"),
            _finding(
                "finding-aaaaaaaaaaaa",
                "Critical",
                "Telnet enabled",
                devices=("dev-S3",),
                what_was_found="Telnet enabled on line vty 0 4",
                what_to_do="Set transport input ssh.",
            ),
        ],
    )


def _order(page: str, *markers: str) -> list[int]:
    return [page.index(marker) for marker in markers]


def test_the_page_is_static_script_free_and_behind_a_csp() -> None:
    page = _page(_three_devices())

    assert page.startswith("<!doctype html>")
    assert 'http-equiv="Content-Security-Policy"' in page
    assert "script-src 'none'" in page
    assert "connect-src 'none'" in page
    assert "<script" not in page.lower()
    assert "<svg" not in page
    assert "Unvisited" not in page
    assert "Backup" not in page


def test_every_finding_is_listed_and_the_map_and_unvisited_are_left_out() -> None:
    data = _three_devices()
    data["unvisited"] = [  # type: ignore[index]  # a JSON document, read by key
        unvisited_device("unv-0123456789ab", "fw-edge", "unreachable", "dev-S1")
    ]

    page = _page(data)

    assert ADVISORY_ID in page
    assert "Telnet enabled on line vty 0 4" in page
    assert "fw-edge" not in page
    assert "unreachable" not in page


def test_the_top_shows_the_run_time_the_total_and_the_counts_per_level() -> None:
    page = _page(_three_devices())

    assert RUN_TIME in page
    assert "2 Findings" in page
    assert re.search(r"Critical</dt><dd>1<", page)
    assert re.search(r"High</dt><dd>1<", page)
    assert re.search(r"Medium</dt><dd>0<", page)
    assert re.search(r"Low</dt><dd>0<", page)


def test_the_index_lists_devices_worst_first_with_counts_per_level() -> None:
    page = _page(_three_devices())

    index_start = page.index('id="device-index"')
    index = page[index_start : page.index("</table>", index_start)]
    assert _order(index, "dev-S3", "dev-S1", "dev-S2") == sorted(
        _order(index, "dev-S3", "dev-S1", "dev-S2")
    )
    body = index[index.index("<tbody>") :]
    rows = re.findall(r"<tr>(.*?)</tr>", body, re.DOTALL)
    assert [re.findall(r"<td>(.*?)</td>", row) for row in rows] == [
        ['<a href="#dev-S3">sw-c</a>', "1", "0", "0", "0", "1"],
        ['<a href="#dev-S1">sw-a</a>', "0", "1", "0", "0", "1"],
        ['<a href="#dev-S2">sw-b</a>', "0", "0", "0", "0", "0"],
    ]


def test_one_sheet_per_device_worst_first_headed_by_its_facts() -> None:
    page = _page(_three_devices())

    first = page.index('id="dev-S3"', page.index("</table>"))
    second = page.index('id="dev-S1"', first)
    third = page.index('id="dev-S2"', second)
    assert first < second < third
    sheet = page[second : page.index("</section>", second)]
    assert "<h2>sw-a</h2>" in sheet
    assert "192.0.2.1" in sheet
    assert "C9300-48P" in sheet
    assert "17.12.4" in sheet


def test_the_upgrade_target_callout_and_the_latest_release_lead_the_sheet() -> None:
    page = _page(_three_devices())

    sheet = page[page.index('id="dev-S1"', page.index("</table>")) :]
    assert "Upgrade to 17.12.8 or later" in sheet
    assert "Latest Release in Train: 17.12.10; overall: 17.12.10" in sheet
    assert sheet.index("Upgrade to 17.12.8 or later") < sheet.index("</details>")


def test_the_latest_release_shows_both_values_with_their_lifecycle_codes() -> None:
    data = document(
        [
            _advised(
                "dev-S1",
                "sw-a",
                "192.0.2.1",
                latest_release="26.2.1",
                latest_in_train="17.12.8",
                latest_release_lifecycle="ED",
                latest_in_train_lifecycle="MD",
            )
        ],
        findings=[_advisory(ADVISORY_ID, "High", "dev-S1")],
    )

    page = _page(data)

    assert "Latest Release in Train: 17.12.8 (MD); overall: 26.2.1 (ED)" in page


def test_a_hostile_lifecycle_code_and_the_newer_text_are_escaped_and_shown() -> None:
    data = document(
        [
            _advised(
                "dev-S1",
                "sw-a",
                "192.0.2.1",
                latest_release="running release is newer than Cisco's list",
                latest_in_train="running release is newer than Cisco's list",
                latest_release_lifecycle=HOSTILE,
                latest_in_train_lifecycle="MD",
            )
        ],
        findings=[_advisory(ADVISORY_ID, "High", "dev-S1")],
    )

    page = _page(data)

    assert "running release is newer than Cisco's list" in page
    assert "&lt;/script&gt;" in page
    assert HOSTILE not in page


@pytest.mark.parametrize(
    ("findings", "advice", "expected"),
    [
        ([_advisory(ADVISORY_ID, "High", "dev-S1")], {}, "Upgrade to 17.12.8 or later"),
        (
            [_advisory(ADVISORY_ID, "High", "dev-S1")],
            {"upgrade_target": None, "latest_release": None, "latest_in_train": None},
            "no fix in Train 17.12",
        ),
        (
            [_advisory(ADVISORY_ID, "High", "dev-S1")],
            {"upgrade_target": "no fix in Train 17.12"},
            "no fix in Train 17.12",
        ),
        (
            [],
            {"outcome": "no known Critical/High Advisories for release 17.12.4"},
            "no Critical/High Advisories",
        ),
        (
            [],
            {"outcome": "could not check: openVuln does not know the release"},
            "could not check: openVuln does not know the release",
        ),
    ],
)
def test_the_upgrade_callout_says_one_of_four_things(
    findings: list[dict[str, object]], advice: dict[str, str | None], expected: str
) -> None:
    data = document([_advised("dev-S1", "sw-a", "192.0.2.1", **advice)], findings=findings)

    page = _page(data)

    assert expected in page


def test_no_fix_in_a_train_without_a_recorded_train_still_reads_as_no_fix() -> None:
    data = document(
        [_advised("dev-S1", "sw-a", "192.0.2.1", upgrade_target=None, train=None)],
        findings=[_advisory(ADVISORY_ID, "High", "dev-S1")],
    )

    page = _page(data)

    assert "no fix in this device's Train" in page


def test_a_file_without_advice_says_could_not_check_rather_than_safe() -> None:
    data = document([device("dev-S1", "sw-a", "192.0.2.1", software_version="17.12.4")])

    page = _page(data)

    assert "could not check: this topology.json does not record the Advisory answer" in page
    assert "no Critical/High Advisories" not in page


def test_advisories_fold_into_one_details_with_the_count_and_the_counts_per_level() -> None:
    data = document(
        [_advised("dev-S1", "sw-a", "192.0.2.1")],
        findings=[
            _advisory(ADVISORY_ID, "Critical", "dev-S1"),
            _advisory("cisco-sa-example-def456", "High", "dev-S1"),
            _advisory("cisco-sa-example-ghi789", "High", "dev-S1"),
        ],
    )

    page = _page(data)

    assert page.count("<details>") == 1
    summary = page[page.index("<summary>") : page.index("</summary>")]
    assert "3 Advisories" in summary
    assert "1 Critical" in summary
    assert "2 High" in summary
    details = page[page.index("<details>") : page.index("</details>")]
    assert details.count(FIXED) == 1
    for header in ("Level", "Advisory", "Title", "CVSS", "CVEs", "First fixed"):
        assert f"<th>{header}</th>" in details
    assert f"{ADVISORY_HREF}{ADVISORY_ID}" in details
    assert 'rel="noopener noreferrer"' in details
    assert "Cisco IOS XE Software Example Vulnerability" in details
    assert "8.6" in details
    assert "CVE-2099-0001, CVE-2099-0002" in details
    assert "17.12.8" in details


def test_an_advisory_with_no_fix_names_the_train() -> None:
    detail = _advisory_detail(first_fixed=None)
    data = document(
        [_advised("dev-S1", "sw-a", "192.0.2.1")],
        findings=[_advisory(ADVISORY_ID, "High", "dev-S1", detail=detail)],
    )

    page = _page(data)

    assert "no fix in Train 17.12" in page


def test_an_unresolved_series_reads_not_available_and_never_upgrades_to_it() -> None:
    """A fix Cisco's `platforms[]` cannot resolve is unknown, not absent (#136)."""
    detail = _advisory_detail(first_fixed=None, fix_unresolved=True)
    data = document(
        [
            _advised(
                "dev-S1",
                "sw-a",
                "192.0.2.1",
                release="9.3(10)",
                outcome="1 Advisory matches",
                upgrade_target="not available",
                train="9.3",
            )
        ],
        findings=[_advisory(ADVISORY_ID, "High", "dev-S1", detail=detail)],
    )

    page = _page(data)

    assert '<p class="callout could-not-check"><b>not available</b></p>' in page
    assert "Upgrade to not available" not in page
    assert "no fix in Train" not in page
    details = page[page.index("<details>") : page.index("</details>")]
    assert "<td>not available</td>" in details


def test_an_advisory_id_that_does_not_pass_the_pattern_is_not_a_link() -> None:
    hostile = 'cisco-sa-x"><script>alert(1)</script>'
    detail = _advisory_detail(ident=hostile)
    data = document(
        [_advised("dev-S1", "sw-a", "192.0.2.1")],
        findings=[_advisory("finding-0123456789ab", "High", "dev-S1", detail=detail)],
    )

    page = _page(data)

    assert ADVISORY_HREF not in page
    assert "<script" not in page.lower()
    assert "&lt;script&gt;" in page


def test_the_other_findings_are_one_table_with_the_device_role_out_of_date_first() -> None:
    data = document(
        [_advised("dev-S1", "sw-a", "192.0.2.1")],
        findings=[
            _advisory(ADVISORY_ID, "High", "dev-S1"),
            _finding(
                "finding-bbbbbbbbbbbb",
                "High",
                "Telnet enabled",
                devices=("dev-S1",),
                what_was_found="Telnet enabled on line vty 0 4",
                what_to_do="Set transport input ssh.",
            ),
            _finding(
                "finding-cccccccccccc",
                "Medium",
                ROLE_CHECK,
                devices=("dev-S1",),
                what_was_found="Device Role is out of date: 2 Checks could not run.",
                what_to_do="Re-apply the Device Role printed by role-snippet.",
            ),
        ],
    )

    page = _page(data)

    other = page[page.index("Other Findings") :]
    for header in ("Level", "Check", "What was found", "What to do"):
        assert f"<th>{header}</th>" in other
    assert _order(other, ROLE_CHECK, "Telnet enabled") == sorted(
        _order(other, ROLE_CHECK, "Telnet enabled")
    )
    assert "Telnet" not in page[page.index("<details>") : page.index("</details>")]


def test_an_eox_finding_lists_each_item_with_its_dates_and_replacement() -> None:
    eox = {
        "items": [
            {
                "name": "C9300-48P",
                "last_date_of_support": "2027-04-30",
                "end_of_security_support": "2027-04-30",
                "end_of_sw_maintenance": "2026-10-31",
                "end_of_sale": "2025-04-30",
                "replacement": "C9300-48P-A",
            },
            {
                "name": "C9300-48P",
                "last_date_of_support": "2028-04-30",
                "end_of_security_support": None,
                "end_of_sw_maintenance": "2027-10-31",
                "end_of_sale": None,
                "replacement": None,
            },
        ]
    }
    data = document(
        [_advised("dev-S1", "sw-a", "192.0.2.1")],
        findings=[
            _finding(
                "finding-dddddddddddd",
                "High",
                "Hardware EoX",
                check_type="Lifecycle",
                devices=("dev-S1",),
                what_was_found="2 items: Last Date of Support passed",
                what_to_do="Order replacements.",
                cisco_detail=eox,
            )
        ],
    )

    page = _page(data)

    assert "2027-04-30" in page
    assert "2026-10-31" in page
    assert "2025-04-30" in page
    assert "C9300-48P-A" in page
    assert "2028-04-30" in page
    assert "2027-10-31" in page
    assert page.count("C9300-48P") >= 2
    assert "no replacement PID named" in page


def test_a_link_finding_appears_on_both_ends_sheets() -> None:
    data = document(
        [
            _advised("dev-S1", "sw-a", "192.0.2.1"),
            _advised("dev-S2", "sw-b", "192.0.2.2"),
        ],
        [link("link-1", "dev-S1", "Gi1/0/1", "dev-S2", "Gi1/0/2")],
        findings=[
            _finding(
                "finding-eeeeeeeeeeee",
                "Medium",
                "Differing native VLAN",
                check_type="Topology",
                devices=("dev-S1", "dev-S2"),
                items=("link-1",),
                what_was_found="Native VLAN 1 on sw-a Gi1/0/1; 99 on sw-b Gi1/0/2",
            )
        ],
    )

    page = _page(data)

    first = page[page.index('id="dev-S1"', page.index("</table>")) :]
    second = page[page.index('id="dev-S2"', page.index("</table>")) :]
    assert "Differing native VLAN" in first
    assert "Differing native VLAN" in second


def test_a_network_wide_finding_appears_on_each_named_device_s_sheet() -> None:
    data = document(
        [
            _advised("dev-S1", "sw-a", "192.0.2.1"),
            _advised("dev-S2", "sw-b", "192.0.2.2"),
            _advised("dev-S3", "sw-c", "192.0.2.3"),
        ],
        findings=[
            _finding(
                "finding-ffffffffffff",
                "Low",
                "Same model on different releases",
                check_type="Consistency",
                devices=("dev-S1", "dev-S2", "dev-S3"),
                what_was_found="C9300-48P runs on 2 releases",
            )
        ],
    )

    page = _page(data)

    for ident in ("dev-S1", "dev-S2", "dev-S3"):
        sheet = page[page.index(f'id="{ident}"', page.index("</table>")) :]
        assert "Same model on different releases" in sheet


def test_every_device_string_and_cisco_string_is_escaped() -> None:
    detail = _advisory_detail(title=HOSTILE)
    data = document(
        [
            _advised("dev-S1", HOSTILE, "192.0.2.1", release=HOSTILE, model=HOSTILE),
        ],
        findings=[
            _advisory(ADVISORY_ID, "High", "dev-S1", detail=detail),
            _finding(
                "finding-aaaaaaaaaaaa",
                "High",
                HOSTILE,
                devices=("dev-S1",),
                what_was_found=HOSTILE,
                what_to_do=HOSTILE,
            ),
        ],
    )

    page = _page(data)

    assert "<script" not in page.lower()
    assert "<img" not in page.lower()
    assert "&lt;/script&gt;" in page
    assert "onerror=alert(1)" in page  # text, escaped, inside no tag
    assert "<img src=x" not in page


def test_a_secret_in_a_finding_is_blocked_before_it_is_escaped(tmp_path: Path) -> None:
    scan = SecretScan()
    scan.watch(Secret(DEVICE_CANARY))
    scan.watch(Secret(BACKUP_CANARY))
    data = document(
        [_advised("dev-S1", "sw-a", "192.0.2.1")],
        findings=[
            _advisory(ADVISORY_ID, "High", "dev-S1"),
            _finding(
                "finding-aaaaaaaaaaaa",
                "High",
                "Telnet enabled",
                devices=("dev-S1",),
                what_was_found=f"{DEVICE_CANARY} {BACKUP_CANARY}",
                what_to_do="Set transport input ssh.",
            ),
        ],
    )
    (tmp_path / "topology.json").write_text(json.dumps(data), encoding="utf-8")
    folder = RunFolder(path=tmp_path, io_path=tmp_path)

    write_findings(folder, scan)

    text = (tmp_path / FINDINGS_FILE).read_text(encoding="utf-8")
    for canary in (DEVICE_CANARY, BACKUP_CANARY):
        assert canary not in text
    assert "[blocked]" in text
    assert "<script" not in text.lower()


def test_the_file_is_written_whole_and_ends_with_a_newline(tmp_path: Path) -> None:
    data = document([_advised("dev-S1", "sw-a", "192.0.2.1")])
    (tmp_path / "topology.json").write_text(json.dumps(data), encoding="utf-8")
    folder = RunFolder(path=tmp_path, io_path=tmp_path)

    write_findings(folder, SecretScan())

    assert sorted(path.name for path in tmp_path.iterdir()) == [FINDINGS_FILE, "topology.json"]
    assert (tmp_path / FINDINGS_FILE).read_text(encoding="utf-8").endswith("\n")


def test_the_run_time_comes_from_the_run_folder_name_when_it_is_not_given(
    tmp_path: Path,
) -> None:
    folder = tmp_path / "20261120T140200Z_dc1"
    folder.mkdir()
    data = document([_advised("dev-S1", "sw-a", "192.0.2.1")])
    (folder / "topology.json").write_text(json.dumps(data), encoding="utf-8")

    write_findings(RunFolder(path=folder, io_path=folder), SecretScan())

    page = (folder / FINDINGS_FILE).read_text(encoding="utf-8")
    assert "2026-11-20 14:02:00Z" in page


def test_a_device_with_no_findings_still_gets_a_sheet_saying_so() -> None:
    data = document(
        [
            _advised(
                "dev-S1",
                "sw-a",
                "192.0.2.1",
                outcome="no known Critical/High Advisories for release 17.12.4",
            )
        ]
    )

    page = _page(data)

    sheet = page[page.index('id="dev-S1"', page.index("</table>")) :]
    assert "no Critical/High Advisories" in sheet
    assert "No Findings" in sheet


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    fake_age.use_fake_age(monkeypatch)
    return Runner(monkeypatch, capsys)


def test_a_run_writes_the_findings_report_beside_its_other_outputs(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run())

    assert got.code == 0
    (folder,) = data_folder().runs.iterdir()
    page = (folder / FINDINGS_FILE).read_text(encoding="utf-8")
    assert "Findings report" in page
    assert "Run time 20" in page
    assert "sw-a" in page
    assert "192.0.2.1" in page
    assert 'http-equiv="Content-Security-Policy"' in page
    assert FINDINGS_FILE in got.out


def test_the_device_role_check_name_is_the_one_platforms_raises() -> None:
    assert REPORTED_ROLE_CHECK == RAISED_ROLE_CHECK
