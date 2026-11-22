"""`run-report.html`: a static record of one Run (#66, stories 156-160).

Synthetic records only. The page has no JavaScript, escapes every device string, and is
written through the secret scan. `render` is covered in `test_render_command`.
"""

import dataclasses
import html
import re
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import discovery, topology
from network_analyser.analysis.advisory import COULD_NOT_CHECK_CHECK, NEWER_THAN_LIST
from network_analyser.analysis.catalogue import ROLE_CHECK
from network_analyser.analysis.lifecycle import (
    HARDWARE_EOX_COULD_NOT_CHECK_CHECK,
    SOFTWARE_EOX_COULD_NOT_CHECK_CHECK,
)
from network_analyser.cli import ExitCode, summary
from network_analyser.credentials import Secret, SecretScan
from network_analyser.records.backup import BackupRecord, BackupResults
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.events import RunEnding
from network_analyser.records.host_keys import HostKeyCheck, HostKeyVerdict
from network_analyser.records.platform import CredentialSetResult, CredentialSetView, Platform
from network_analyser.records.run_summary import RunReport, RunReportFacts
from network_analyser.records.sweep import ProbeFailure, ProbeResult, SweepResult
from network_analyser.records.topology import (
    AdvisoryOutcome,
    AdvisoryOutcomeKind,
    AnalysisSummary,
    Check,
    CheckType,
    CiscoLookups,
    DeviceAdvice,
    Finding,
    FindingKind,
    FindingLevel,
    SkippedCheck,
    Topology,
    UnknownInterfaceName,
    UnplacedNextHop,
)
from network_analyser.run_output import RunFolder
from network_analyser.run_output import report as report_page
from tests.support import fake_age
from tests.support.fake_device import synthetic_key
from tests.support.run_driver import (
    BACKUP_CANARY,
    DEVICE_CANARY,
    FLAGS,
    Runner,
    data_folder,
    first_run,
)
from tests.support.topology_records import neighbour, port, unvisited, visited

HOSTILE = "http://evil.example/x<script>alert(1)</script>"
STARTED = datetime(2026, 11, 19, 11, 5, 0, tzinfo=UTC)
ENDED = datetime(2026, 11, 19, 11, 7, 4, tzinfo=UTC)
_SCRIPT = re.compile(r"<script", re.IGNORECASE)
_URL = re.compile(r"https?://", re.IGNORECASE)
_ATTENTION = (
    "192.0.2.9: host key changed. run:\n"
    "    network-analyser trust-key 192.0.2.9 --fingerprint SHA256:abc"
)
_SWEEP = SweepResult(
    probes=(
        ProbeResult(
            IPv4Address("192.0.2.50"), open=True, ssh_id="SSH-2.0-Cisco-1.25", failure=None
        ),
        ProbeResult(
            IPv4Address("192.0.2.51"), open=False, ssh_id=None, failure=ProbeFailure.TIMED_OUT
        ),
    ),
    login_seeds=(IPv4Address("192.0.2.50"),),
)


def test_the_attention_marks_match_the_summary() -> None:
    assert {reason.value for reason in summary.ATTENTION_REASONS} == report_page.ATTENTION_REASONS


def test_the_page_is_static_escaped_and_in_utc() -> None:
    page = report_page.render_run_report(_report(), SecretScan())

    assert "<!doctype html>" in page
    assert 'http-equiv="Content-Security-Policy"' in page
    assert "script-src 'none'" in page
    assert _SCRIPT.search(page) is None
    assert _URL.search(page) is None
    assert "2026-11-19 11:05:00Z" in page
    assert "2026-11-19 11:07:04Z" in page
    assert "ended: completed" in page
    assert "dev-S1" in page
    assert "&lt;script&gt;" in page
    assert 'href="diagram.html#device=dev-S1"' in page
    assert "show vlan brief: denied" in page
    assert "GigabitEthernet9/9/9" in page
    assert "198.51.100.9" in page
    assert "no Link could be inferred" in page
    assert "!!" in page
    assert "unreachable" in page
    assert "netops-ro" in page
    assert "IOS/IOS-XE only" in page
    assert "retired" in page
    assert "sw-a__S1.cfg.age" in page
    assert "ab" * 32 in page
    assert "2^17" in page
    assert "ssh-ed25519" in page
    assert "SHA256:" in page
    assert "192.0.2.50" in page
    assert "SSH-2.0-Cisco-1.25" in page
    assert "timed out" in page
    assert "PC-1" in page
    assert "NETWORK\\ops" in page
    assert "0.1.0" in page
    assert "parallel: 4" in page
    assert "strict host keys: yes" in page
    assert "192.0.2.0/24" in page
    assert "on a network location" in page
    assert "trust-key 192.0.2.9" in page
    assert "1.5 s" in page


def test_a_stopped_or_crashed_run_says_how_it_ended() -> None:
    base = _report()
    stopped = report_page.render_run_report(
        dataclasses.replace(
            base,
            facts=dataclasses.replace(
                base.facts,
                ending=RunEnding.STOPPED,
                stop_reason="the operator pressed Ctrl+C",
            ),
        ),
        SecretScan(),
    )
    crashed = report_page.render_run_report(
        dataclasses.replace(
            base,
            facts=dataclasses.replace(base.facts, ending=RunEnding.CRASHED),
            attention=("The Run ended in an internal error.",),
        ),
        SecretScan(),
    )

    assert "ended: stopped" in stopped
    assert "the operator pressed Ctrl+C" in stopped
    assert "ended: crashed" in crashed
    assert "internal error" in crashed


def test_a_run_without_a_sweep_says_so() -> None:
    page = report_page.render_run_report(dataclasses.replace(_report(), sweep=None), SecretScan())

    assert "did not sweep" in page
    assert "192.0.2.50" not in page


def test_a_secret_in_device_text_is_blocked_before_it_is_escaped(tmp_path: Path) -> None:
    quoted = 'CANARY-pw-"<q>'
    scan = SecretScan()
    scan.watch(Secret(DEVICE_CANARY))
    scan.watch(Secret(BACKUP_CANARY))
    scan.watch(Secret(quoted))
    record = visited("192.0.2.1", "S1", f"sw-{DEVICE_CANARY}")
    built = dataclasses.replace(
        topology.build((record,)),
        findings=(
            Finding(
                id="finding-0123456789ab",
                devices=("dev-S1",),
                items=(),
                evidence=(),
                level=FindingLevel.LOW,
                check=Check(
                    "topology-conflicting-evidence", "Conflicting evidence", CheckType.TOPOLOGY
                ),
                what_was_found=f"see {quoted} and {BACKUP_CANARY}",
                what_to_do="Check both reports for the port.",
                source="device reports",
                kind=FindingKind.CONFLICTING_EVIDENCE,
                summary=f"see {quoted} and {BACKUP_CANARY}",
            ),
        ),
    )
    folder = RunFolder(path=tmp_path, io_path=tmp_path)

    report_page.write_run_report(
        folder, dataclasses.replace(_report(), devices=(record,), topology=built), scan
    )

    text = (tmp_path / "run-report.html").read_text(encoding="utf-8")
    for canary in (DEVICE_CANARY, BACKUP_CANARY, quoted, "CANARY-pw"):
        assert canary not in text
    assert "[blocked]" in text
    assert _SCRIPT.search(text) is None
    assert _URL.search(text) is None


def test_a_finding_without_a_v1_kind_is_named_by_its_check() -> None:
    base = _report()
    analysis = dataclasses.replace(
        base.topology.findings[0],
        kind=None,
        level=FindingLevel.HIGH,
        check=Check(
            "consistency-model-drift",
            "Same model on different releases",
            CheckType.CONSISTENCY,
        ),
        summary="C9300-48P runs on two releases",
    )
    built = dataclasses.replace(base.topology, findings=(analysis,))

    page = report_page.render_run_report(dataclasses.replace(base, topology=built), SecretScan())

    assert "Same model on different releases" in page
    assert "C9300-48P runs on two releases" not in page


def test_the_file_is_written_whole_through_the_scan(tmp_path: Path) -> None:
    folder = RunFolder(path=tmp_path, io_path=tmp_path)

    report_page.write_run_report(folder, _report(), SecretScan())

    assert [path.name for path in tmp_path.iterdir()] == ["run-report.html"]
    assert (tmp_path / "run-report.html").read_text(encoding="utf-8").endswith("\n")


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    fake_age.use_fake_age(monkeypatch)
    return Runner(monkeypatch, capsys)


def test_a_crash_still_writes_a_report_marked_crashed(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        msg = "CANARY-crash-text"
        raise RuntimeError(msg)

    monkeypatch.setattr(discovery, "crawl", boom)

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.INTERNAL_ERROR
    assert "CANARY-crash-text" not in got.out + got.err
    text = _report_text()
    assert "ended: crashed" in text
    assert "CANARY" not in text
    assert _SCRIPT.search(text) is None


def test_ctrl_c_before_the_crawl_still_writes_the_report(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def stop(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(discovery, "crawl", stop)

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.STOPPED
    text = _report_text()
    assert "ended: stopped" in text
    assert "the operator pressed Ctrl+C" in text
    folder = _run_folder()
    assert f"Run report  {folder / 'run-report.html'}" in got.out


def _report_text() -> str:
    return (_run_folder() / "run-report.html").read_text(encoding="utf-8")


def _run_folder() -> Path:
    (folder,) = data_folder().runs.iterdir()
    return folder


def _report() -> RunReport:
    record = dataclasses.replace(
        visited(
            "192.0.2.1",
            "S1",
            HOSTILE,
            cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", "192.0.2.2")],
            interfaces=[port("Gi1/0/1")],
        ),
        host_key=HostKeyCheck(
            IPv4Address("192.0.2.1"),
            22,
            HostKeyVerdict.NEW,
            synthetic_key(),
            (),
        ),
    )
    missed = unvisited("192.0.2.9", UnvisitedReason.UNREACHABLE)
    chosen = (record, missed)
    drawn = _drawn(chosen)
    backups = BackupResults(
        backups=(
            BackupRecord(
                IPv4Address("192.0.2.1"),
                HOSTILE,
                r"C:\Runs\backups\sw-a__S1.cfg.age",
                "ab" * 32,
                17,
                1.5,
            ),
        ),
        lock_seconds=1.5,
        manifest_path=r"C:\Runs\backups\manifest.age",
        manifest_problem=None,
    )
    facts = RunReportFacts(
        started_at=STARTED,
        ended_at=ENDED,
        ending=RunEnding.COMPLETED,
        stop_reason=None,
        tool_version="0.1.0",
        windows_account="NETWORK\\ops",
        pc_name="PC-1",
        folder="C:\\Runs\\20261119T110500Z",
        scope=("192.0.2.0/24",),
        exclusions=("192.0.2.255/32",),
        seeds=("192.0.2.1",),
        flags=(
            "label: none (default)",
            "parallel: 4 (command line)",
            "failure budget: 3 (default)",
            "sweep: yes (command line)",
            "sweep in flight: 100 (default)",
            "strict host keys: yes",
            "timeouts (seconds): connect 10, login 20, command 60, backup 300, device 900",
        ),
        notices=("Notice: the Run folder will be on a network location.",),
        secret_scan_hits=0,
    )
    return RunReport(
        facts=facts,
        devices=chosen,
        backups=backups,
        topology=drawn,
        credential_sets=(
            CredentialSetResult(
                CredentialSetView(1, "netops-ro", Platform.IOS_XE),
                successes=2,
                failures=3,
                retired=True,
            ),
        ),
        sweep=_SWEEP,
        attention=(_ATTENTION,),
    )


def _drawn(devices: tuple[DeviceRecord, ...]) -> Topology:
    return dataclasses.replace(
        topology.build(devices),
        findings=(
            Finding(
                id="finding-0123456789ab",
                devices=("dev-S1",),
                items=(),
                evidence=(),
                level=FindingLevel.MEDIUM,
                check=Check(
                    "topology-differing-native-vlan", "Differing native VLAN", CheckType.TOPOLOGY
                ),
                what_was_found="native VLAN differs on the trunk",
                what_to_do="Set the same native VLAN on both ends.",
                source="config",
                kind=FindingKind.DIFFERING_NATIVE_VLAN,
                summary="native VLAN differs on the trunk",
            ),
            Finding(
                id="finding-aaaaaaaaaaaa",
                devices=("dev-S1",),
                items=(),
                evidence=(),
                level=FindingLevel.LOW,
                check=Check(
                    "topology-vlan-on-one-end",
                    "VLAN on one end only",
                    CheckType.TOPOLOGY,
                    soft=True,
                ),
                what_was_found="VLAN 30 on one end only",
                what_to_do="Add the VLAN to the other end, or prune it from this end.",
                source="config",
                kind=FindingKind.VLAN_ON_ONE_END,
                summary="VLAN 30 on one end only",
            ),
        ),
        skipped=(SkippedCheck("dev-S1", "vlans", "show vlan brief: denied"),),
        unknown_interface_names=(UnknownInterfaceName("dev-S1", "GigabitEthernet9/9/9"),),
        unplaced_next_hops=(
            UnplacedNextHop(
                "dev-S1",
                "unv-0123456789ab",
                "default",
                IPv4Address("198.51.100.9"),
                "no Link could be inferred",
            ),
        ),
    )


# -- Analysis in the Run report (#110, stories 21, 47, 54 and 99-102) ------------------------


def _analysis_report(
    *findings: Finding,
    lookups: bool = False,
    attention: tuple[str, ...] = (),
) -> RunReport:
    """A Run report with two ordinary devices and the given Analysis Findings."""
    chosen = (visited("192.0.2.1", "S1", "sw-a"), visited("192.0.2.2", "S2", "sw-b"))
    built = dataclasses.replace(
        topology.build(chosen),
        findings=findings,
        cisco_lookups=CiscoLookups(ran=lookups, when="2026-11-19 11:06:00Z" if lookups else None),
    )
    return dataclasses.replace(_report(), devices=chosen, topology=built, attention=attention)


def _check_finding(
    check_id: str,
    level: FindingLevel,
    *,
    name: str | None = None,
    devices: tuple[str, ...] = ("dev-S1",),
    what_was_found: str | None = None,
) -> Finding:
    return Finding(
        id=f"finding-{check_id}",
        devices=devices,
        items=(),
        evidence=(),
        level=level,
        check=Check(check_id, name or check_id, CheckType.CONFIGURATION),
        what_was_found=what_was_found or f"{check_id} found",
        what_to_do="Fix it.",
        source="config",
        summary=f"{check_id} summary",
    )


def _section(page: str, ident: str) -> str:
    return page.split(f'<section id="{ident}">', 1)[1].split("</section>", 1)[0]


def test_the_analysis_check_ids_match_the_ones_analysis_raises() -> None:
    assert ROLE_CHECK.id == report_page.DEVICE_ROLE_CHECK_ID
    assert COULD_NOT_CHECK_CHECK.id == report_page.COULD_NOT_CHECK_CHECK_ID
    assert (
        HARDWARE_EOX_COULD_NOT_CHECK_CHECK.id == report_page.HARDWARE_EOX_COULD_NOT_CHECK_CHECK_ID
    )
    assert (
        SOFTWARE_EOX_COULD_NOT_CHECK_CHECK.id == report_page.SOFTWARE_EOX_COULD_NOT_CHECK_CHECK_ID
    )


def test_needs_attention_lists_an_eox_could_not_check_for_its_device() -> None:
    page = report_page.render_run_report(
        _analysis_report(
            _check_finding(
                HARDWARE_EOX_COULD_NOT_CHECK_CHECK.id,
                FindingLevel.LOW,
                name="Hardware EoX could not check",
                what_was_found=(
                    "Could not check the hardware's end-of-life dates: Cisco EoX has no record "
                    "for PID C9300-48P (SSA_ERR_026)."
                ),
            ),
            _check_finding(
                SOFTWARE_EOX_COULD_NOT_CHECK_CHECK.id,
                FindingLevel.LOW,
                name="Software EoX could not check",
                what_was_found=(
                    "Could not check the release's end-of-life dates: the release is not readable."
                ),
            ),
        ),
        SecretScan(),
    )

    attention = _section(page, "attention")
    assert "sw-a: Could not check the hardware" in attention
    assert "SSA_ERR_026" in attention
    assert "sw-a: Could not check the release" in attention


def test_the_summary_gives_the_finding_total_and_each_level_count() -> None:
    page = report_page.render_run_report(
        _analysis_report(
            _check_finding("check-critical", FindingLevel.CRITICAL),
            _check_finding("check-high", FindingLevel.HIGH),
            _check_finding("check-medium", FindingLevel.MEDIUM),
            _check_finding("check-low-one", FindingLevel.LOW),
            _check_finding("check-low-two", FindingLevel.LOW),
        ),
        SecretScan(),
    )

    summary = _section(page, "summary")
    assert "<dt>Findings</dt><dd>5</dd>" in summary
    assert "<dt>Critical</dt><dd>1</dd>" in summary
    assert "<dt>High</dt><dd>1</dd>" in summary
    assert "<dt>Medium</dt><dd>1</dd>" in summary
    assert "<dt>Low</dt><dd>2</dd>" in summary


def test_needs_attention_carries_outages_could_not_check_role_and_the_critical_line() -> None:
    outage = "Cisco advisories (openVuln) did not run: Cisco could not be reached."
    page = report_page.render_run_report(
        _analysis_report(
            _check_finding(
                "advisory-cisco-sa-example",
                FindingLevel.CRITICAL,
                name="Example Advisory",
            ),
            _check_finding(
                "advisory-could-not-check",
                FindingLevel.LOW,
                name="Advisory could not check",
                what_was_found=(
                    "Could not check the release's Advisories: the release is unreadable."
                ),
            ),
            _check_finding(
                "config-device-role-out-of-date",
                FindingLevel.MEDIUM,
                name="Device Role out of date",
                what_was_found=(
                    "Device Role is out of date: 2 Checks could not run "
                    "(NTP not synchronised, SSH key under 2048 bits). "
                    "Re-apply the Device Role printed by role-snippet."
                ),
            ),
            attention=(outage,),
        ),
        SecretScan(),
    )

    attention = _section(page, "attention")
    assert outage in attention
    assert "sw-a: Could not check" in attention
    assert "the release is unreadable." in attention
    assert "sw-a: Device Role is out of date: 2 Checks could not run" in attention
    assert "role-snippet" in attention
    assert "!! 1 Critical Findings from 1 Checks \u2014 see the Findings report." in attention


def test_the_findings_section_counts_checks_and_links_to_the_findings_report() -> None:
    page = report_page.render_run_report(
        _analysis_report(
            _check_finding(
                "critical-advisory",
                FindingLevel.CRITICAL,
                devices=("dev-S1", "dev-S2"),
            ),
            _check_finding("high-telnet", FindingLevel.HIGH),
            _check_finding("medium-ntp", FindingLevel.MEDIUM),
            _check_finding("low-bundle", FindingLevel.LOW),
        ),
        SecretScan(),
    )

    findings = _section(page, "findings")
    assert "4 Findings from 4 Checks" in findings
    assert '<a href="findings.html">findings.html</a>' in findings


def test_the_critical_and_high_table_is_worst_first_capped_and_counts_devices() -> None:
    page = report_page.render_run_report(
        _analysis_report(
            _check_finding(
                "critical-big",
                FindingLevel.CRITICAL,
                name="Critical big",
                devices=("dev-S1", "dev-S2"),
            ),
            _check_finding("critical-small", FindingLevel.CRITICAL, name="Critical small"),
            *(
                _check_finding(f"high-{number:02d}", FindingLevel.HIGH, name=f"High {number:02d}")
                for number in range(1, 11)
            ),
        ),
        SecretScan(),
    )

    findings = _section(page, "findings")
    assert "<th>Level</th><th>Check</th><th>Devices</th>" in findings
    assert "<tr><td>Critical</td><td>Critical big</td><td>2</td></tr>" in findings
    assert "<tr><td>Critical</td><td>Critical small</td><td>1</td></tr>" in findings
    assert findings.index("Critical big") < findings.index("Critical small")
    assert findings.index("Critical small") < findings.index("High 01")
    assert "High 08" in findings
    assert "High 09" not in findings
    assert "High 10" not in findings
    assert "Showing the worst 10 of 12 Critical and High Checks." in findings


def test_the_findings_section_lists_only_critical_and_high_checks() -> None:
    page = report_page.render_run_report(
        _analysis_report(
            _check_finding("critical-advisory", FindingLevel.CRITICAL, name="Critical check"),
            _check_finding(
                "medium-ntp",
                FindingLevel.MEDIUM,
                name="NTP not synchronised",
                what_was_found="NTP is not synchronised on sw-a",
            ),
            _check_finding(
                "low-bundle",
                FindingLevel.LOW,
                name="VLAN on one end only",
                what_was_found="VLAN 30 on one end only",
            ),
        ),
        SecretScan(),
    )

    findings = _section(page, "findings")
    assert "Critical check" in findings
    assert "NTP not synchronised" not in findings
    assert "NTP is not synchronised on sw-a" not in findings
    assert "VLAN on one end only" not in findings
    assert "VLAN 30 on one end only" not in findings


def test_the_report_says_ciscos_data_was_fetched_over_tls_only_when_lookups_ran() -> None:
    ran = report_page.render_run_report(_analysis_report(lookups=True), SecretScan())
    not_ran = report_page.render_run_report(_analysis_report(lookups=False), SecretScan())

    assert ran.count("was fetched over TLS and not signature-checked.") == 1
    assert "Cisco&#x27;s data was fetched over TLS" in ran
    assert "not signature-checked" not in not_ran


def test_the_report_says_medium_and_low_are_not_listed_and_that_openvuln_covers_nxos() -> None:
    page = report_page.render_run_report(_analysis_report(lookups=True), SecretScan())

    assert page.count("Medium and Low Advisories are not listed.") == 1
    assert page.count("openVuln covers NX-OS only from July 2019.") == 1


def test_analysis_strings_are_escaped_in_the_table_and_needs_attention() -> None:
    hostile = '<script>alert("x")</script>'
    page = report_page.render_run_report(
        _analysis_report(
            _check_finding("critical-hostile", FindingLevel.CRITICAL, name=hostile),
            _check_finding(
                "advisory-could-not-check",
                FindingLevel.LOW,
                name="Advisory could not check",
                what_was_found=f"Could not check the release's Advisories: {hostile}",
            ),
        ),
        SecretScan(),
    )

    assert "&lt;script&gt;" in page
    assert _SCRIPT.search(page) is None
    assert _URL.search(page) is None


def test_each_devices_upgrade_target_comes_from_the_advice_record() -> None:
    base = _analysis_report()
    advice = (
        _advice("dev-S1", "17.12.8", not_cleared=1),
        _advice("dev-S2", "17.12.9", not_cleared=0),
    )
    built = dataclasses.replace(base.topology, analysis=AnalysisSummary(advice=advice, checks=()))

    page = report_page.render_run_report(dataclasses.replace(base, topology=built), SecretScan())

    assert (
        "Upgrade to 17.12.8 or later (does not clear 1 Advisories: no fix in Train 17.12)" in page
    )
    assert "Upgrade to 17.12.9 or later" in page
    assert "Upgrade to 17.12.9 or later (does not clear" not in page


def test_an_unresolved_upgrade_target_reads_not_available_not_an_upgrade() -> None:
    base = _analysis_report()
    advice = (dataclasses.replace(_advice("dev-S1", "not available", not_cleared=0), train="9.3"),)
    built = dataclasses.replace(base.topology, analysis=AnalysisSummary(advice=advice, checks=()))
    page = report_page.render_run_report(dataclasses.replace(base, topology=built), SecretScan())

    assert "Upgrade to not available" not in page
    assert "<td>not available</td>" in _section(page, "visited")


def test_a_hostile_partial_upgrade_target_is_escaped_in_the_visited_table() -> None:
    hostile = "</td><img src=x onerror=alert(1)>"
    base = _analysis_report()
    advice = (_advice("dev-S1", hostile, not_cleared=1),)
    built = dataclasses.replace(base.topology, analysis=AnalysisSummary(advice=advice, checks=()))
    page = report_page.render_run_report(dataclasses.replace(base, topology=built), SecretScan())

    visited = _section(page, "visited")
    assert "<img" not in page
    assert "Upgrade to &lt;/td&gt;&lt;img" in visited
    assert "does not clear 1 Advisories" in visited


def _advice(device: str, target: str, *, not_cleared: int) -> DeviceAdvice:
    return DeviceAdvice(
        device=device,
        advisory_outcome=AdvisoryOutcome(
            AdvisoryOutcomeKind.MATCHES,
            matched=2,
            release="17.12.4",
        ),
        upgrade_target=target,
        latest_release_in_train="17.12.10",
        latest_release="17.12.10",
        train="17.12",
        not_cleared=not_cleared,
    )


def _latest_advice(
    device: str,
    *,
    in_train: str = "17.12.10",
    overall: str = "26.2.1",
    in_train_lifecycle: str | None = None,
    overall_lifecycle: str | None = None,
) -> DeviceAdvice:
    return dataclasses.replace(
        _advice(device, "17.12.8", not_cleared=0),
        latest_release_in_train=in_train,
        latest_release=overall,
        latest_in_train_lifecycle=in_train_lifecycle,
        latest_release_lifecycle=overall_lifecycle,
    )


def test_the_visited_table_shows_both_latest_releases_with_their_lifecycle_codes() -> None:
    base = _analysis_report()
    advice = (
        _latest_advice(
            "dev-S1",
            in_train="17.12.8",
            overall="26.2.1",
            in_train_lifecycle="MD",
            overall_lifecycle="ED",
        ),
    )
    built = dataclasses.replace(base.topology, analysis=AnalysisSummary(advice=advice, checks=()))

    page = report_page.render_run_report(dataclasses.replace(base, topology=built), SecretScan())

    visited = _section(page, "visited")
    assert "<th>Latest Release</th>" in visited
    assert "Latest Release in Train: 17.12.8 (MD); overall: 26.2.1 (ED)" in visited


def test_a_hostile_lifecycle_code_and_release_are_escaped_in_the_visited_table() -> None:
    base = _analysis_report()
    advice = (
        _latest_advice(
            "dev-S1",
            in_train=HOSTILE,
            overall=HOSTILE,
            in_train_lifecycle=HOSTILE,
            overall_lifecycle=HOSTILE,
        ),
    )
    built = dataclasses.replace(base.topology, analysis=AnalysisSummary(advice=advice, checks=()))

    page = report_page.render_run_report(dataclasses.replace(base, topology=built), SecretScan())

    assert _SCRIPT.search(page) is None
    assert _URL.search(page) is None
    assert "&lt;script&gt;" in page
    assert HOSTILE not in page


def test_no_lifecycle_code_beside_not_available_or_the_newer_release_text() -> None:
    base = _analysis_report()
    advice = (
        _latest_advice(
            "dev-S1",
            in_train="not available",
            overall="26.2.1",
            in_train_lifecycle="MD",
            overall_lifecycle="ED",
        ),
        _latest_advice(
            "dev-S2",
            in_train="17.12.10",
            overall=report_page.NEWER_THAN_LIST,
            overall_lifecycle="ED",
        ),
    )
    built = dataclasses.replace(base.topology, analysis=AnalysisSummary(advice=advice, checks=()))

    page = report_page.render_run_report(dataclasses.replace(base, topology=built), SecretScan())

    visited = _section(page, "visited")
    assert "Latest Release in Train: not available; overall: 26.2.1 (ED)" in visited
    newer = html.escape(report_page.NEWER_THAN_LIST)
    assert f"Latest Release in Train: 17.12.10; overall: {newer}" in visited
    assert "not available (MD)" not in visited
    assert f"{newer} (ED)" not in visited


def test_the_run_reports_newer_release_text_matches_analysiss() -> None:
    assert report_page.NEWER_THAN_LIST == NEWER_THAN_LIST


def test_v1s_other_report_sections_are_unchanged() -> None:
    page = report_page.render_run_report(_report(), SecretScan())

    for heading in (
        "Summary",
        "Needs attention",
        "New host keys",
        "Visited Devices",
        "Unvisited Devices",
        "Sweep",
        "Credential Sets",
    ):
        assert f"<h2>{heading}</h2>" in page
