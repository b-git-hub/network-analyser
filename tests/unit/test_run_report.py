"""`run-report.html`: a static record of one Run (#66, stories 156-160).

Synthetic records only. The page has no JavaScript, escapes every device string, and is
written through the secret scan. `render` is covered in `test_render_command`.
"""

import dataclasses
import re
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import discovery, topology
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
    Check,
    CheckType,
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
    assert 'href="diagram.html#finding=finding-0123456789ab"' in page
    assert "differing native VLAN" in page
    assert "VLAN on one end only: 1" in page
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
    assert "C9300-48P runs on two releases" in page


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
