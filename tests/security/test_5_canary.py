"""Security test 5, canary no-secrets (spec #37, Testing Decisions; decided on #28, #30).

A canary Credential Set password and Backup Passphrase never appear in `repr`/`str`, the
console output, `audit.log`, `topology.json` (#52), `diagram.html` (#63), `diagram.drawio`
(#65), `run-report.html` (#66) or `findings.html` (#107), and nothing from
the `netmiko`/`paramiko` loggers reaches any file or the console. Plain pytest, no device.
Every Finding's text is scanned too, as a backstop for a Check that leaks a secret (#93).
"""

import dataclasses
import io
import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import backup_store, run_output, topology
from network_analyser.cli import main
from network_analyser.cli.console import ScannedStream
from network_analyser.cli.diagram_file import write_diagram
from network_analyser.cli.findings_file import write_findings
from network_analyser.cli.parser import build_parser
from network_analyser.cli.run_topology import save_topology
from network_analyser.credentials import CredentialSet, CredentialSets, Secret, SecretScan
from network_analyser.records.events import LoginAttempted, LoginResult
from network_analyser.records.topology import (
    AdvisoryDetail,
    Check,
    CheckType,
    CiscoDetailKind,
    Finding,
    FindingKind,
    FindingLevel,
)
from network_analyser.run_output.report import write_run_report
from tests.support import fake_age
from tests.support.run_driver import (
    BACKUP_CANARY,
    DEVICE_CANARY,
    FLAGS,
    Runner,
    data_folder,
    first_run,
)
from tests.support.topology_documents import device, document
from tests.support.topology_records import neighbour, port, visited
from tests.unit.test_run_report import _report

pytestmark = pytest.mark.security

CANARIES = (BACKUP_CANARY, DEVICE_CANARY)
LIBRARY_LOGGERS = ("netmiko", "netmiko.base_connection", "paramiko", "paramiko.transport")


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


def _holders(tmp_path: Path) -> Iterator[object]:
    password = Secret(DEVICE_CANARY)
    credential_set = CredentialSet("netops-ro", password, None)
    sets = CredentialSets([credential_set])
    passphrase = backup_store.create_check_file(tmp_path / "check.age", Secret(BACKUP_CANARY))
    scan = SecretScan()
    sets.add_to_scan(scan)
    passphrase.add_to_scan(scan)
    yield from (password, Secret(BACKUP_CANARY), credential_set, sets, passphrase, scan)


def test_no_holder_of_a_secret_shows_it_in_repr_or_str(tmp_path: Path) -> None:
    shown = [text for holder in _holders(tmp_path) for text in (repr(holder), str(holder))]

    assert [text for text in shown if any(c in text for c in CANARIES)] == []


def test_a_whole_run_shows_no_secret_on_the_console_or_in_any_file(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    got = Runner(monkeypatch, capsys)(*FLAGS, typed=first_run())

    assert got.code == 0
    for canary in CANARIES:
        assert canary not in got.out + got.err
    (folder,) = data_folder().runs.iterdir()
    assert (folder / "audit.log").is_file()
    assert (folder / "topology.json").is_file()
    assert (folder / "diagram.html").is_file()
    assert (folder / "diagram.drawio").is_file()
    assert (folder / "run-report.html").is_file()
    assert (folder / "findings.html").is_file()
    report_text = (folder / "run-report.html").read_text(encoding="utf-8")
    assert "<script" not in report_text.lower()
    findings_text = (folder / "findings.html").read_text(encoding="utf-8")
    assert "<script" not in findings_text.lower()
    written = [p for p in data_folder().root.rglob("*") if p.is_file()]
    for canary in CANARIES:
        assert [p for p in written if canary.encode() in p.read_bytes()] == []


def _scan() -> SecretScan:
    scan = SecretScan()
    for canary in CANARIES:
        scan.watch(Secret(canary))
    return scan


def test_a_secret_that_slips_into_console_output_is_blocked() -> None:
    console = io.StringIO()
    stream = ScannedStream(console, _scan())
    print("set 1:", DEVICE_CANARY, "passphrase", BACKUP_CANARY, file=stream)

    assert console.getvalue() == "set 1: [blocked] passphrase [blocked]\n"


def test_a_secret_that_slips_into_an_audit_event_is_blocked(tmp_path: Path) -> None:
    folder = run_output.RunFolder(path=tmp_path, io_path=tmp_path)
    log = run_output.open_audit_log(folder, _scan(), now=lambda: datetime.now(UTC))
    log.record(
        LoginAttempted(
            IPv4Address("192.0.2.1"), 1, DEVICE_CANARY + BACKUP_CANARY, LoginResult.FAILED
        )
    )
    log.close()

    text = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert json.loads(text)["username"] == "[blocked]"
    for canary in CANARIES:
        assert canary not in text


def test_a_secret_that_slips_into_device_records_never_reaches_topology_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    quoted = 'CANARY-pw-"q\\uote'  # JSON escapes would hide it from a scan of the text
    scan = _scan()
    scan.watch(Secret(quoted))
    described = dataclasses.replace(port("Gi1/0/1"), description=f"to {BACKUP_CANARY}")
    record = visited(
        "192.0.2.1",
        "S1",
        DEVICE_CANARY,
        interfaces=[described],
        cdp=[neighbour("Gi1/0/1", quoted, "Gi0/1", "192.0.2.9", platform=DEVICE_CANARY)],
    )
    folder = run_output.RunFolder(path=tmp_path, io_path=tmp_path)

    assert save_topology(folder, (record,), scan)

    capsys.readouterr()
    text = (tmp_path / "topology.json").read_text(encoding="utf-8")
    assert "[blocked]" in text
    for canary in (*CANARIES, quoted, json.dumps(quoted)[1:-1]):
        assert canary not in text
    assert scan.hits == 4


def test_a_secret_that_slips_into_topology_json_never_reaches_the_diagram(tmp_path: Path) -> None:
    quoted = 'CANARY-pw-"<q\\uote'  # HTML and the page's escapes would hide it from a scan
    scan = _scan()
    scan.watch(Secret(quoted))
    data = document([device("dev-S1", quoted, model=DEVICE_CANARY, platform=BACKUP_CANARY)])
    (tmp_path / "topology.json").write_text(json.dumps(data), encoding="utf-8")
    folder = run_output.RunFolder(path=tmp_path, io_path=tmp_path)

    write_diagram(folder, scan)

    for name in ("diagram.html", "diagram.drawio"):
        text = (tmp_path / name).read_text(encoding="utf-8")
        for canary in (*CANARIES, quoted, "CANARY-pw"):
            assert canary not in text, name
    assert scan.hits >= 6  # at least the three in each file


def test_a_secret_that_slips_into_a_finding_never_reaches_disk(tmp_path: Path) -> None:
    quoted = 'CANARY-pw-"<q\\uote'
    scan = _scan()
    scan.watch(Secret(quoted))
    detail = AdvisoryDetail(
        kind=CiscoDetailKind.ADVISORY,
        id=quoted,
        title=f"{DEVICE_CANARY} {BACKUP_CANARY}",
        sir=FindingLevel.CRITICAL,
        cvss=BACKUP_CANARY,
        cves=(quoted,),
        published=DEVICE_CANARY,
        updated=BACKUP_CANARY,
        first_fixed=quoted,
    )
    finding = Finding(
        id="finding-0123456789ab",
        devices=(),
        items=(),
        evidence=(),
        level=FindingLevel.HIGH,
        check=Check(f"advisory-{quoted}", DEVICE_CANARY, CheckType.ADVISORY),
        what_was_found=f"{quoted} {DEVICE_CANARY}",
        what_to_do=f"{BACKUP_CANARY} {quoted}",
        source=DEVICE_CANARY,
        kind=FindingKind.CONFLICTING_EVIDENCE,
        summary=quoted,
        cisco_detail=detail,
        also_flagged_by_cisco=True,
    )
    built = dataclasses.replace(topology.build(()), findings=(finding,))
    folder = run_output.RunFolder(path=tmp_path, io_path=tmp_path)

    run_output.write_scanned_json(folder, "topology.json", topology.to_document(built), scan)
    write_diagram(folder, scan)
    write_findings(folder, scan)
    write_run_report(folder, dataclasses.replace(_report(), topology=built), scan)

    for name in (
        "topology.json",
        "diagram.html",
        "diagram.drawio",
        "findings.html",
        "run-report.html",
    ):
        text = (tmp_path / name).read_text(encoding="utf-8")
        for canary in (*CANARIES, quoted, "CANARY-pw"):
            assert canary not in text, name
    assert "[blocked]" in (tmp_path / "topology.json").read_text(encoding="utf-8")


def test_a_secret_that_slips_into_device_text_never_reaches_the_run_report(tmp_path: Path) -> None:
    quoted = 'CANARY-pw-"<q>'
    scan = _scan()
    scan.watch(Secret(quoted))
    page_report = _report()
    record = page_report.devices[0]
    hostile = dataclasses.replace(record, version=None)
    built = dataclasses.replace(
        page_report.topology,
        findings=(
            dataclasses.replace(
                page_report.topology.findings[0],
                summary=f"see {quoted} {DEVICE_CANARY} {BACKUP_CANARY}",
            ),
        ),
    )
    folder = run_output.RunFolder(path=tmp_path, io_path=tmp_path)

    write_run_report(
        folder,
        dataclasses.replace(
            page_report,
            devices=(dataclasses.replace(hostile, ssh_id=DEVICE_CANARY),),
            topology=dataclasses.replace(
                built,
                devices=tuple(
                    dataclasses.replace(device, hostname=BACKUP_CANARY) for device in built.devices
                ),
            ),
        ),
        scan,
    )

    text = (tmp_path / "run-report.html").read_text(encoding="utf-8")
    for canary in (*CANARIES, quoted, "CANARY-pw"):
        assert canary not in text
    assert "[blocked]" in text
    assert scan.hits >= 1


def test_nothing_the_ssh_libraries_log_reaches_a_file_or_the_console(
    capfd: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert main(["--version"]) == 0  # main() caps the library loggers first
    capfd.readouterr()
    before = sorted(Path.cwd().rglob("*")) + sorted(tmp_path.rglob("*"))

    for name in LIBRARY_LOGGERS:
        logger = logging.getLogger(name)
        for level in (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR):
            logger.log(level, "read_channel: %s", DEVICE_CANARY)
        logger.critical("secret %s", BACKUP_CANARY)

    captured = capfd.readouterr()
    assert captured.out + captured.err == ""
    assert sorted(Path.cwd().rglob("*")) + sorted(tmp_path.rglob("*")) == before
    for name in ("netmiko", "paramiko"):
        logger = logging.getLogger(name)
        assert logger.level == logging.WARNING
        assert logger.propagate is False
        assert all(type(h) is logging.NullHandler for h in logger.handlers)


@pytest.mark.parametrize("flag", ["--debug", "--verbose", "--session-log"])
def test_there_is_no_debug_mode_that_could_record_device_output(flag: str) -> None:
    with pytest.raises(SystemExit) as refused:
        build_parser().parse_args(["run", flag])

    assert refused.value.code == 2
