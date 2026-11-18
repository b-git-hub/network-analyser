"""Security test 5, canary no-secrets (spec #37, Testing Decisions; decided on #28, #30).

A canary Credential Set password and Backup Passphrase never appear in `repr`/`str`, the
console output or `audit.log`, and nothing from the `netmiko`/`paramiko` loggers reaches any
file or the console. Plain pytest, no device. Later tickets extend it to `topology.json`
(#52) and `run-report.html` (#66).
"""

import io
import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import backup_store, run_output
from network_analyser.cli import main
from network_analyser.cli.console import ScannedStream
from network_analyser.cli.parser import build_parser
from network_analyser.credentials import CredentialSet, CredentialSets, Secret, SecretScan
from network_analyser.records.events import LoginAttempted, LoginResult
from tests.support import fake_age
from tests.support.run_driver import (
    BACKUP_CANARY,
    DEVICE_CANARY,
    FLAGS,
    Runner,
    data_folder,
    first_run,
)

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
