"""A started Run keeps `audit.log`, and its console is scanned (ticket #48; stories 86, 161-164).

Driven through `main(argv)` with what the operator types. The Seed is a fake device
(tests/support/run_driver); a started Run writes its Run-start event, the Seed's events and
its Run-end event.
"""

import json
from pathlib import Path

import pytest

from network_analyser import run_output
from network_analyser._version import __version__
from network_analyser.cli import ExitCode
from tests.support import fake_age
from tests.support.run_driver import (
    BACKUP_CANARY,
    DEVICE_CANARY,
    FLAGS,
    Runner,
    data_folder,
    first_run,
    typed,
)


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    return Runner(monkeypatch, capsys)


def _run_folders() -> list[Path]:
    runs = data_folder().runs
    return sorted(runs.iterdir()) if runs.is_dir() else []


def _audit(folder: Path) -> list[dict[str, object]]:
    text = (folder / "audit.log").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def test_a_started_run_records_its_start_and_end_in_audit_log(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COMPUTERNAME", "PC-A")
    got = run(*FLAGS, "--label", "site-a", typed=first_run())

    assert got.code == ExitCode.CLEAN
    (folder,) = _run_folders()
    lines = _audit(folder)
    start, end = lines[0], lines[-1]
    assert start["event"] == "run_started"
    assert start["severity"] == "info"
    assert start["tool_version"] == __version__
    assert start["pc_name"] == "PC-A"
    assert start["run_folder"] == str(folder)
    assert start["scope"] == ["192.0.2.0/24"]
    assert start["seeds"] == ["192.0.2.1"]
    assert start["label"] == "site-a"
    assert start["credential_sets"] == ["netops-ro"]
    assert end == {
        "time": end["time"],
        "event": "run_ended",
        "severity": "info",
        "ended": "completed",
        "devices_visited": 1,
        "devices_unvisited": 0,
        "backups_written": 1,
        "secret_scan_hits": 0,
    }
    text = (folder / "audit.log").read_text(encoding="utf-8")
    assert BACKUP_CANARY not in text
    assert DEVICE_CANARY not in text


def test_an_audit_log_that_cannot_be_created_stops_the_run_as_ctrl_c_would(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def cannot(*_args: object, **_kwargs: object) -> run_output.AuditLog:
        msg = "audit.log could not be created"
        raise run_output.AuditLogError(msg)

    monkeypatch.setattr(run_output, "open_audit_log", cannot)

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.STOPPED
    assert "audit.log could not be written" in got.err
    assert "as if Ctrl+C had been pressed" in got.err
    assert "No device was contacted." in got.err


def test_an_audit_log_that_stops_taking_lines_stops_the_run(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def disk_full(_handle: int, _data: bytes) -> int:
        raise OSError(28, "No space left on device")

    real_open = run_output.open_audit_log

    def full_disk_log(folder: run_output.RunFolder, scan: object) -> run_output.AuditLog:
        return real_open(folder, scan, write=disk_full)  # type: ignore[arg-type]  # the cli's own scan

    monkeypatch.setattr(run_output, "open_audit_log", full_disk_log)

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.STOPPED
    assert "audit.log could not be written" in got.err
    assert "the crawl is not built yet" not in got.err


def test_a_username_holding_a_password_is_blocked_everywhere_with_one_warning(
    run: Runner,
) -> None:
    username = f"ops-{DEVICE_CANARY}"
    answers = typed("YES", BACKUP_CANARY, BACKUP_CANARY, username, DEVICE_CANARY, "", "n", "y")

    got = run(*FLAGS, typed=answers)

    assert got.code == ExitCode.NEEDS_ATTENTION  # a secret-scan hit needs attention (story 157)
    (folder,) = _run_folders()
    # The password prompt names the username before the password exists; from then on, no.
    shown = got.out + got.err.split(f"Password for {username}: ", 1)[1]
    assert DEVICE_CANARY not in shown
    assert "ops-[blocked]" in shown
    assert (folder / "audit.log").read_text(encoding="utf-8").count(DEVICE_CANARY) == 0
    assert _audit(folder)[0]["credential_sets"] == ["ops-[blocked]"]
    assert _audit(folder)[-1]["severity"] == "warning"
    assert got.err.count("Warning: the secret scan") == 1
    assert "Credential Set password is common text" in got.err
    assert "Set 1" not in got.err.split("Warning: the secret scan")[1]


def test_a_run_folder_path_holding_a_typed_secret_refuses_the_run(
    run: Runner, tmp_path: Path
) -> None:
    runs = tmp_path / f"x{DEVICE_CANARY}"

    got = run(*FLAGS, "--runs-dir", str(runs), typed=first_run())

    assert got.code == ExitCode.REFUSED
    assert "Run folder" in got.err
    assert list(runs.iterdir()) == []
    assert DEVICE_CANARY not in got.out + got.err
