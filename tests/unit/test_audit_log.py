import json
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import cast

import pytest

from network_analyser import run_output
from network_analyser.credentials import Secret, SecretScan
from network_analyser.records import events
from network_analyser.records.events import (
    CommandResult,
    CommandSent,
    LoginAttempted,
    LoginResult,
    RunEnded,
    RunEnding,
)

CANARY = "CANARY-pw-3b9f"
DEVICE = IPv4Address("192.0.2.10")
WHEN = datetime(2026, 11, 18, 10, 15, 30, 123456, tzinfo=UTC)


def _folder(tmp_path: Path) -> run_output.RunFolder:
    path = tmp_path / "20261118T101530Z"
    path.mkdir()
    return run_output.RunFolder(path=path, io_path=path)


def _scan() -> SecretScan:
    scan = SecretScan()
    scan.watch(Secret(CANARY))
    return scan


def _open(tmp_path: Path, scan: SecretScan | None = None) -> run_output.AuditLog:
    return run_output.open_audit_log(_folder(tmp_path), scan or _scan(), now=lambda: WHEN)


def _lines(tmp_path: Path) -> list[dict[str, object]]:
    text = (tmp_path / "20261118T101530Z" / "audit.log").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def _command(command: str = "show version") -> CommandSent:
    return CommandSent(
        ip=DEVICE, command=command, duration_ms=412, bytes_received=2048, result=CommandResult.OK
    )


def test_an_event_is_one_json_line_with_time_event_severity_and_its_fields(
    tmp_path: Path,
) -> None:
    log = _open(tmp_path)
    log.record(_command())

    assert _lines(tmp_path) == [
        {
            "time": "2026-11-18T10:15:30.123Z",
            "event": "command_sent",
            "severity": "info",
            "ip": "192.0.2.10",
            "command": "show version",
            "duration_ms": 412,
            "bytes_received": 2048,
            "result": "ok",
        }
    ]


def test_each_line_is_on_disk_as_soon_as_it_is_recorded(tmp_path: Path) -> None:
    log = _open(tmp_path)
    log.record(_command("terminal length 0"))
    log.record(_command("show version"))

    assert [line["command"] for line in _lines(tmp_path)] == ["terminal length 0", "show version"]


def test_severity_follows_the_event(tmp_path: Path) -> None:
    log = _open(tmp_path)
    log.record(LoginAttempted(DEVICE, 1, "netops-ro", LoginResult.FAILED))
    log.record(RunEnded(RunEnding.CRASHED, 0, 0, 0, 0))

    assert [line["severity"] for line in _lines(tmp_path)] == ["warning", "error"]


def test_a_secret_in_any_field_is_blocked_and_counted(tmp_path: Path) -> None:
    scan = _scan()
    log = _open(tmp_path, scan)
    log.record(LoginAttempted(DEVICE, 1, f"x{CANARY}", LoginResult.SUCCEEDED))

    text = (tmp_path / "20261118T101530Z" / "audit.log").read_text(encoding="utf-8")
    assert CANARY not in text
    assert _lines(tmp_path)[0]["username"] == "x[blocked]"
    assert scan.hits == 1


def test_a_secret_with_characters_json_escapes_is_still_blocked(tmp_path: Path) -> None:
    tricky = 'CANARY-"pw"\\é'
    scan = SecretScan()
    scan.watch(Secret(tricky))
    log = _open(tmp_path, scan)
    log.record(_command(f"show {tricky}"))

    assert _lines(tmp_path)[0]["command"] == "show [blocked]"


def test_control_characters_never_reach_the_file_raw(tmp_path: Path) -> None:
    log = _open(tmp_path)
    log.record(_command("show\x1b[2J\x9b version"))

    raw = (tmp_path / "20261118T101530Z" / "audit.log").read_bytes()
    assert b"\x1b" not in raw
    assert all(byte < 0x80 for byte in raw)
    assert _lines(tmp_path)[0]["command"] == "show\x1b[2J\x9b version"


def test_an_event_type_off_the_schema_is_refused(tmp_path: Path) -> None:
    @dataclass(frozen=True, slots=True)
    class WithOutput(CommandSent):
        output: str

    log = _open(tmp_path)
    sneaky = WithOutput(DEVICE, "show version", 1, 1, CommandResult.OK, "hostname sw-a")

    with pytest.raises(run_output.AuditEventRefusedError):
        log.record(sneaky)
    assert _lines(tmp_path) == []


def test_a_value_that_is_not_plain_data_is_refused(tmp_path: Path) -> None:
    log = _open(tmp_path)
    leak = LoginAttempted(DEVICE, 1, cast("str", Secret(CANARY)), LoginResult.FAILED)

    with pytest.raises(run_output.AuditEventRefusedError):
        log.record(leak)
    assert _lines(tmp_path) == []


def test_every_event_type_has_a_fixed_field_list_matching_its_record() -> None:
    defined = {
        kind
        for kind in vars(events).values()
        if isinstance(kind, type)
        and issubclass(kind, events.AuditEvent)
        and kind is not events.AuditEvent
    }

    assert set(run_output.AUDIT_SCHEMA) == defined
    for kind, (_name, fields) in run_output.AUDIT_SCHEMA.items():
        assert fields == tuple(getattr(kind, "__dataclass_fields__", ()))


def test_no_event_field_can_carry_device_output() -> None:
    words = ("output", "config", "raw", "text", "line", "password", "passphrase")
    names = [f for _name, fields in run_output.AUDIT_SCHEMA.values() for f in fields]

    assert [n for n in names if set(n.split("_")) & set(words)] == []


def test_an_existing_audit_log_is_never_appended_to(tmp_path: Path) -> None:
    folder = _folder(tmp_path)
    (folder.path / "audit.log").write_text("earlier\n", encoding="utf-8")

    with pytest.raises(run_output.AuditLogError):
        run_output.open_audit_log(folder, _scan())


def test_a_failed_write_raises_and_every_later_write_does_too(tmp_path: Path) -> None:
    def disk_full(_handle: int, _data: bytes) -> int:
        raise OSError(28, "No space left on device")

    log = run_output.open_audit_log(_folder(tmp_path), _scan(), write=disk_full)

    with pytest.raises(run_output.AuditLogError):
        log.record(_command())
    with pytest.raises(run_output.AuditLogError):
        log.record(_command())


def test_a_short_write_is_finished(tmp_path: Path) -> None:
    import os  # noqa: PLC0415 (only this test needs the real write)

    def one_byte_at_a_time(handle: int, data: bytes) -> int:
        return os.write(handle, data[:1])

    log = run_output.open_audit_log(
        _folder(tmp_path), _scan(), now=lambda: WHEN, write=one_byte_at_a_time
    )
    log.record(_command())

    assert _lines(tmp_path)[0]["command"] == "show version"
