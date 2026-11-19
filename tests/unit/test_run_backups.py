"""A Run backs up each Visited Device and locks it at once (ticket #51; stories 84, 92-105).

Driven through `main(["run", ...])` with what the operator types; the Seeds are fake devices
at the `device_gateway` seam (tests/support/run_driver). One test locks with real age.
"""

import json
from ipaddress import IPv4Address
from pathlib import Path

import pyrage
import pytest

from network_analyser.cli import ExitCode
from network_analyser.records.backup import BackupCapture
from network_analyser.records.events import ConnectionResult
from tests.support import device_text, fake_age
from tests.support.fake_device import FakeDevice
from tests.support.run_driver import BACKUP_CANARY, FLAGS, Runner, data_folder, first_run

TWO_SEEDS = (*FLAGS, "--seed", "192.0.2.2")


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    return Runner(monkeypatch, capsys)


def _folder() -> Path:
    (folder,) = sorted(data_folder().runs.iterdir())
    return folder


def _audit() -> list[dict[str, object]]:
    text = (_folder() / "audit.log").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def _every_file() -> list[Path]:
    return [p for p in data_folder().root.rglob("*") if p.is_file()]


def test_a_run_locks_its_seeds_backup_with_real_age_and_no_config_reaches_disk_in_the_clear(
    run: Runner,
) -> None:
    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.CLEAN, got.err
    backup = _folder() / "backups" / "sw-a__TEST0000A01.cfg.age"
    locked = backup.read_bytes()
    assert pyrage.passphrase.decrypt(locked, BACKUP_CANARY).decode() == (
        device_text.IOS_XE_RUNNING_CONFIG
    )
    for path in _every_file():
        on_disk = path.read_bytes()
        assert b"hostname sw-a" not in on_disk, path
        assert not [c for c in device_text.CONFIG_CANARIES if c.encode() in on_disk], path
    for canary in device_text.CONFIG_CANARIES:
        assert canary not in got.out + got.err
    assert "Backups: 1 of 1 locked and written" in got.out
    (written,) = [line for line in _audit() if line["event"] == "backup_written"]
    assert written["path"] == str(backup)
    assert written["ip"] == "192.0.2.1"


@pytest.mark.usefixtures("fake")
def test_a_seed_without_a_whole_config_is_partial_and_needs_attention(run: Runner) -> None:
    run.seed.replies["show running-config view full"] = device_text.COMMAND_AUTHORISATION_FAILED

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert "192.0.2.1: partial: the account cannot read the full running config." in got.out
    assert "Backups: 0 of 0 locked and written" in got.out
    assert {p.name for p in (_folder() / "backups").iterdir()} == {"manifest.age"}


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.mark.usefixtures("fake")
def test_backups_already_captured_are_still_locked_after_ctrl_c(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    run.network.add("192.0.2.2", FakeDevice(connection=ConnectionResult.REFUSED))
    dial = run.network.dial

    def ctrl_c_at_the_second_seed(*args: object, **kwargs: object) -> object:
        if args[1] == IPv4Address("192.0.2.2"):
            raise KeyboardInterrupt
        return dial(*args, **kwargs)  # type: ignore[arg-type]  # passing the call through

    monkeypatch.setattr("network_analyser.device_gateway.ssh.dial", ctrl_c_at_the_second_seed)

    got = run(*TWO_SEEDS, typed=first_run())

    assert got.code == ExitCode.STOPPED
    names = {p.name for p in (_folder() / "backups").iterdir()}
    assert names == {"manifest.age", "sw-a__TEST0000A01.cfg.age"}
    events = [line["event"] for line in _audit()]
    assert events.index("backup_written") < events.index("run_ended")


def test_a_backup_locked_below_2_to_the_18_needs_attention(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_age.use_fake_age(monkeypatch, level=17)

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert "192.0.2.1: locked at scrypt level 2^17, below 2^18" in got.out
    (written,) = [line for line in _audit() if line["event"] == "backup_written"]
    assert written["severity"] == "warning"
    assert written["scrypt_level"] == 17


def test_the_capture_record_never_holds_the_config() -> None:
    fields = set(BackupCapture.__dataclass_fields__)

    assert fields == {"ip", "platform", "hostname", "serials", "command", "captured_at"}
