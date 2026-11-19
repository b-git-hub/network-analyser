"""Locking Backups with the Backup Passphrase (ticket #51; stories 84, 92-101, 103-105; ADR 0004).

Driven through `backup_store.BackupLocker`, the sink `device_gateway.visit` hands each
running config to. Most tests use the fast fake age (tests/support/fake_age); one locks
with real age, to prove the files are standard age that `age -d` opens.
"""

import hashlib
import json
import os
import re
import signal
import sys
import threading
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

import pyrage
import pytest

from network_analyser import backup_store
from network_analyser.backup_store import BackupLocker, BackupPassphrase
from network_analyser.backup_store import check_file as check_file_module
from network_analyser.credentials import Secret, SecretScan
from network_analyser.records import Platform
from network_analyser.records.backup import BackupCapture
from network_analyser.records.device import Unknown
from network_analyser.records.events import AuditEvent, BackupWritten, ErrorRaised, Severity
from tests.support import device_text, fake_age

CANARY = "CANARY-pp-61b9-locker"
DEVICE = IPv4Address("192.0.2.10")
CONFIG = device_text.IOS_XE_RUNNING_CONFIG
WHEN = datetime(2026, 11, 18, 10, 15, 30, tzinfo=UTC)


def _capture(
    hostname: str | Unknown = "sw-a",
    serials: tuple[str, ...] | Unknown = ("TEST0000A01", "TEST0000A02"),
    ip: IPv4Address = DEVICE,
) -> BackupCapture:
    return BackupCapture(
        ip, Platform.IOS_XE, hostname, serials, "show running-config view full", WHEN
    )


class Locking:
    """A Run folder, the passphrase and what the locker emitted."""

    def __init__(self, tmp_path: Path) -> None:
        self.folder = tmp_path / "run"
        self.folder.mkdir()
        self.events: list[AuditEvent] = []
        self.scan = SecretScan()
        self.passphrase = self._passphrase(tmp_path)

    @staticmethod
    def _passphrase(tmp_path: Path) -> BackupPassphrase:
        check = tmp_path / "check.age"
        return backup_store.create_check_file(check, Secret(CANARY), fake_age.FAKE_AGE)

    def locker(self, capacity: int = 2) -> BackupLocker:
        return BackupLocker(
            self.folder,
            shown=self.folder,
            passphrase=self.passphrase,
            capacity=capacity,
            emit=self.events.append,
            scan=self.scan,
            tool_version="0.1.0",
        )

    def names(self) -> set[str]:
        return {p.name for p in (self.folder / "backups").iterdir()}

    def written(self) -> list[BackupWritten]:
        return [e for e in self.events if isinstance(e, BackupWritten)]


@pytest.fixture
def locking(tmp_path: Path) -> Locking:
    return Locking(tmp_path)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


def _header_level(locked: bytes) -> int:
    found = re.match(rb"age-encryption\.org/v1\n-> scrypt \S+ (\d+)\n", locked)
    assert found is not None
    return int(found.group(1))


# -- Real age ---------------------------------------------------------------------------------


def test_a_backup_is_standard_age_that_opens_to_exactly_the_config(locking: Locking) -> None:
    locker = locking.locker()

    locker.take(_capture(), CONFIG)
    results = locker.finish()

    backup = locking.folder / "backups" / "sw-a__TEST0000A01.cfg.age"
    locked = backup.read_bytes()
    assert pyrage.passphrase.decrypt(locked, CANARY) == CONFIG.encode()
    for name in ("backups/sw-a__TEST0000A01.cfg.age", "backups/manifest.age"):
        on_disk = (locking.folder / name).read_bytes()
        assert on_disk.startswith(b"age-encryption.org/v1\n-> scrypt ")
        assert b"hostname" not in on_disk
        assert not [c for c in device_text.CONFIG_CANARIES if c.encode() in on_disk]
    assert locking.names() == {"manifest.age", "sw-a__TEST0000A01.cfg.age"}
    (written,) = locking.written()
    assert written.ciphertext_sha256 == hashlib.sha256(locked).hexdigest()
    assert written.scrypt_level == _header_level(locked)
    (record,) = results.backups
    assert record.scrypt_level == written.scrypt_level
    assert record.lock_seconds > 0
    assert results.lock_seconds >= record.lock_seconds


# -- Names (story 94) -------------------------------------------------------------------------


@pytest.mark.usefixtures("fake")
@pytest.mark.parametrize(
    ("hostname", "serials", "name"),
    [
        ("sw-a", ("TEST0000A01",), "sw-a__TEST0000A01.cfg.age"),
        ("sw a/b\\c:..", ("TEST 01",), "sw_a_b_c___TEST_01.cfg.age"),
        ("h" * 80, ("TEST0000A01",), f"{'h' * 51}__TEST0000A01.cfg.age"),
        (Unknown("not read"), ("TEST0000A01",), "TEST0000A01.cfg.age"),
        ("sw-a", Unknown("not read"), "backup-1.cfg.age"),
        ("sw-a", (), "backup-1.cfg.age"),
        ("sw-a", ("...",), "backup-1.cfg.age"),
        (Unknown("not read"), ("CON",), "backup-1.cfg.age"),  # a Windows device name
        (
            "\N{CYRILLIC SMALL LETTER ES}w-a",
            ("TEST\N{LATIN SMALL LETTER E WITH ACUTE}",),
            "_w-a__TEST_.cfg.age",
        ),
    ],
)
def test_backups_are_named_from_hostname_and_chassis_serial_with_fallbacks(
    locking: Locking, hostname: str | Unknown, serials: tuple[str, ...] | Unknown, name: str
) -> None:
    locker = locking.locker()

    locker.take(_capture(hostname, serials), CONFIG)
    locker.finish()

    assert locking.names() == {"manifest.age", name}
    assert len(name.removesuffix(".cfg.age")) <= 64


@pytest.mark.usefixtures("fake")
def test_two_devices_with_the_same_name_never_share_a_file(locking: Locking) -> None:
    locker = locking.locker()

    for last in (1, 2, 3):
        locker.take(_capture(ip=IPv4Address(f"192.0.2.{last}")), CONFIG)
    locker.finish()

    assert locking.names() == {
        "manifest.age",
        "sw-a__TEST0000A01-2.cfg.age",
        "sw-a__TEST0000A01-3.cfg.age",
        "sw-a__TEST0000A01.cfg.age",
    }


@pytest.mark.usefixtures("fake")
def test_a_name_that_holds_a_typed_secret_is_never_put_on_disk(locking: Locking) -> None:
    locking.scan.watch(Secret("CANARY-pw-0a1b-host"))
    locker = locking.locker()

    locker.take(_capture(hostname="CANARY-pw-0a1b-host"), CONFIG)
    locker.finish()

    assert locking.names() == {"manifest.age", "TEST0000A01.cfg.age"}


# -- The manifest (stories 98-99) -------------------------------------------------------------


@pytest.mark.usefixtures("fake")
def test_the_manifest_records_each_backup_and_is_locked(locking: Locking) -> None:
    locker = locking.locker()
    locker.take(_capture(), CONFIG)
    locker.take(_capture("nx-a", ("TEST0000N01",)), device_text.NXOS_RUNNING_CONFIG)

    results = locker.finish()

    locked = (locking.folder / "backups" / "manifest.age").read_bytes()
    plaintext = fake_age.unlock(locked, CANARY)
    assert plaintext is not None
    manifest = json.loads(plaintext)
    first, second = manifest["backups"]
    backup = (locking.folder / "backups" / "sw-a__TEST0000A01.cfg.age").read_bytes()
    assert first == {
        "file": "sw-a__TEST0000A01.cfg.age",
        "ip": "192.0.2.10",
        "hostname": "sw-a",
        "serials": ["TEST0000A01", "TEST0000A02"],
        "platform": "IOS/IOS-XE",
        "command": "show running-config view full",
        "captured_at": "2026-11-18T10:15:30Z",
        "tool_version": "0.1.0",
        "plaintext_sha256": hashlib.sha256(CONFIG.encode()).hexdigest(),
        "ciphertext_sha256": hashlib.sha256(backup).hexdigest(),
    }
    assert second["file"] == "nx-a__TEST0000N01.cfg.age"
    assert results.manifest_path == str(locking.folder / "backups" / "manifest.age")
    assert results.manifest_problem is None


@pytest.mark.usefixtures("fake")
def test_only_the_ciphertext_hash_is_in_the_clear(locking: Locking) -> None:
    locker = locking.locker()
    locker.take(_capture(), CONFIG)

    results = locker.finish()

    plain_hash = hashlib.sha256(CONFIG.encode()).hexdigest()
    assert plain_hash not in repr(locking.events) + repr(results)


@pytest.mark.usefixtures("fake")
def test_a_run_with_no_backups_still_gets_a_manifest(locking: Locking) -> None:
    results = locking.locker().finish()

    assert locking.names() == {"manifest.age"}
    assert results.backups == ()


# -- Levels (story 101) -----------------------------------------------------------------------


def test_a_backup_locked_below_2_to_the_18_is_flagged(
    locking: Locking, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_age.use_fake_age(monkeypatch, level=17)
    locker = locking.locker()

    locker.take(_capture(), CONFIG)
    results = locker.finish()

    (written,) = locking.written()
    assert written.scrypt_level == 17
    assert written.severity is Severity.WARNING
    assert results.backups[0].scrypt_level == 17


# -- One worker, a capped queue (story 100) ---------------------------------------------------


def test_one_worker_locks_one_backup_at_a_time(
    locking: Locking, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = fake_age.cipher()
    at_once: list[int] = []
    running = [0]
    threads: set[int] = set()

    def lock(plaintext: bytes, passphrase: str) -> bytes:
        running[0] += 1
        at_once.append(running[0])
        threads.add(threading.get_ident())
        locked = fake.lock(plaintext, passphrase)
        running[0] -= 1
        return locked

    monkeypatch.setattr(check_file_module, "AGE", check_file_module.Cipher(lock, fake.unlock))
    locker = locking.locker(capacity=3)
    takers = [
        threading.Thread(
            target=locker.take, args=(_capture(ip=IPv4Address(f"192.0.2.{n}")), CONFIG)
        )
        for n in range(1, 7)
    ]
    for taker in takers:
        taker.start()
    for taker in takers:
        taker.join()
    locker.finish()

    assert len(locking.written()) == 6
    assert max(at_once) == 1
    assert len(threads) == 1
    assert threading.get_ident() not in threads


def test_the_queue_is_capped_at_the_parallelism_number(
    locking: Locking, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = fake_age.cipher()
    release = threading.Event()

    def slow_lock(plaintext: bytes, passphrase: str) -> bytes:
        assert release.wait(timeout=10)
        return fake.lock(plaintext, passphrase)

    monkeypatch.setattr(check_file_module, "AGE", check_file_module.Cipher(slow_lock, fake.unlock))
    locker = locking.locker(capacity=2)
    locker.take(_capture(ip=IPv4Address("192.0.2.1")), CONFIG)
    locker.take(_capture(ip=IPv4Address("192.0.2.2")), CONFIG)
    third = threading.Thread(
        target=locker.take, args=(_capture(ip=IPv4Address("192.0.2.3")), CONFIG)
    )
    third.start()
    third.join(timeout=0.2)

    assert third.is_alive()  # waiting for room in the queue
    release.set()
    third.join(timeout=10)
    assert not third.is_alive()
    locker.finish()
    assert len(locking.written()) == 3


# -- Crashes and failures (stories 84, 92, 104) ------------------------------------------------


@pytest.mark.usefixtures("fake")
def test_finishing_locks_every_backup_already_taken(locking: Locking) -> None:
    locker = locking.locker(capacity=5)

    def stopped_run() -> None:
        try:
            for last in (1, 2, 3):
                locker.take(_capture(serials=(f"TEST{last}",)), CONFIG)
            raise KeyboardInterrupt
        finally:
            locker.finish()

    with pytest.raises(KeyboardInterrupt):
        stopped_run()

    assert locking.names() == {
        "manifest.age",
        "sw-a__TEST1.cfg.age",
        "sw-a__TEST2.cfg.age",
        "sw-a__TEST3.cfg.age",
    }


@pytest.mark.skipif(
    sys.platform == "win32", reason="os.kill with SIGINT ends the whole process on Windows"
)
def test_a_config_waiting_for_room_when_ctrl_c_is_pressed_is_still_locked(
    locking: Locking, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = fake_age.cipher()
    release = threading.Event()

    def slow_lock(plaintext: bytes, passphrase: str) -> bytes:
        assert release.wait(timeout=10)
        return fake.lock(plaintext, passphrase)

    monkeypatch.setattr(check_file_module, "AGE", check_file_module.Cipher(slow_lock, fake.unlock))
    locker = locking.locker(capacity=1)
    locker.take(_capture(serials=("TEST1",)), CONFIG)
    ctrl_c = threading.Timer(0.2, os.kill, (os.getpid(), signal.SIGINT))
    ctrl_c.start()  # Ctrl+C while the next one waits for room

    with pytest.raises(KeyboardInterrupt):
        locker.take(_capture(serials=("TEST2",)), CONFIG)
    release.set()
    locker.finish()

    assert locking.names() == {"manifest.age", "sw-a__TEST1.cfg.age", "sw-a__TEST2.cfg.age"}


@pytest.mark.usefixtures("fake")
def test_a_backup_that_cannot_be_written_is_recorded_and_the_rest_carry_on(
    locking: Locking,
) -> None:
    (locking.folder / "backups").write_text("in the way\n")
    locker = locking.locker()

    locker.take(_capture(), CONFIG)
    results = locker.finish()

    (record,) = results.backups
    assert record.path is None
    assert record.problem == "the Backup could not be written"
    assert results.manifest_problem == "the manifest could not be written"
    errors = [e for e in locking.events if isinstance(e, ErrorRaised)]
    assert [e.step for e in errors] == ["write Backup", "write manifest"]
    assert locking.written() == []


@pytest.mark.usefixtures("fake")
def test_no_temporary_file_is_left_beside_a_finished_backup(locking: Locking) -> None:
    locker = locking.locker()

    locker.take(_capture(), CONFIG)
    locker.finish()

    assert locking.names() == {"manifest.age", "sw-a__TEST0000A01.cfg.age"}


@pytest.mark.usefixtures("fake")
def test_an_existing_file_is_never_replaced(locking: Locking) -> None:
    backups = locking.folder / "backups"
    backups.mkdir()
    (backups / "sw-a__TEST0000A01.cfg.age").write_bytes(b"earlier\n")
    locker = locking.locker()

    locker.take(_capture(), CONFIG)
    locker.finish()

    assert (backups / "sw-a__TEST0000A01.cfg.age").read_bytes() == b"earlier\n"
    assert "sw-a__TEST0000A01-2.cfg.age" in locking.names()


@pytest.mark.usefixtures("fake")
def test_nothing_is_taken_after_finishing(locking: Locking) -> None:
    locker = locking.locker()
    locker.finish()

    with pytest.raises(RuntimeError):
        locker.take(_capture(), CONFIG)
