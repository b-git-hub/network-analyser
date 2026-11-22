"""The Cisco API key file at `backup_store` (ticket #103; ADR 0008; stories 30, 33, 37-39).

Locked with the Backup Passphrase through the same age cipher as a Backup, so the client ID
and secret stay out of the ciphertext. The fast fake age stands in for scrypt.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from network_analyser import backup_store
from network_analyser.backup_store import (
    KEY_LOCKED_ELSEWHERE,
    CiscoKey,
    key_file_set_time,
    lock_key_file,
    relock_key_file,
    remove_key_file,
    unlock_key_file,
)
from network_analyser.credentials import BLOCKED, Secret, SecretScan
from tests.support import fake_age

OLD = "CANARY-pp-0ld1-current"
NEW = "CANARY-pp-n3w2-rotated"
THIRD = "CANARY-pp-th1rd-other"
CLIENT_ID = "CANARY-client-id-103a"
CLIENT_SECRET = "CANARY-client-secret-103a"
SET_AT = datetime(2026, 11, 20, 12, 34, 56, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _fake(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


def _passphrase(tmp_path: Path, name: str, secret: str) -> backup_store.BackupPassphrase:
    return backup_store.create_check_file(tmp_path / name, Secret(secret))


def _passphrases(
    tmp_path: Path,
) -> tuple[backup_store.BackupPassphrase, backup_store.BackupPassphrase]:
    return _passphrase(tmp_path, "check.age", OLD), _passphrase(tmp_path, "new.age", NEW)


def _store(
    tmp_path: Path, passphrase: backup_store.BackupPassphrase, *, name: str = "cisco-key.age"
) -> Path:
    path = tmp_path / name
    lock_key_file(path, Secret(CLIENT_ID), Secret(CLIENT_SECRET), passphrase, set_at=SET_AT)
    return path


def test_a_key_round_trips_and_holds_no_plaintext(tmp_path: Path) -> None:
    old, _ = _passphrases(tmp_path)
    path = _store(tmp_path, old)

    locked = path.read_bytes()
    assert locked.startswith(b"age-encryption.org/v1\n")
    assert CLIENT_ID.encode() not in locked
    assert CLIENT_SECRET.encode() not in locked

    key = unlock_key_file(path, old)
    assert isinstance(key, CiscoKey)
    assert key.client_id.same_as(Secret(CLIENT_ID))
    assert key.client_secret.same_as(Secret(CLIENT_SECRET))
    assert key.set_at == SET_AT
    assert key.client_id_suffix() == CLIENT_ID[-4:]


def test_a_new_key_replaces_an_earlier_one(tmp_path: Path) -> None:
    old, _ = _passphrases(tmp_path)
    path = _store(tmp_path, old)

    lock_key_file(
        path,
        Secret("CANARY-client-id-new1"),
        Secret("CANARY-client-secret-new1"),
        old,
        set_at=SET_AT,
    )

    key = unlock_key_file(path, old)
    assert key is not None
    assert key.client_id.same_as(Secret("CANARY-client-id-new1"))
    assert key.client_secret.same_as(Secret("CANARY-client-secret-new1"))


def test_the_key_file_says_when_it_was_set_and_a_relock_keeps_that_time(tmp_path: Path) -> None:
    old, new = _passphrases(tmp_path)
    path = _store(tmp_path, old)

    assert key_file_set_time(path) == SET_AT
    assert relock_key_file(path, old, new).problem is None

    assert key_file_set_time(path) == SET_AT


def test_the_client_id_and_secret_join_the_scan_when_the_key_is_unlocked(tmp_path: Path) -> None:
    old, _ = _passphrases(tmp_path)
    key = unlock_key_file(_store(tmp_path, old), old)
    assert key is not None
    scan = SecretScan()

    key.add_to_scan(scan)

    blocked, hits = scan.contains_secret(f"{CLIENT_ID} {CLIENT_SECRET}")
    assert blocked == f"{BLOCKED} {BLOCKED}"
    assert hits == 2


def test_a_key_the_passphrase_cannot_open_is_none(tmp_path: Path) -> None:
    old, _ = _passphrases(tmp_path)
    path = _store(tmp_path, old)
    _, wrong = _passphrases(tmp_path / "other")

    assert unlock_key_file(path, wrong) is None
    assert unlock_key_file(tmp_path / "missing.age", old) is None


def test_a_file_that_is_not_a_key_document_is_none(tmp_path: Path) -> None:
    old, _ = _passphrases(tmp_path)
    path = tmp_path / "cisco-key.age"
    path.write_bytes(old.lock(b'{"not": "a key"}\n'))

    assert unlock_key_file(path, old) is None


def test_a_file_that_is_not_age_at_all_is_none(tmp_path: Path) -> None:
    old, _ = _passphrases(tmp_path)
    path = tmp_path / "cisco-key.age"
    path.write_bytes(b"plain text, not an age file")

    assert unlock_key_file(path, old) is None


def test_a_key_document_without_a_zone_in_its_time_is_none(tmp_path: Path) -> None:
    old, _ = _passphrases(tmp_path)
    path = tmp_path / "cisco-key.age"
    document = (
        b'{"format_version": 1, "client_id": "CANARY-client-id-103a", '
        b'"client_secret": "CANARY-client-secret-103a", "set_at": "2026-11-20T12:34:56"}'
    )
    path.write_bytes(old.lock(document))

    assert unlock_key_file(path, old) is None


def test_a_file_too_big_to_be_a_key_is_none(tmp_path: Path) -> None:
    old, _ = _passphrases(tmp_path)
    path = tmp_path / "cisco-key.age"
    path.write_bytes(b"x" * (64 * 1024 + 1))

    assert unlock_key_file(path, old) is None


def test_an_unreadable_key_file_has_its_own_reason(tmp_path: Path) -> None:
    """A sharing violation or an oversized file is not a wrong passphrase (#150)."""
    old, _ = _passphrases(tmp_path)
    path = tmp_path / "cisco-key.age"
    path.write_bytes(b"x" * (64 * 1024 + 1))

    opened = backup_store.open_key_file(path, old)

    assert opened.key is None
    assert opened.problem == backup_store.KEY_FILE_UNREADABLE


def test_a_wrong_passphrase_has_no_unreadable_reason(tmp_path: Path) -> None:
    old, _ = _passphrases(tmp_path)
    path = _store(tmp_path, old)
    _, wrong = _passphrases(tmp_path / "other")

    opened = backup_store.open_key_file(path, wrong)

    assert opened.key is None
    assert opened.problem is None


def test_a_key_file_held_open_by_another_program_has_its_own_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, _ = _passphrases(tmp_path)
    path = _store(tmp_path, old)

    def refuse(*_args: object, **_kwargs: object) -> None:
        msg = "held open by another program"
        raise PermissionError(msg)

    monkeypatch.setattr(Path, "open", refuse)

    opened = backup_store.open_key_file(path, old)

    assert opened.key is None
    assert opened.problem == backup_store.KEY_FILE_UNREADABLE


def test_the_key_never_shows_its_value_in_repr_or_str(tmp_path: Path) -> None:
    old, _ = _passphrases(tmp_path)
    key = unlock_key_file(_store(tmp_path, old), old)
    assert key is not None

    shown = repr(key) + str(key)
    assert CLIENT_ID not in shown
    assert CLIENT_SECRET not in shown
    assert "held in memory" in shown


def test_relock_moves_the_key_to_the_new_passphrase_and_keeps_the_content(tmp_path: Path) -> None:
    old, new = _passphrases(tmp_path)
    path = _store(tmp_path, old)
    before = unlock_key_file(path, old)
    assert before is not None

    outcome = relock_key_file(path, old, new)

    assert outcome.problem is None
    assert outcome.rekeyed
    after = unlock_key_file(path, new)
    assert after is not None
    assert after.client_id.same_as(before.client_id)
    assert after.client_secret.same_as(before.client_secret)
    assert after.set_at == before.set_at
    assert unlock_key_file(path, old) is None


def test_relock_of_a_missing_file_is_nothing_to_do(tmp_path: Path) -> None:
    old, new = _passphrases(tmp_path)

    outcome = relock_key_file(tmp_path / "missing.age", old, new)

    assert outcome.problem is None
    assert outcome.rekeyed


def test_relock_of_a_file_neither_passphrase_opens_is_reported(tmp_path: Path) -> None:
    old, new = _passphrases(tmp_path)
    third = _passphrase(tmp_path / "third", "check.age", THIRD)
    path = _store(tmp_path, third)  # locked under a third passphrase

    outcome = relock_key_file(path, old, new)

    assert outcome.problem == KEY_LOCKED_ELSEWHERE
    assert not outcome.rekeyed


def test_relock_of_a_file_already_under_the_new_passphrase_is_done(tmp_path: Path) -> None:
    old, new = _passphrases(tmp_path)
    path = _store(tmp_path, new)

    outcome = relock_key_file(path, old, new)

    assert outcome.problem is None
    assert outcome.rekeyed
    assert unlock_key_file(path, new) is not None


def test_remove_deletes_the_file_and_tolerates_absence(tmp_path: Path) -> None:
    old, _ = _passphrases(tmp_path)
    path = _store(tmp_path, old)

    remove_key_file(path)

    assert not path.exists()
    remove_key_file(path)  # missing_ok
    assert not path.exists()
