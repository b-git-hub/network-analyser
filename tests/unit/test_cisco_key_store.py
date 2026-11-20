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
    lock_key_file,
    relock_key_file,
    remove_key_file,
    unlock_key_file,
)
from network_analyser.credentials import Secret
from tests.support import fake_age

OLD = "CANARY-pp-0ld1-current"
NEW = "CANARY-pp-n3w2-rotated"
CLIENT_ID = "CANARY-client-id-103a"
CLIENT_SECRET = "CANARY-client-secret-103a"
SET_AT = datetime(2026, 11, 20, 12, 34, 56, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _fake(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


def _passphrases(tmp_path: Path) -> tuple[backup_store.BackupPassphrase, backup_store.BackupPassphrase]:
    old = backup_store.create_check_file(tmp_path / "check.age", Secret(OLD))
    new = backup_store.create_check_file(tmp_path / "new.age", Secret(NEW))
    return old, new


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
    _, other = _passphrases(tmp_path / "other")
    path = _store(tmp_path, other)  # locked under a third passphrase

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
