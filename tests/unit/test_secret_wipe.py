"""A Run wipes its device secrets at its end, before Cisco is asked (ADR 0007; #104)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from network_analyser import backup_store
from network_analyser.credentials import CredentialSet, CredentialSets, Secret, SecretScan
from tests.support import fake_age

CANARY = "CANARY-pw-104-w1pe"
PASSPHRASE = "CANARY-pp-104-w1pe"
CLIENT_ID = "CANARY-client-id-104"
CLIENT_SECRET = "CANARY-client-secret-104"


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


def test_a_wiped_secret_has_no_value_and_refuses_to_reveal_one() -> None:
    secret = Secret(CANARY)

    secret.wipe()

    assert secret.wiped
    assert secret.is_empty()
    with pytest.raises(RuntimeError, match="wiped"):
        secret.reveal()


def test_wiping_every_credential_set_wipes_each_password() -> None:
    first = CredentialSet("netops-ro", Secret(CANARY), None)
    sets = CredentialSets([first, CredentialSet("backup-ro", Secret("CANARY-pw-104-two"), None)])

    sets.wipe()

    assert sets.wiped
    assert first.wiped
    with pytest.raises(RuntimeError, match="wiped"):
        first.password_for_login().reveal()


def test_wiping_the_backup_passphrase_refuses_a_later_lock(tmp_path: Path) -> None:
    passphrase = backup_store.create_check_file(
        tmp_path / "check.age", Secret(PASSPHRASE), cipher=fake_age.FAKE_AGE
    )

    passphrase.wipe()

    assert passphrase.wiped
    with pytest.raises(RuntimeError, match="wiped"):
        passphrase.lock(b"plaintext")


def test_the_secret_scan_still_redacts_after_the_secret_is_wiped() -> None:
    secret = Secret(CANARY)
    scan = SecretScan()
    scan.watch(secret)

    secret.wipe()

    assert scan.contains_secret(f"x {CANARY} y") == ("x [blocked] y", 1)
    scan.forget()
    assert scan.contains_secret(f"x {CANARY} y") == (f"x {CANARY} y", 0)
    assert scan.hits == 1  # the count stays, so the Run's one warning still holds


def test_the_cisco_key_wipes_both_of_its_secrets(tmp_path: Path) -> None:
    passphrase = backup_store.create_check_file(
        tmp_path / "check.age", Secret(PASSPHRASE), cipher=fake_age.FAKE_AGE
    )
    backup_store.lock_key_file(
        tmp_path / "cisco-key.age",
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        passphrase,
        set_at=datetime(2026, 11, 21, tzinfo=UTC),
    )
    key = backup_store.unlock_key_file(tmp_path / "cisco-key.age", passphrase)
    assert key is not None

    key.wipe()

    assert key.wiped
    with pytest.raises(RuntimeError, match="wiped"):
        key.client_id.reveal()
