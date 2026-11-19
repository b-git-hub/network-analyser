"""The Backup check file and the passphrase rules (ADR 0004; spec #37 stories 20-22).

The check file is a small standard age file in the per-user folder, holding a known phrase
locked with the Backup Passphrase. One test uses real age; the rest use the fast fake.
"""

from pathlib import Path

import pytest

from network_analyser.backup_store import (
    PASSPHRASE_MIN,
    BackupPassphrase,
    CheckFileError,
    change_is_pending,
    create_check_file,
    passphrase_problem,
    unlock_check_file,
)
from network_analyser.credentials import Secret
from tests.support import fake_age

CANARY = "CANARY-pp-91d4-long"
OTHER = "CANARY-pp-0000-other"


@pytest.fixture
def check(tmp_path: Path) -> Path:
    return tmp_path / "NetworkAnalyser" / "passphrase-check.age"


def test_a_check_file_is_a_standard_age_file_that_only_its_passphrase_unlocks(
    check: Path,
) -> None:
    created = create_check_file(check, Secret(CANARY))

    locked = check.read_bytes()
    assert locked.startswith(b"age-encryption.org/v1\n-> scrypt ")
    assert CANARY.encode() not in locked
    assert created.same_as(Secret(CANARY))
    assert unlock_check_file(check, Secret(OTHER)) is None
    unlocked = unlock_check_file(check, Secret(CANARY))
    assert unlocked is not None
    assert unlocked.same_as(Secret(CANARY))


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.mark.usefixtures("fake")
def test_an_existing_check_file_is_never_replaced(check: Path) -> None:
    create_check_file(check, Secret(CANARY))
    before = check.read_bytes()

    with pytest.raises(CheckFileError):
        create_check_file(check, Secret(OTHER))

    assert check.read_bytes() == before


@pytest.mark.usefixtures("fake")
def test_a_file_that_unlocks_but_holds_another_phrase_is_not_a_check_file(check: Path) -> None:
    check.parent.mkdir(parents=True)
    check.write_bytes(fake_age.lock(b"something else\n", CANARY))

    with pytest.raises(CheckFileError):
        unlock_check_file(check, Secret(CANARY))


@pytest.mark.usefixtures("fake")
def test_a_check_file_that_cannot_be_read_is_an_error(check: Path) -> None:
    check.mkdir(parents=True)  # a folder where the file should be

    with pytest.raises(CheckFileError):
        unlock_check_file(check, Secret(CANARY))


def test_the_passphrase_is_at_least_15_characters() -> None:
    assert PASSPHRASE_MIN == 15
    assert passphrase_problem(Secret("a" * 15)) is None
    problem = passphrase_problem(Secret("CANARY-pp-123"))
    assert problem == "it must be at least 15 characters"


@pytest.mark.usefixtures("fake")
def test_a_check_file_is_never_made_with_a_short_passphrase(check: Path) -> None:
    with pytest.raises(ValueError, match="15"):
        create_check_file(check, Secret("CANARY-short"))

    assert not check.exists()


@pytest.mark.usefixtures("fake")
def test_the_unlocked_passphrase_never_shows_its_value(check: Path) -> None:
    held = create_check_file(check, Secret(CANARY))

    assert isinstance(held, BackupPassphrase)
    assert CANARY not in repr(held) + str(held) + f"{held}"
    assert "held in memory" in repr(held)
    assert not held.same_as(Secret(OTHER))


def test_a_change_is_pending_while_its_marker_exists(tmp_path: Path) -> None:
    marker = tmp_path / "change-pending.json"
    assert not change_is_pending(marker)

    marker.write_text("{}", encoding="utf-8")

    assert change_is_pending(marker)
