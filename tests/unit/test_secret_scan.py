import copy
import pickle
from pathlib import Path

import pytest

from network_analyser import backup_store
from network_analyser.credentials import CredentialSet, CredentialSets, Secret, SecretScan
from tests.support import fake_age

CANARY = "CANARY-pw-51ab"
BACKUP_CANARY = "CANARY-pp-77c0-backup"


def _scan(*values: str) -> SecretScan:
    scan = SecretScan()
    for value in values:
        scan.watch(Secret(value))
    return scan


def test_text_without_a_secret_comes_back_unchanged() -> None:
    assert _scan(CANARY).contains_secret("login ok for netops-ro") == (
        "login ok for netops-ro",
        0,
    )


def test_each_match_becomes_blocked_and_is_counted() -> None:
    text = f"a {CANARY} b {BACKUP_CANARY} c {CANARY}"

    assert _scan(CANARY, BACKUP_CANARY).contains_secret(text) == (
        "a [blocked] b [blocked] c [blocked]",
        3,
    )


def test_matching_is_exact_and_case_sensitive() -> None:
    scan = _scan("Cisco123")

    assert scan.contains_secret("cisco123 CISCO123 Cisco12") == ("cisco123 CISCO123 Cisco12", 0)


def test_overlapping_secrets_leave_no_part_of_either_showing() -> None:
    scan = _scan("abcd", "cdef")

    assert scan.contains_secret("x abcdef y") == ("x [blocked] y", 1)


def test_a_secret_inside_another_is_blocked_with_it() -> None:
    scan = _scan("pass", "longpassword")

    assert scan.contains_secret("longpassword pass") == ("[blocked] [blocked]", 2)


def test_repeated_secret_runs_are_blocked_without_leaving_a_tail() -> None:
    assert _scan("aa").contains_secret("aaa") == ("[blocked]", 1)


def test_an_empty_scan_finds_nothing() -> None:
    assert SecretScan().contains_secret("anything") == ("anything", 0)


def test_the_scan_keeps_a_running_total_of_hits() -> None:
    scan = _scan(CANARY)
    scan.contains_secret(CANARY)
    scan.contains_secret(f"{CANARY}{CANARY} and {CANARY}")

    assert scan.hits == 3


def test_credential_sets_add_every_password_to_the_scan() -> None:
    sets = CredentialSets(
        [
            CredentialSet("netops-ro", Secret(CANARY), None),
            CredentialSet("backup-ro", Secret("CANARY-pw-9d2e"), None),
        ]
    )
    scan = SecretScan()
    sets.add_to_scan(scan)

    assert scan.contains_secret(f"{CANARY} CANARY-pw-9d2e netops-ro") == (
        "[blocked] [blocked] netops-ro",
        2,
    )


def test_the_scan_never_shows_what_it_watches() -> None:
    scan = _scan(CANARY)

    assert CANARY not in repr(scan)
    assert CANARY not in str(scan)
    with pytest.raises(TypeError):
        pickle.dumps(scan)
    with pytest.raises(TypeError):
        copy.copy(scan)


def test_the_backup_passphrase_adds_itself_to_the_scan(tmp_path: Path) -> None:
    passphrase = backup_store.create_check_file(
        tmp_path / "check.age", Secret(BACKUP_CANARY), cipher=fake_age.FAKE_AGE
    )
    scan = SecretScan()
    passphrase.add_to_scan(scan)

    assert scan.contains_secret(f"x {BACKUP_CANARY} y") == ("x [blocked] y", 1)


def test_holds_secret_says_whether_text_holds_one_without_counting_a_hit() -> None:
    scan = _scan(CANARY)

    assert scan.holds_secret(f"C:/runs/{CANARY}/x")
    assert not scan.holds_secret("C:/runs/x")
    assert scan.hits == 0
