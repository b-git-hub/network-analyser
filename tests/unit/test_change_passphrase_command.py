"""`network-analyser change-passphrase` (ticket #58; spec #37 stories 106-116; #22, #27).

Driven through `cli.main` with what the operator types on stdin. Standard input is not a
console in tests, so each prompt reads one line; on Linux the crash-dump guard always asks
for `YES`. Run folders are made by the real `BackupLocker` and registered as a Run would;
the fast fake age stands in for scrypt.
"""

import io
import os
import signal
from dataclasses import dataclass
from pathlib import Path

import pytest

from network_analyser import backup_store, run_output
from network_analyser.cli import main
from network_analyser.credentials import Secret, SecretScan
from tests.support import fake_age
from tests.support.run_driver import Runner, data_folder, later_run, typed
from tests.support.run_folders import make_run_folder

OLD = "CANARY-pp-0ld1-current"
NEW = "CANARY-pp-n3w2-rotated"


@dataclass(frozen=True)
class Outcome:
    code: int
    out: str
    err: str


@pytest.fixture(autouse=True)
def _fake(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


class Operator:
    """The operator's per-user data folder, Run folders, and the command itself."""

    def __init__(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self.data = data_folder()
        self.runs = tmp_path / "runs"
        self._monkeypatch = monkeypatch
        self._capsys = capsys
        self.old = backup_store.create_check_file(self.data.check_file, Secret(OLD))

    def run_folder(self, name: str, *hostnames: str, register: bool = True) -> Path:
        return make_run_folder(
            self.runs / name,
            self.old,
            *hostnames,
            register=self.data.run_register if register else None,
        )

    def __call__(self, *argv: str, typed: str = "") -> Outcome:
        self._monkeypatch.setattr("sys.stdin", io.StringIO(typed))
        code = main(["change-passphrase", *argv])
        captured = self._capsys.readouterr()
        return Outcome(code, captured.out, captured.err)


@pytest.fixture
def operator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Operator:
    return Operator(tmp_path, monkeypatch, capsys)


def _change(*, start: str = "y") -> str:
    return typed("YES", OLD, NEW, NEW, start)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _locked_files(folder: Path) -> list[Path]:
    return sorted((folder / "backups").glob("*.age"))


def _all_open_with(folder: Path, passphrase: str) -> bool:
    return all(
        fake_age.unlock(p.read_bytes(), passphrase) is not None for p in _locked_files(folder)
    )


# -- The whole change (stories 106-110, 114-115) ----------------------------------------------


def test_every_registered_backup_is_relocked_and_the_change_finishes(operator: Operator) -> None:
    first = operator.run_folder("20261117T080000Z", "sw-a", "sw-b")
    second = operator.run_folder("20261118T101530Z_dc1", "sw-c")

    got = operator(typed=_change())

    assert got.code == 0, got.err
    assert _all_open_with(first, NEW)
    assert _all_open_with(second, NEW)
    assert backup_store.unlock_check_file(operator.data.check_file, Secret(NEW)) is not None
    assert not operator.data.change_pending.exists()
    assert not operator.data.previous_check_file.exists()
    assert (first / "relock-").parent.exists()
    assert len(list(first.glob("relock-*.txt"))) == 1
    assert len(list(second.glob("relock-*.txt"))) == 1
    assert "Re-locked 3 Backups in 2 Runs" in got.out
    assert OLD not in got.out + got.err
    assert NEW not in got.out + got.err


def test_the_summary_before_the_confirm_counts_files_and_estimates_3_s_each(
    operator: Operator,
) -> None:
    operator.run_folder("20261117T080000Z", "sw-a", "sw-b")
    gone = operator.runs / "20261116T080000Z"
    backup_store.register_run_folder(operator.data.run_register, gone, scan=SecretScan())

    got = operator(typed=_change(start="n"))

    assert got.code == 3
    assert "2 Backups" in got.err
    assert "1 Run" in got.err
    assert "Not found: 1 Run folder" in got.err
    assert str(gone) in got.err
    assert "about 9 s (3 s per file, 3 files)" in got.err
    assert "Nothing was changed." in got.err
    assert not operator.data.change_pending.exists()
    assert backup_store.unlock_check_file(operator.data.check_file, Secret(OLD)) is not None


def test_the_end_says_what_rotation_cannot_fix(operator: Operator) -> None:
    operator.run_folder("20261117T080000Z", "sw-a")

    got = operator(typed=_change())

    for words in (
        "Previous Versions",
        "sync history",
        "PC backups",
        "stay locked with the old passphrase",
        "does not wipe the old file contents",
        "treat the secrets in these configs as exposed",
    ):
        assert words in _flat(got.out)


# -- --run-folder (story 107) -----------------------------------------------------------------


def test_run_folder_adds_a_moved_folder_and_registers_it(operator: Operator) -> None:
    moved = operator.run_folder("20261117T080000Z", "sw-a", register=False)

    got = operator("--run-folder", str(moved), typed=_change())

    assert got.code == 0, got.err
    assert _all_open_with(moved, NEW)
    assert moved in backup_store.registered_run_folders(operator.data.run_register)


def test_a_folder_not_found_is_listed_and_needs_attention(operator: Operator) -> None:
    operator.run_folder("20261117T080000Z", "sw-a")
    gone = operator.runs / "gone"

    got = operator("--run-folder", str(gone), typed=_change())

    assert got.code == 1
    assert str(gone) in got.out
    assert not operator.data.change_pending.exists()


# -- Passphrases (story 109) ------------------------------------------------------------------


def test_a_wrong_current_passphrase_three_times_refuses_and_changes_nothing(
    operator: Operator,
) -> None:
    folder = operator.run_folder("20261117T080000Z", "sw-a")
    wrong = "CANARY-pp-wrong-xxxxxx"

    got = operator(typed=typed("YES", wrong, wrong, wrong))

    assert got.code == 2
    assert "--help" in got.err
    assert _all_open_with(folder, OLD)
    assert not operator.data.change_pending.exists()


@pytest.mark.parametrize(
    ("entries", "reason"),
    [
        (("CANARY-short", "CANARY-short"), "at least 15 characters"),
        ((OLD, OLD), "the same as the current one"),
        ((NEW, "CANARY-pp-n3w2-typo00"), "differ"),
    ],
)
def test_the_new_passphrase_is_asked_again_until_it_is_acceptable(
    operator: Operator, entries: tuple[str, str], reason: str
) -> None:
    folder = operator.run_folder("20261117T080000Z", "sw-a")

    got = operator(typed=typed("YES", OLD, *entries, NEW, NEW, "y"))

    assert got.code == 0, got.err
    assert reason in got.err
    assert _all_open_with(folder, NEW)


def test_declining_the_crash_dump_check_asks_for_no_passphrase(operator: Operator) -> None:
    got = operator(typed=typed("no"))

    assert got.code == 2
    assert "Current Backup Passphrase" not in got.err


def test_with_no_check_file_there_is_nothing_to_change(operator: Operator) -> None:
    operator.data.check_file.unlink()

    got = operator(typed=_change())

    assert got.code == 2
    assert "first Run sets it" in got.err


def test_the_help_documents_the_manual_reset_for_a_forgotten_passphrase(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["change-passphrase", "--help"]) == 0

    out = capsys.readouterr().out
    assert "delete the check file" in out
    assert "passphrase-check.age" in out
    assert "no reset command" in out


# -- Interrupted and resumed (stories 111-112) ------------------------------------------------


def _ctrl_c_on_lock(monkeypatch: pytest.MonkeyPatch, number: int) -> None:
    """Press Ctrl+C while the `number`th lock with age is under way."""
    fake = fake_age.cipher()
    calls: list[int] = []

    def lock(plaintext: bytes, passphrase: str) -> bytes:
        calls.append(1)
        if len(calls) == number:
            signal.raise_signal(signal.SIGINT)
        return fake.lock(plaintext, passphrase)

    monkeypatch.setattr(
        backup_store.check_file, "AGE", backup_store.check_file.Cipher(lock, fake.unlock)
    )


def test_ctrl_c_finishes_the_current_file_then_stops_and_a_rerun_resumes(
    operator: Operator, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    folder = operator.run_folder("20261117T080000Z", "sw-a", "sw-b", "sw-c")
    _ctrl_c_on_lock(monkeypatch, 2)  # lock 1 is the new check file, lock 2 the first Backup

    stopped = operator(typed=_change())

    assert stopped.code == 3
    assert 'Run "network-analyser change-passphrase" again' in _flat(stopped.err)
    assert operator.data.change_pending.exists()
    files = _locked_files(folder)
    under_new = [p for p in files if fake_age.unlock(p.read_bytes(), NEW) is not None]
    assert len(under_new) == 1
    refused = Runner(monkeypatch, capsys)(*("--scope", "192.0.2.0/24"), typed=later_run())
    assert refused.code == 2
    assert "change-passphrase" in refused.err

    fake_age.use_fake_age(monkeypatch)
    resumed = operator(typed=typed("YES", OLD, NEW, "y"))

    assert resumed.code == 0, resumed.err
    assert "1 file already re-locked" in resumed.err
    assert _all_open_with(folder, NEW)
    assert not operator.data.change_pending.exists()


def test_while_a_change_is_pending_another_cannot_start_alongside_it(
    operator: Operator,
) -> None:
    lock = run_output.take_instance_lock(operator.data)
    assert lock is not None
    try:
        got = operator(typed=_change())
    finally:
        lock.release()

    assert got.code == 2
    assert "in progress" in got.err


def test_nothing_is_written_with_a_typed_passphrase_in_it(operator: Operator) -> None:
    folder = operator.run_folder("20261117T080000Z", "sw-a")

    operator(typed=_change())

    every = [p for p in Path(os.environ["LOCALAPPDATA"]).rglob("*") if p.is_file()]
    every += [p for p in folder.rglob("*") if p.is_file()]
    for path in every:
        data = path.read_bytes()
        assert OLD.encode() not in data
        assert NEW.encode() not in data
