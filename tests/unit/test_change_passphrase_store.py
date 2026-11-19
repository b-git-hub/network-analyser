"""Changing the Backup Passphrase, at `backup_store` (ticket #58; stories 106-116; #22, #27).

Driven through `backup_store`'s change API: the change's status, starting or resuming it,
planning which files to re-lock, re-locking one Run folder at a time, and finishing. The
Run folders are made by the real `BackupLocker`; the fast fake age stands in for scrypt.
"""

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from network_analyser import backup_store
from network_analyser.backup_store import (
    BackupPassphrase,
    ChangeStage,
    FileOutcome,
    PassphraseFiles,
    Relocker,
)
from network_analyser.credentials import Secret, SecretScan
from tests.support import fake_age
from tests.support.run_folders import make_run_folder

OLD = "CANARY-pp-0ld1-current"
NEW = "CANARY-pp-n3w2-rotated"
STARTED = datetime(2026, 11, 19, 9, 30, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _fake(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Store:
    """A per-user data folder with a check file, and Run folders with locked Backups."""

    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path
        data = tmp_path / "NetworkAnalyser"
        self.files = PassphraseFiles(
            check_file=data / "passphrase-check.age",
            previous_check_file=data / "passphrase-check.previous.age",
            change_pending=data / "change-pending.json",
        )
        self.old = backup_store.create_check_file(self.files.check_file, Secret(OLD))
        self.scan = SecretScan()

    def run_folder(self, name: str, *hostnames: str) -> Path:
        return make_run_folder(self.root / "runs" / name, self.old, *hostnames)

    def start(self) -> tuple[BackupPassphrase, backup_store.PendingChange]:
        return backup_store.start_change(
            self.files, self.old, Secret(NEW), scan=self.scan, now=STARTED
        )

    def relocker(self, new: BackupPassphrase, pending: backup_store.PendingChange) -> Relocker:
        return Relocker(
            old=self.old, new=new, pending=pending, scan=self.scan, tool_version="0.2.0"
        )


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path)


def _opens_with(path: Path, passphrase: str) -> bytes | None:
    return fake_age.unlock(path.read_bytes(), passphrase)


def _every_file(root: Path) -> Iterator[Path]:
    return (p for p in root.rglob("*") if p.is_file())


# -- Re-locking a Run folder (stories 106, 110, 114) ------------------------------------------


def test_every_backup_and_the_manifest_are_relocked_in_place_under_the_new_passphrase(
    store: Store,
) -> None:
    folder = store.run_folder("20261118T101530Z", "sw-a", "sw-b")
    backups = folder / "backups"
    before = {p.name: p.read_bytes() for p in backups.iterdir()}
    new, pending = store.start()

    plan = backup_store.plan_relock([folder])
    (run,) = plan.runs
    result = store.relocker(new, pending).relock_run(run)

    assert result is not None
    assert {p.name for p in backups.iterdir()} == set(before)
    for name, old_bytes in before.items():
        assert _opens_with(backups / name, OLD) is None
        assert _opens_with(backups / name, NEW) is not None
        if name.endswith(".cfg.age"):  # the manifest's fingerprints change, a config never
            assert _opens_with(backups / name, NEW) == fake_age.unlock(old_bytes, OLD)
    outcomes = {Path(f.path).name: f for f in result.files}
    assert set(outcomes) == set(before)
    for name, outcome in outcomes.items():
        assert outcome.outcome is FileOutcome.RELOCKED
        assert outcome.before == _sha(before[name])
        assert outcome.after == _sha((backups / name).read_bytes())
        assert outcome.flag is None


def test_the_manifest_gets_the_new_fingerprints_and_keeps_the_config_fingerprints(
    store: Store,
) -> None:
    folder = store.run_folder("20261118T101530Z", "sw-a")
    manifest = folder / "backups" / "manifest.age"
    old_document = json.loads(_opens_with(manifest, OLD) or b"")
    new, pending = store.start()

    (run,) = backup_store.plan_relock([folder]).runs
    store.relocker(new, pending).relock_run(run)

    document = json.loads(_opens_with(manifest, NEW) or b"")
    (entry,) = document["backups"]
    (old_entry,) = old_document["backups"]
    backup = folder / "backups" / entry["file"]
    assert entry["ciphertext_sha256"] == _sha(backup.read_bytes())
    assert entry["plaintext_sha256"] == old_entry["plaintext_sha256"]
    assert {k: v for k, v in entry.items() if k != "ciphertext_sha256"} == {
        k: v for k, v in old_entry.items() if k != "ciphertext_sha256"
    }


def test_each_relocked_run_folder_gets_a_relock_record_with_fingerprints(store: Store) -> None:
    folder = store.run_folder("20261118T101530Z", "sw-a")
    backup = folder / "backups" / "sw-a__TEST0001.cfg.age"
    before = _sha(backup.read_bytes())
    new, pending = store.start()

    (run,) = backup_store.plan_relock([folder]).runs
    result = store.relocker(new, pending).relock_run(run)

    record = folder / "relock-20261119T093000Z.txt"
    assert result is not None
    assert result.record == record
    text = record.read_text(encoding="ascii")
    assert "backups/sw-a__TEST0001.cfg.age" in text
    assert f"before: {before}" in text
    assert f"after:  {_sha(backup.read_bytes())}" in text
    assert "backups/manifest.age" in text
    assert "0.2.0" in text
    assert "2026-11-19T09:30:00Z" in text


# -- Finding the files (story 107) ------------------------------------------------------------


def test_a_folder_that_is_not_there_is_listed_as_not_found(store: Store) -> None:
    found = store.run_folder("20261118T101530Z", "sw-a")
    gone = store.root / "runs" / "20261117T080000Z"
    empty = store.root / "runs" / "20261116T080000Z"
    empty.mkdir(parents=True)

    plan = backup_store.plan_relock([gone, found, empty, found])

    assert plan.not_found == (gone,)
    assert [run.folder for run in plan.runs] == [found, empty]
    assert plan.backups == 1
    assert plan.files == 2
    assert plan.runs_with_files == 1


# -- Files that will not re-lock cleanly (story 113) ------------------------------------------


def test_a_file_that_will_not_open_with_the_old_passphrase_is_skipped_and_recorded(
    store: Store,
) -> None:
    folder = store.run_folder("20261118T101530Z", "sw-a", "sw-b")
    damaged = folder / "backups" / "sw-b__TEST0002.cfg.age"
    damaged.write_bytes(b"age-encryption.org/v1\nnot really\n")
    new, pending = store.start()

    (run,) = backup_store.plan_relock([folder]).runs
    result = store.relocker(new, pending).relock_run(run)

    assert result is not None
    outcomes = {Path(f.path).name: f for f in result.files}
    skipped = outcomes["sw-b__TEST0002.cfg.age"]
    assert skipped.outcome is FileOutcome.SKIPPED
    assert skipped.problem is not None
    assert "does not open with the old passphrase" in skipped.problem
    assert damaged.read_bytes() == b"age-encryption.org/v1\nnot really\n"
    assert outcomes["sw-a__TEST0001.cfg.age"].outcome is FileOutcome.RELOCKED
    record = (folder / "relock-20261119T093000Z.txt").read_text(encoding="ascii")
    assert "backups/sw-b__TEST0002.cfg.age\n  not re-locked: it does not open" in record


def test_a_backup_that_does_not_match_its_manifest_is_relocked_unchanged_and_flagged(
    store: Store,
) -> None:
    folder = store.run_folder("20261118T101530Z", "sw-a")
    backup = folder / "backups" / "sw-a__TEST0001.cfg.age"
    changed = b"hostname sw-a\n! changed after it was taken\n"
    backup.write_bytes(fake_age.lock(changed, OLD))
    stray = folder / "backups" / "stray.cfg.age"
    stray.write_bytes(fake_age.lock(b"hostname stray\n", OLD))
    new, pending = store.start()

    (run,) = backup_store.plan_relock([folder]).runs
    result = store.relocker(new, pending).relock_run(run)

    assert result is not None
    outcomes = {Path(f.path).name: f for f in result.files}
    assert outcomes["sw-a__TEST0001.cfg.age"].outcome is FileOutcome.RELOCKED
    assert outcomes["sw-a__TEST0001.cfg.age"].flag == "content does not match its manifest"
    assert outcomes["stray.cfg.age"].flag == "not listed in its manifest"
    assert _opens_with(backup, NEW) == changed
    record = (folder / "relock-20261119T093000Z.txt").read_text(encoding="ascii")
    assert "flagged: content does not match its manifest" in record


# -- Stages, resuming and finishing (stories 111-112) -----------------------------------------


def test_starting_a_change_keeps_the_old_check_file_and_marks_the_change_pending(
    store: Store,
) -> None:
    old_check = store.files.check_file.read_bytes()
    assert backup_store.change_status(store.files).stage is ChangeStage.NONE

    new, _ = store.start()

    assert store.files.previous_check_file.read_bytes() == old_check
    assert backup_store.change_is_pending(store.files.change_pending)
    assert backup_store.unlock_check_file(store.files.check_file, Secret(NEW)) is not None
    assert new.same_as(Secret(NEW))
    status = backup_store.change_status(store.files)
    assert status.stage is ChangeStage.SWITCHED
    assert status.old_check_file == store.files.previous_check_file
    assert OLD not in store.files.change_pending.read_text(encoding="ascii")
    assert NEW not in store.files.change_pending.read_text(encoding="ascii")


def test_the_new_passphrase_must_differ_from_the_current_one(store: Store) -> None:
    with pytest.raises(ValueError, match="differ"):
        backup_store.start_change(store.files, store.old, Secret(OLD), scan=store.scan, now=STARTED)

    assert not store.files.change_pending.exists()


def test_a_marker_left_before_the_new_check_file_was_saved_means_choose_again(
    store: Store,
) -> None:
    store.files.previous_check_file.write_bytes(store.files.check_file.read_bytes())
    store.files.change_pending.write_text("{}", encoding="ascii")

    status = backup_store.change_status(store.files)

    assert status.stage is ChangeStage.CHOOSING
    assert status.old_check_file == store.files.check_file


def test_a_stale_previous_check_file_without_a_marker_is_ignored_and_replaced(
    store: Store,
) -> None:
    store.files.previous_check_file.write_bytes(fake_age.lock(b"older\n", "CANARY-pp-older-xxxx"))

    assert backup_store.change_status(store.files).stage is ChangeStage.NONE
    store.start()

    assert _opens_with(store.files.previous_check_file, OLD) is not None


def test_no_check_file_means_there_is_no_passphrase_to_change(tmp_path: Path) -> None:
    files = PassphraseFiles(tmp_path / "c.age", tmp_path / "p.age", tmp_path / "m.json")

    with pytest.raises(backup_store.CheckFileError):
        backup_store.change_status(files)


def test_a_rerun_resumes_and_skips_files_already_done(store: Store) -> None:
    folder = store.run_folder("20261118T101530Z", "sw-a", "sw-b", "sw-c")
    new, pending = store.start()
    (run,) = backup_store.plan_relock([folder]).runs
    asked: list[int] = []

    def stop_after_two() -> bool:
        asked.append(1)
        return len(asked) > 2

    assert store.relocker(new, pending).relock_run(run, stop=stop_after_two) is None
    assert not (folder / "relock-20261119T093000Z.txt").exists()
    status = backup_store.change_status(store.files)
    assert status.stage is ChangeStage.SWITCHED
    assert status.done == 2

    resumed = backup_store.resume_change(store.files, scan=store.scan, now=datetime.now(UTC))
    result = store.relocker(new, resumed).relock_run(run)

    assert result is not None
    outcomes = [f.outcome for f in result.files]
    assert outcomes == [
        FileOutcome.DONE_EARLIER,
        FileOutcome.DONE_EARLIER,
        FileOutcome.RELOCKED,
        FileOutcome.RELOCKED,
    ]
    assert all(f.before is not None and f.after is not None for f in result.files)
    for path in (folder / "backups").iterdir():
        assert _opens_with(path, NEW) is not None
    manifest = json.loads(_opens_with(folder / "backups" / "manifest.age", NEW) or b"")
    for entry in manifest["backups"]:
        assert entry["ciphertext_sha256"] == _sha((folder / "backups" / entry["file"]).read_bytes())
    assert (folder / "relock-20261119T093000Z.txt").exists()


def test_a_file_relocked_just_before_a_crash_is_counted_done(store: Store) -> None:
    folder = store.run_folder("20261118T101530Z", "sw-a")
    new, _ = store.start()
    backup = folder / "backups" / "sw-a__TEST0001.cfg.age"
    backup.write_bytes(fake_age.lock(_opens_with(backup, OLD) or b"", NEW))  # marker missed it

    resumed = backup_store.resume_change(store.files, scan=store.scan, now=STARTED)
    (run,) = backup_store.plan_relock([folder]).runs
    result = store.relocker(new, resumed).relock_run(run)

    assert result is not None
    first = result.files[0]
    assert first.outcome is FileOutcome.DONE_EARLIER
    assert first.before is None
    assert first.after == _sha(backup.read_bytes())


def test_finishing_removes_the_marker_and_the_previous_check_file(store: Store) -> None:
    store.start()

    backup_store.finish_change(store.files)

    assert not store.files.change_pending.exists()
    assert not store.files.previous_check_file.exists()
    assert store.files.check_file.exists()
    assert backup_store.change_status(store.files).stage is ChangeStage.NONE
