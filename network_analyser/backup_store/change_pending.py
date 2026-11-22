"""The state of a change of the Backup Passphrase (`change-passphrase`, ticket #58; #22).

Three files in the per-user data folder say how far a change has gone:

- the **check file**, which the current Backup Passphrase unlocks (ADR 0004);
- the **previous check file**, a copy of the check file from before the change;
- the **change-pending marker**, `change-pending.json`: the change's start time and the files
  already re-locked, with each one's fingerprint (SHA-256 of the locked file) before and
  after. It holds no secret. A Run is refused while it is there (story 112).

A change starts in this order, each step written to a temporary name, flushed and renamed
into place, so a crash between two steps always leaves a state the next run recognises:

1. the check file is copied to the previous check file (a leftover copy from an earlier
   change is replaced: with no marker it means nothing);
2. the marker is written;
3. the check file is replaced by one locked with the new passphrase.

So: no marker means no change is pending (`ChangeStage.NONE`). A marker with the previous
check file missing or still the same as the check file means the new passphrase was never
saved, and no file has been re-locked yet (`CHOOSING`): the operator chooses it again. A
marker with a different previous check file means the check file holds the new passphrase
(`SWITCHED`): the old one is checked against the previous check file, the new one against
the check file, and files already re-locked are skipped (story 111).

When every file is done, the marker is removed first and then the previous check file, so a
crash between the two leaves only a stale copy, which the next change replaces. These two
are the tool's own bookkeeping files, never a Run folder or a Backup (story 104).
"""

import json
import os
import secrets
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Final

from network_analyser._winsys import retry_rename
from network_analyser.backup_store.check_file import (
    BackupPassphrase,
    CheckFileError,
    renew_check_file,
)
from network_analyser.credentials import Secret, SecretScan

MARKER_FORMAT: Final = 1
_READ_AT_MOST: Final = 64 * 1024 * 1024  # a marker for many thousand files is a few MiB

if sys.platform == "win32":
    _NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY
else:
    _NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL


@dataclass(frozen=True, slots=True)
class PassphraseFiles:
    """The per-user files that say which passphrase is current, and how far a change is.

    Attributes:
        check_file: the check file, locked with the current Backup Passphrase (#45); mid-
            change, the new one.
        previous_check_file: while a change is pending, the old passphrase's check file.
        change_pending: the marker an unfinished `change-passphrase` leaves (#58).
    """

    check_file: Path
    previous_check_file: Path
    change_pending: Path


class ChangeStage(Enum):
    """How far a change of the Backup Passphrase has gone."""

    NONE = "no change is pending"
    CHOOSING = "a change was started, but the new passphrase was never saved"
    SWITCHED = "a change is under way: the check file holds the new passphrase"


@dataclass(frozen=True, slots=True)
class ChangeStatus:
    """What `change-passphrase` finds before it asks for any passphrase."""

    stage: ChangeStage
    old_check_file: Path
    """The check file the current (old) passphrase must unlock."""
    done: int
    """How many files the marker says are already re-locked."""


@dataclass(frozen=True, slots=True)
class Fingerprints:
    """SHA-256 of a locked file before and after it was re-locked."""

    before: str | None
    """None when the file was re-locked by a run that was interrupted before saying so."""
    after: str


def change_status(files: PassphraseFiles) -> ChangeStatus:
    """Say how far a change has gone (see the module's notes).

    Raises:
        CheckFileError: there is no check file, so no Backup Passphrase has been set; or a
            check file cannot be read.
    """
    if not files.check_file.exists():
        msg = "no Backup Passphrase has been set yet: the first Run sets it"
        raise CheckFileError(msg)
    if not files.change_pending.exists():
        return ChangeStatus(ChangeStage.NONE, files.check_file, 0)
    if not _switched(files):
        return ChangeStatus(ChangeStage.CHOOSING, files.check_file, 0)
    _, done = _read_marker(files.change_pending)
    return ChangeStatus(ChangeStage.SWITCHED, files.previous_check_file, len(done))


def _switched(files: PassphraseFiles) -> bool:
    if not files.previous_check_file.exists():
        return False
    return _read_check(files.previous_check_file) != _read_check(files.check_file)


def _read_check(path: Path) -> bytes:
    try:
        with path.open("rb") as file:
            return file.read(_READ_AT_MOST)
    except OSError as error:
        msg = "a check file cannot be read"
        raise CheckFileError(msg) from error


class PendingChange:
    """The change under way: its start time and the files already re-locked (the marker)."""

    def __init__(
        self,
        marker: Path,
        *,
        started_at: datetime,
        done: dict[str, Fingerprints],
        scan: SecretScan,
    ) -> None:
        """Hold the marker's contents; `mark_done` keeps the file in step."""
        self._marker = marker
        self._started_at = started_at
        self._done = done
        self._scan = scan

    @property
    def started_at(self) -> datetime:
        """When the change started (UTC): it names each Run folder's re-lock record."""
        return self._started_at

    def done(self, path: str) -> Fingerprints | None:
        """Return the fingerprints of a file already re-locked, or None if it is not done."""
        return self._done.get(path)

    def mark_done(self, path: str, fingerprints: Fingerprints) -> None:
        """Record that the file at `path` is re-locked, in memory and in the marker.

        A path that holds a typed secret is not written to the marker: a rerun then finds
        the file opens with the new passphrase and counts it done all the same. If the
        marker cannot be written, the next file's write tries again; meanwhile a rerun
        finds the file done the same way.
        """
        if self._scan.holds_secret(path):
            return
        self._done[path] = fingerprints
        try:
            _write_marker(self._marker, self._started_at, self._done)
        except OSError:
            return  # a lagging marker costs a rerun one unlock per file, nothing more


def start_change(
    files: PassphraseFiles,
    old: BackupPassphrase,
    new: Secret,
    *,
    scan: SecretScan,
    now: datetime,
) -> tuple[BackupPassphrase, PendingChange]:
    """Start a change (stage NONE or CHOOSING): keep the old check file, then switch.

    Args:
        files: the check file, the previous check file and the marker.
        old: the current passphrase, already checked against the check file.
        new: the new passphrase, typed twice, at least 15 characters.
        scan: the command's secret scan: paths holding a typed secret stay out of the marker.
        now: the change's start time (UTC).

    Raises:
        ValueError: the new passphrase is too short or the same as the old one.
        OSError: a file could not be written; the change can be started again.
    """
    if old.same_as(new):
        msg = "the new Backup Passphrase must differ from the current one"
        raise ValueError(msg)
    _write_replacing(files.previous_check_file, _read_check(files.check_file))
    _write_marker(files.change_pending, now, {})
    passphrase = renew_check_file(files.check_file, new)
    return passphrase, PendingChange(files.change_pending, started_at=now, done={}, scan=scan)


def resume_change(files: PassphraseFiles, *, scan: SecretScan, now: datetime) -> PendingChange:
    """Pick up a change in stage SWITCHED from its marker.

    A marker that cannot be read as one still means a change is pending: its start time
    becomes `now` and every file is checked again (a file already re-locked opens with the
    new passphrase and is counted done).
    """
    started_at, done = _read_marker(files.change_pending)
    return PendingChange(files.change_pending, started_at=started_at or now, done=done, scan=scan)


def finish_change(files: PassphraseFiles) -> None:
    """End the change: remove the marker, then the previous check file (story 111)."""
    files.change_pending.unlink(missing_ok=True)
    files.previous_check_file.unlink(missing_ok=True)


# -- The marker ---------------------------------------------------------------------------


def _write_marker(marker: Path, started_at: datetime, done: dict[str, Fingerprints]) -> None:
    document = {
        "format_version": MARKER_FORMAT,
        "started_at": _utc_text(started_at),
        "done": {path: {"before": f.before, "after": f.after} for path, f in done.items()},
    }
    _write_replacing(marker, json.dumps(document, ensure_ascii=True, indent=1).encode("ascii"))


def _read_marker(marker: Path) -> tuple[datetime | None, dict[str, Fingerprints]]:
    """Return the marker's start time and done files; what cannot be read is left out."""
    try:
        with marker.open("rb") as file:
            document: object = json.loads(file.read(_READ_AT_MOST))
    except OSError, ValueError:
        return None, {}
    if not isinstance(document, dict):
        return None, {}
    return _started_at(document.get("started_at")), _done(document.get("done"))


def _started_at(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def _done(value: object) -> dict[str, Fingerprints]:
    if not isinstance(value, dict):
        return {}
    done: dict[str, Fingerprints] = {}
    for path, entry in value.items():
        if not (isinstance(path, str) and isinstance(entry, dict)):
            continue
        before, after = entry.get("before"), entry.get("after")
        if isinstance(after, str) and (before is None or isinstance(before, str)):
            done[path] = Fingerprints(before, after)
    return done


def _utc_text(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_replacing(path: Path, data: bytes) -> None:
    """Write `data` to a temporary name beside `path`, flush it, then rename it over `path`.

    Only the tool's own bookkeeping goes through here: the marker (paths and fingerprints)
    and the copy of the check file (age ciphertext of a fixed phrase).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
    handle = os.open(temporary, _NEW_FILE, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(handle, view) :]
        os.fsync(handle)
    finally:
        os.close(handle)
    retry_rename(lambda: temporary.replace(path))
