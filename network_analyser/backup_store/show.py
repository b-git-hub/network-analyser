"""Opening a Backup for `show-backup`, in memory only (ticket #57; stories 102 and 112).

Decided on #12 and #22 and ADR 0004. A Backup is read as ciphertext, unlocked in memory
with the passphrase the operator typed, and its config handed back to the cli, which prints
it to the console. Nothing here writes a file, so no plaintext config ever reaches disk.

When a Backup does not open, the check files tell why, without reading any exception text:
- the passphrase unlocks the check file, and no change is pending: the Backup is damaged,
  or was locked under another passphrase (for example before a manual reset);
- a `change-passphrase` is unfinished (story 112): the passphrase unlocks the new check
  file, so this Backup is probably still under the old passphrase; or it unlocks the
  previous check file, so this Backup is probably already re-locked under the new one;
- it unlocks neither: the passphrase is wrong.

The passphrase is revealed only for the call into age, as when locking (`check_file`).
"""

from dataclasses import dataclass
from enum import Enum, unique
from pathlib import Path
from typing import Final

from network_analyser.backup_store import check_file
from network_analyser.backup_store.change_pending import PassphraseFiles
from network_analyser.backup_store.check_file import CheckFileError, change_is_pending
from network_analyser.backup_store.locker import BACKUP_SUFFIX, BACKUPS_FOLDER, scrypt_level
from network_analyser.credentials import Secret

READ_AT_MOST: Final = 16 * 1024 * 1024
"""A Backup is at most a 1,000,000-character config (the gateway's cap) plus age's framing."""


@unique
class Unopened(Enum):
    """Why a Backup was not shown. Each value is fixed text, safe to print."""

    UNREADABLE = "the file cannot be read"
    TOO_BIG = "the file is too big to be a Backup"
    NOT_A_BACKUP = "it is not a Backup: not an age file locked with a passphrase"
    UNLOCKS_NOTHING = (
        "that passphrase does not open it, and it is not the Backup Passphrase: it does not "
        "unlock the check file"
    )
    NO_CHECK_FILE = (
        "that passphrase does not open it. There is no check file here to tell a wrong "
        "passphrase from a damaged file"
    )
    DAMAGED = (
        "it does not open with the Backup Passphrase, though that passphrase unlocks the "
        "check file. The file is damaged, or was locked under another passphrase"
    )
    STILL_UNDER_OLD = (
        "it does not open with that passphrase, which is the new one. A change of the Backup "
        "Passphrase is unfinished, so this Backup is probably still under the old passphrase"
    )
    ALREADY_UNDER_NEW = (
        "it does not open with that passphrase, which is the old one. A change of the Backup "
        "Passphrase is unfinished, so this Backup is probably already under the new passphrase"
    )


@dataclass(frozen=True, slots=True)
class LockedBackup:
    """A Backup file's ciphertext, read and checked to be an age passphrase file."""

    locked: bytes


def load_backup(path: Path) -> LockedBackup | Unopened:
    """Read the Backup at `path` (in the form file calls take); no passphrase needed yet."""
    try:
        with path.open("rb") as file:
            locked = file.read(READ_AT_MOST + 1)
    except OSError:
        return Unopened.UNREADABLE
    if len(locked) > READ_AT_MOST:
        return Unopened.TOO_BIG
    try:
        scrypt_level(locked)
    except ValueError:
        return Unopened.NOT_A_BACKUP
    return LockedBackup(locked)


def open_backup(backup: LockedBackup, passphrase: Secret, files: PassphraseFiles) -> str | Unopened:
    """Return the Backup's config, unlocked in memory with `passphrase`, or why it was not.

    The config is exactly what was locked (story 93). Bytes that are not UTF-8 come back as
    backslash escapes; the cli escapes control characters before it prints.
    """
    plaintext = _unlock(backup.locked, passphrase)
    if plaintext is not None:
        return plaintext.decode("utf-8", errors="backslashreplace")
    pending = change_is_pending(files.change_pending)
    if _unlocks(files.check_file, passphrase):
        return Unopened.STILL_UNDER_OLD if pending else Unopened.DAMAGED
    if pending and _unlocks(files.previous_check_file, passphrase):
        return Unopened.ALREADY_UNDER_NEW
    if not files.check_file.exists():
        return Unopened.NO_CHECK_FILE
    return Unopened.UNLOCKS_NOTHING


def backup_files(run_folder: Path) -> tuple[Path, ...] | None:
    """Return the Backups in a Run folder, by name; None when the folder is not there.

    Only finished Backups are listed: a temporary file, the manifest and anything else in
    the folder are left out.
    """
    if not run_folder.is_dir():
        return None
    backups = run_folder / BACKUPS_FOLDER
    if not backups.is_dir():
        return ()
    found = (p for p in backups.iterdir() if p.name.endswith(BACKUP_SUFFIX) and p.is_file())
    return tuple(sorted(found, key=lambda p: p.name))


def _unlock(locked: bytes, passphrase: Secret) -> bytes | None:
    try:
        return check_file.AGE.unlock(locked, passphrase.reveal())
    except CheckFileError:  # not an age file: load_backup has already ruled that out
        return None


def _unlocks(path: Path, passphrase: Secret) -> bool:
    if not path.is_file():
        return False
    try:
        return check_file.unlock_check_file(path, passphrase) is not None
    except CheckFileError:  # a damaged check file cannot tell anything
        return False
