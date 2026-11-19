"""The Backup Passphrase and its check file (ADR 0004; spec #37 stories 20-22; #12, #15).

The check file is a small standard age file in the per-user data folder: a known phrase
locked with the Backup Passphrase. The first Run creates it; every later Run must unlock it
before any Backup is locked, so a typo can never lock new Backups under a passphrase that
differs from the earlier ones. It holds no secret: guessing against it is no easier than
guessing against a Backup. A forgotten passphrase cannot be recovered (there is deliberately
no second way in); the documented manual reset is deleting the file, which the tool never does.

The Backup Passphrase itself is held only here, in a `BackupPassphrase`, and revealed only at
the call into age (CODING_STANDARDS.md, "Secrets").
"""

import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, NoReturn, final, override

import pyrage

from network_analyser.credentials import Secret, SecretScan
from network_analyser.credentials.secret import HELD_IN_MEMORY

PASSPHRASE_MIN: Final = 15
"""At least 15 characters: NIST SP 800-63B for a single-factor secret (ADR 0004)."""

CHECK_PHRASE: Final = b"Network Analyser check file: this passphrase locks the Backups.\n"
_AGE_HEADER = b"age-encryption.org/v1\n"
_READ_AT_MOST = 64 * 1024  # a check file is a few hundred bytes


class CheckFileError(Exception):
    """The check file exists but cannot be used. The message is fixed text."""


@dataclass(frozen=True, slots=True)
class Cipher:
    """How a check file is locked and unlocked: age, or a fast fake in tests.

    Attributes:
        lock: locks plaintext with a passphrase.
        unlock: returns the plaintext, or None when the passphrase does not unlock it.
    """

    lock: Callable[[bytes, str], bytes]
    unlock: Callable[[bytes, str], bytes | None]


def _age_lock(plaintext: bytes, passphrase: str) -> bytes:
    locked: bytes = pyrage.passphrase.encrypt(plaintext, passphrase)
    return locked


def _age_unlock(locked: bytes, passphrase: str) -> bytes | None:
    if not locked.startswith(_AGE_HEADER):
        msg = "the check file is not an age file"
        raise CheckFileError(msg)
    try:
        plaintext: bytes = pyrage.passphrase.decrypt(locked, passphrase)
    except pyrage.DecryptError:
        return None
    return plaintext


AGE: Cipher = Cipher(lock=_age_lock, unlock=_age_unlock)
"""Standard age passphrase (scrypt) locking, through pyrage. Takes about a second."""


@final
class BackupPassphrase:
    """The Run's Backup Passphrase, once it has unlocked or created the check file."""

    __slots__ = ("__secret",)

    def __init__(self, secret: Secret) -> None:
        """Hold a passphrase that has been checked. Only this module makes one."""
        self.__secret: Final = secret

    def same_as(self, secret: Secret) -> bool:
        """Say, in constant time, whether `secret` is the Backup Passphrase (story 27)."""
        return self.__secret.same_as(secret)

    def lock(self, plaintext: bytes) -> bytes:
        """Return `plaintext` locked with the passphrase in standard age (scrypt), #51.

        The work factor is pyrage's own choice, about a second on this PC; the tool never
        lowers it (ADR 0004). The passphrase is revealed only for the call into age.
        """
        return AGE.lock(plaintext, self.__secret.reveal())

    def add_to_scan(self, scan: SecretScan) -> None:
        """Have the secret scan look for the passphrase in everything written (#30, #48).

        The passphrase goes straight from here to `credentials`, never through a record or
        the cli, so it stays held only by `backup_store` and the scan.
        """
        scan.watch(self.__secret)

    @override
    def __init_subclass__(cls) -> NoReturn:
        """Refuse subclasses: one could add a way to the passphrase."""
        msg = "BackupPassphrase cannot be subclassed"
        raise TypeError(msg)

    @override
    def __repr__(self) -> str:
        return f"BackupPassphrase({HELD_IN_MEMORY})"

    @override
    def __reduce_ex__(self, protocol: object) -> NoReturn:
        msg = "the Backup Passphrase cannot be saved, pickled or copied"
        raise TypeError(msg)


def passphrase_problem(passphrase: Secret) -> str | None:
    """Return why `passphrase` cannot be the Backup Passphrase, or None (story 21)."""
    if len(passphrase.reveal()) < PASSPHRASE_MIN:
        return f"it must be at least {PASSPHRASE_MIN} characters"
    return None


def create_check_file(
    path: Path, passphrase: Secret, cipher: Cipher | None = None
) -> BackupPassphrase:
    """Create the check file for a new Backup Passphrase (first Run, story 20).

    The file is locked, written to a temporary name beside it, flushed and renamed into
    place, so a crash never leaves half a check file. An existing check file is never
    replaced: Backups already locked depend on it.

    Args:
        path: where the check file goes, in the per-user data folder.
        passphrase: the new Backup Passphrase, already typed twice by the operator.
        cipher: how to lock it; None for age.

    Raises:
        ValueError: the passphrase is too short.
        CheckFileError: a check file is already there, or it could not be written.
    """
    if passphrase_problem(passphrase) is not None:
        msg = f"the Backup Passphrase must be at least {PASSPHRASE_MIN} characters"
        raise ValueError(msg)
    if path.exists():
        msg = "a check file is already there"
        raise CheckFileError(msg)
    locked = (cipher or AGE).lock(CHECK_PHRASE, passphrase.reveal())
    try:
        _write_new(path, locked)
    except OSError as error:
        msg = "the check file could not be written"
        raise CheckFileError(msg) from error
    return BackupPassphrase(passphrase)


def _write_new(path: Path, locked: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp-{secrets.token_hex(8)}")
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(handle, locked)
        os.fsync(handle)
    finally:
        os.close(handle)
    temporary.replace(path)


def unlock_check_file(
    path: Path, passphrase: Secret, cipher: Cipher | None = None
) -> BackupPassphrase | None:
    """Return the Backup Passphrase if it unlocks the check file, else None (story 22).

    Raises:
        CheckFileError: the file cannot be read, is not a check file, or unlocks to
            something other than the known phrase.
    """
    try:
        with path.open("rb") as file:
            locked = file.read(_READ_AT_MOST + 1)
    except OSError as error:
        msg = "the check file cannot be read"
        raise CheckFileError(msg) from error
    if len(locked) > _READ_AT_MOST:
        msg = "the check file is too big to be a check file"
        raise CheckFileError(msg)
    plaintext = (cipher or AGE).unlock(locked, passphrase.reveal())
    if plaintext is None:
        return None
    if plaintext != CHECK_PHRASE:
        msg = "the check file does not hold the check phrase"
        raise CheckFileError(msg)
    return BackupPassphrase(passphrase)


def change_is_pending(marker: Path) -> bool:
    """Say whether an unfinished `change-passphrase` left its marker (story 112).

    `change-passphrase` (#58) writes and removes the marker; a Run is refused while it is
    there, because Backups may be under either passphrase.
    """
    return marker.exists()
