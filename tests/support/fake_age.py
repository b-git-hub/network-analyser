"""A fast stand-in for age passphrase locking, for tests that are not about age itself.

Real age (pyrage) spends about a second on scrypt per lock or unlock, so tests that drive a
whole Run start use this instead through `backup_store`'s cipher seam. It keeps only a
SHA-256 of the passphrase, never the passphrase itself, so no test secret reaches the disk.
"""

import hashlib

import pytest

from network_analyser.backup_store import check_file

_MAGIC = b"FAKE-AGE\n"


def lock(plaintext: bytes, passphrase: str) -> bytes:
    """Return a fake locked file for `plaintext`."""
    digest = hashlib.sha256(passphrase.encode()).hexdigest().encode()
    return _MAGIC + digest + b"\n" + plaintext


def unlock(locked: bytes, passphrase: str) -> bytes | None:
    """Return the plaintext, or None when `passphrase` is not the one it was locked with."""
    if not locked.startswith(_MAGIC):
        return None
    digest, _, plaintext = locked.removeprefix(_MAGIC).partition(b"\n")
    if digest != hashlib.sha256(passphrase.encode()).hexdigest().encode():
        return None
    return plaintext


FAKE_AGE = check_file.Cipher(lock=lock, unlock=unlock)


def use_fake_age(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every check-file lock and unlock in this test use the fast fake."""
    monkeypatch.setattr(check_file, "AGE", FAKE_AGE)
