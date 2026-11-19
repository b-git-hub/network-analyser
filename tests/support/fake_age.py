"""A fast stand-in for age passphrase locking, for tests that are not about age itself.

Real age (pyrage) spends about a second on scrypt per lock or unlock, so tests that drive a
whole Run start use this instead through `backup_store`'s cipher seam. It keeps only a
SHA-256 of the passphrase, never the passphrase itself, so no test secret reaches the disk,
and it stores the plaintext base64-encoded, so a test can prove no config is in the clear.
Its header has age's shape, with a scrypt level a test may choose (#51).
"""

import base64
import hashlib
import re

import pytest

from network_analyser.backup_store import check_file

_HEADER = re.compile(rb"age-encryption\.org/v1\n-> scrypt ZmFrZXNhbHQ (\d+)\n([0-9a-f]{64})\n")


def cipher(level: int = 18) -> check_file.Cipher:
    """Return a fake age whose files claim scrypt work factor 2^`level`."""

    def lock(plaintext: bytes, passphrase: str) -> bytes:
        digest = hashlib.sha256(passphrase.encode()).hexdigest().encode()
        header = b"age-encryption.org/v1\n-> scrypt ZmFrZXNhbHQ %d\n" % level
        return header + digest + b"\n--- fake\n" + base64.b64encode(plaintext)

    return check_file.Cipher(lock=lock, unlock=unlock)


def lock(plaintext: bytes, passphrase: str) -> bytes:
    """Return a fake locked file for `plaintext`."""
    return FAKE_AGE.lock(plaintext, passphrase)


def unlock(locked: bytes, passphrase: str) -> bytes | None:
    """Return the plaintext, or None when `passphrase` is not the one it was locked with."""
    found = _HEADER.match(locked)
    if found is None or found.group(2) != hashlib.sha256(passphrase.encode()).hexdigest().encode():
        return None
    return base64.b64decode(locked[found.end() :].removeprefix(b"--- fake\n"))


FAKE_AGE = cipher()


def use_fake_age(monkeypatch: pytest.MonkeyPatch, level: int = 18) -> None:
    """Make every check-file and Backup lock and unlock in this test use the fast fake."""
    monkeypatch.setattr(check_file, "AGE", cipher(level))
