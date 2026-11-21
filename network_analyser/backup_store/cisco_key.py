"""The Cisco API Key file, `cisco-key.age`, locked with the Backup Passphrase (ADR 0008; #103).

The key file is a standard age passphrase file, exactly like a Backup: the same cipher as the
check file, the same ciphertext-only temp-then-rename writes, and the same in-memory unlock.
Its plaintext is a small JSON document holding the client ID, the client secret and when the
key was set; nothing else is kept between Runs.

The client ID and client secret are `credentials.Secret` from the moment the file is unlocked
and stay so for their whole life. Only `advisories` (to make Cisco's request) and this module
(to lock or unlock the file) may reveal them (CODING_STANDARDS.md, "Secrets").

`unlock_key_file` and `relock_key_file` are the entry points the Run-end (#104) and
`change-passphrase` call. The Run-end is not wired here: that is #104. `lock_key_file` is
`cisco-key set`'s call, `remove_key_file` is `cisco-key remove`'s and the "start over" call.
"""

import contextlib
import json
import os
import secrets
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, NoReturn, final, override

from network_analyser.backup_store.check_file import BackupPassphrase
from network_analyser.credentials import Secret, SecretScan
from network_analyser.credentials.secret import HELD_IN_MEMORY

KEY_FORMAT: Final = 1
"""The version of the key file's plaintext document; a breaking change bumps it."""

KEY_LOCKED_ELSEWHERE: Final = (
    "Cisco key locked with a different passphrase: run cisco-key set again"
)
"""Fixed text for a key file the current Backup Passphrase cannot open (story 38)."""

NOT_READ: Final = "The Cisco API key file could not be read, so it was not re-locked"
NOT_CHECKED_OUT: Final = (
    "The re-locked Cisco API key file did not open to the same content; it was left as it was"
)
NOT_WRITTEN: Final = (
    "The Cisco API key file could not be written; it is still under the old passphrase"
)

_READ_AT_MOST: Final = 64 * 1024  # a key document is a few hundred bytes

if sys.platform == "win32":  # binary: Windows text mode would turn age's \n into \r\n
    _NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY
else:
    _NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL


@final
class CiscoKey:
    """The Cisco API Key, unlocked in memory: client ID, secret and when it was set.

    The client ID and secret stay `Secret`s for the object's whole life. Only `advisories`
    (to make Cisco's request) may reveal them; `client_id_suffix` is the one way to a part of
    the client ID for the operator, so `show` can say which key is in use without exposing it.
    """

    __slots__ = ("client_id", "client_secret", "set_at")

    def __init__(self, client_id: Secret, client_secret: Secret, set_at: datetime) -> None:
        """Hold an unlocked key. Only this module makes one."""
        self.client_id: Final = client_id
        self.client_secret: Final = client_secret
        self.set_at: Final = set_at

    def add_to_scan(self, scan: SecretScan) -> None:
        """Have the secret scan look for the client ID and secret in everything written."""
        scan.watch(self.client_id)
        scan.watch(self.client_secret)

    def wipe(self) -> None:
        """Wipe the client ID and secret once Cisco has answered (ADR 0007, story 20)."""
        self.client_id.wipe()
        self.client_secret.wipe()

    @property
    def wiped(self) -> bool:
        """Say whether the client ID and secret were wiped, for the Run end to prove it."""
        return self.client_id.wiped and self.client_secret.wiped

    def client_id_suffix(self) -> str:
        """Return the last 4 characters of the client ID, so `show` can say which key is set.

        The value is revealed only here, and only its tail is returned: the rest never leaves
        this method.
        """
        return self.client_id.reveal()[-4:]

    @override
    def __init_subclass__(cls) -> NoReturn:
        msg = "CiscoKey cannot be subclassed"
        raise TypeError(msg)

    @override
    def __repr__(self) -> str:
        return f"CiscoKey(client ID {HELD_IN_MEMORY}, secret {HELD_IN_MEMORY}, set {self.set_at})"

    @override
    def __reduce_ex__(self, protocol: object) -> NoReturn:
        msg = "a Cisco API Key cannot be saved, pickled or copied"
        raise TypeError(msg)


@dataclass(frozen=True, slots=True)
class KeyOutcome:
    """What came of re-locking the key file (`relock_key_file`), for `change-passphrase`.

    Attributes:
        rekeyed: whether the key file is now under the new passphrase (or was not there).
        problem: fixed text saying why it is not, or None when there is nothing to look at.
    """

    rekeyed: bool
    problem: str | None = None


def lock_key_file(
    path: Path,
    client_id: Secret,
    client_secret: Secret,
    passphrase: BackupPassphrase,
    *,
    set_at: datetime,
) -> None:
    """Lock the key into `path` with the Backup Passphrase, writing ciphertext only.

    The plaintext document holds the client ID, the client secret and `set_at` (UTC); it is
    built in memory and locked before anything reaches disk. An existing file is replaced:
    `cisco-key set` is how the operator stores a new key over an old one. The file's
    modification time is set to `set_at`, so `show` can say when the key was set without
    opening it.

    Raises:
        OSError: the key file could not be written.
    """
    document = {
        "format_version": KEY_FORMAT,
        "client_id": client_id.reveal(),
        "client_secret": client_secret.reveal(),
        "set_at": _utc_text(set_at),
    }
    plaintext = json.dumps(document, ensure_ascii=True).encode("utf-8")
    _write_new(path, passphrase.lock(plaintext))
    _set_mtime(path, int(set_at.timestamp()))


def unlock_key_file(path: Path, passphrase: BackupPassphrase) -> CiscoKey | None:
    """Return the key at `path` unlocked with the passphrase, or None if it does not open.

    None covers every unusable file: the wrong passphrase, a file that is not an age file, and
    a file whose plaintext is not a key document. The recovery is the same in every case: run
    `cisco-key set` again (story 38).
    """
    locked = _read(path)
    if locked is None:
        return None
    plaintext = passphrase.unlock(locked)
    if plaintext is None:
        return None
    return _parse(plaintext)


def relock_key_file(  # noqa: PLR0911 (one return per fixed outcome, each named)
    path: Path, old: BackupPassphrase, new: BackupPassphrase
) -> KeyOutcome:
    """Re-lock the key file from the old Backup Passphrase to the new, in place (story 37).

    Only ciphertext is written. A file that already opens with the new passphrase (re-locked
    before an interruption, or a replace that finished) is counted done; a file the old
    passphrase cannot open and the new one cannot either is reported with the story-38 message.
    A missing file is nothing to do. The file's modification time is kept, so `show` still
    says when the key was set, not when the passphrase changed.
    """
    if not path.is_file():
        return KeyOutcome(rekeyed=True)
    locked = _read(path)
    if locked is None:
        return KeyOutcome(rekeyed=False, problem=NOT_READ)
    plaintext = old.unlock(locked)
    if plaintext is None:
        if new.unlock(locked) is not None:  # re-locked before an interruption
            return KeyOutcome(rekeyed=True)
        return KeyOutcome(rekeyed=False, problem=KEY_LOCKED_ELSEWHERE)
    relocked = new.lock(plaintext)
    if new.unlock(relocked) != plaintext:
        return KeyOutcome(rekeyed=False, problem=NOT_CHECKED_OUT)
    mtime_ns = _mtime_ns(path)
    try:
        _write_new(path, relocked)
    except OSError:
        return KeyOutcome(rekeyed=False, problem=NOT_WRITTEN)
    if mtime_ns is not None:
        _set_mtime_ns(path, mtime_ns)
    return KeyOutcome(rekeyed=True)


def remove_key_file(path: Path) -> None:
    """Delete the key file (story 31, story 39). Only this module removes it."""
    path.unlink(missing_ok=True)


def key_file_set_time(path: Path) -> datetime | None:
    """Return when the key in `path` was set, or None when the file cannot be read.

    `lock_key_file` gives the file the set time as its modification time and `relock_key_file`
    keeps it, so this reads no secret and needs no passphrase.
    """
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except OSError:
        return None


def _read(path: Path) -> bytes | None:
    if not path.is_file():
        return None
    try:
        with path.open("rb") as file:
            locked = file.read(_READ_AT_MOST + 1)
    except OSError:
        return None
    return None if len(locked) > _READ_AT_MOST else locked


def _parse(plaintext: bytes) -> CiscoKey | None:
    try:
        document: object = json.loads(plaintext)
    except ValueError, RecursionError:
        return None
    if not isinstance(document, dict) or document.get("format_version") != KEY_FORMAT:
        return None
    client_id = document.get("client_id")
    client_secret = document.get("client_secret")
    set_at = _parse_set_at(document.get("set_at"))
    if not isinstance(client_id, str) or not isinstance(client_secret, str) or set_at is None:
        return None
    return CiscoKey(Secret(client_id), Secret(client_secret), set_at)


def _parse_set_at(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def _utc_text(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _mtime_ns(path: Path) -> int | None:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return None


def _set_mtime(path: Path, seconds: int) -> None:
    _set_mtime_ns(path, seconds * 1_000_000_000)


def _set_mtime_ns(path: Path, mtime_ns: int) -> None:
    """Give the file a set time to the whole second; best effort, never a reason to fail."""
    with contextlib.suppress(OSError):
        os.utime(path, ns=(mtime_ns, mtime_ns))


def _write_new(path: Path, locked: bytes) -> None:
    """Write ciphertext to a temporary name beside `path`, flush it, then rename over it.

    The temporary file is in the same folder, so the rename is atomic: a crash leaves the old
    key file or the new one, never part of either. Only age ciphertext is written.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp-{secrets.token_hex(8)}")
    handle = os.open(temporary, _NEW_FILE, 0o600)
    try:
        view = memoryview(locked)
        while view:
            view = view[os.write(handle, view) :]
        os.fsync(handle)
    finally:
        os.close(handle)
    temporary.replace(path)
