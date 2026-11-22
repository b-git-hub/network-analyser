"""The locking worker: every captured running config becomes a locked Backup (ticket #51).

Decided on #12, #27 and ADR 0004; spec #37 stories 84, 92-101 and 103-105.

- `device_gateway.visit` hands each whole config to `BackupLocker.take`, the Run's Backup
  sink. Nothing else ever sees it (spec-37 call 4).
- One worker thread locks the configs one at a time, because pyrage holds the GIL for the
  second its scrypt takes. Its queue holds at most the Run's parallelism number of configs:
  a device's visit waits in `take` until there is room (story 100).
- A config is locked in memory with the Backup Passphrase, in standard age (scrypt), so
  `age -d` opens it (story 103). Only ciphertext is written: to a temporary name beside the
  Backup, flushed to disk, then renamed into place, so a crash keeps every finished Backup
  and never leaves a partial one under a Backup's name (story 92). An existing file is never
  replaced and a Backup is never deleted (story 104).
- `finish` locks every config already taken, also after Ctrl+C (story 84), then writes the
  Run's locked `manifest.age` (story 98). Only ciphertext hashes are ever in the clear: in
  `audit.log` and the results (story 99).

Each Backup is named `<hostname>__<chassis serial>.cfg.age` from device text sanitised by
`records.safe_names`, falling back to the serial only, then an index (story 94).
"""

import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Final

from network_analyser._winsys import retry_rename
from network_analyser.backup_store.check_file import BackupPassphrase
from network_analyser.credentials import SecretScan
from network_analyser.records.backup import BackupCapture, BackupRecord, BackupResults
from network_analyser.records.device import Unknown
from network_analyser.records.events import AuditEvent, BackupWritten, error_event
from network_analyser.records.safe_names import sanitised

BACKUPS_FOLDER: Final = "backups"
MANIFEST_NAME: Final = "manifest.age"
BACKUP_SUFFIX: Final = ".cfg.age"
NAME_MAX: Final = 64
"""The most characters a Backup's name may have before `.cfg.age` (story 94)."""
MANIFEST_FORMAT: Final = 1
_WAIT_SLICE_S: Final = 0.25

NOT_WRITTEN: Final = "the Backup could not be written"
MANIFEST_NOT_WRITTEN: Final = "the manifest could not be written"
_MESSAGES: Final[Mapping[type[BaseException], str]] = {
    OSError: "a file in the Run folder's backups folder could not be written"
}

_SCRYPT_STANZA: Final = re.compile(rb"-> scrypt [A-Za-z0-9+/]+ (\d{1,2})")
_AGE_FIRST_LINE: Final = b"age-encryption.org/v1"
# Windows refuses these as file names, whatever follows the first dot.
_WINDOWS_DEVICES: Final = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"{kind}{n}" for kind in ("COM", "LPT") for n in (*range(10), "¹", "²", "³")}
)

if sys.platform == "win32":
    _NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY
else:
    _NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL

type Emit = Callable[[AuditEvent], None]


def scrypt_level(locked: bytes) -> int:
    """Return the scrypt work factor (log2) from an age passphrase file's header (story 101).

    Raises:
        ValueError: it is not an age passphrase file. A bug in the tool: it only reads
            files it has just locked.
    """
    first, _, rest = locked.partition(b"\n")
    stanza = rest.partition(b"\n")[0]
    found = _SCRYPT_STANZA.fullmatch(stanza)
    if first != _AGE_FIRST_LINE or found is None:
        msg = "not an age passphrase file"
        raise ValueError(msg)
    return int(found.group(1))


class BackupLocker:
    """The Run's one locking worker and its capped queue. `take` is the Backup sink."""

    def __init__(  # noqa: PLR0913 (where the Backups go and everything locking needs, by name)
        self,
        run_folder: Path,
        *,
        shown: Path,
        passphrase: BackupPassphrase,
        capacity: int,
        emit: Emit,
        scan: SecretScan,
        tool_version: str,
    ) -> None:
        """Get ready to lock this Run's Backups. Nothing is written until the first one.

        Args:
            run_folder: the Run folder, in the form file calls take (long-path form on
                Windows).
            shown: the Run folder's plain path, for `audit.log` and the results.
            passphrase: the Run's Backup Passphrase, checked against the check file.
            capacity: the most configs waiting or being locked: the Run's parallelism.
            emit: takes each Audit log event; safe to call from the worker thread.
            scan: the Run's secret scan: a name that holds a typed secret is not used.
            tool_version: recorded in the manifest.
        """
        if capacity < 1:
            msg = "the queue must hold at least one config"
            raise ValueError(msg)
        self._folder = run_folder / BACKUPS_FOLDER
        self._shown = shown / BACKUPS_FOLDER
        self._passphrase = passphrase
        self._emit = emit
        self._scan = scan
        self._tool_version = tool_version
        self._room = threading.BoundedSemaphore(capacity)
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="backup-locker")
        self._jobs: list[Future[None]] = []
        self._records: list[BackupRecord] = []
        self._entries: list[dict[str, object]] = []
        self._taken_names: set[str] = set()
        self._lock_seconds = 0.0
        self._finished = False
        self._manifest_written = False

    def take(self, capture: BackupCapture, config: str, /) -> None:
        """Queue `config` to be locked; wait while the queue is full (the Backup sink).

        Raises:
            RuntimeError: the locker has finished. A bug in the tool.
        """
        if self._finished:
            msg = "the Backups of this Run are already finished"
            raise RuntimeError(msg)
        try:
            while not self._room.acquire(timeout=_WAIT_SLICE_S):
                pass  # short waits, so Ctrl+C is seen at once on Windows too
        except KeyboardInterrupt:
            # The config was captured, so it is locked all the same (story 84), beyond the
            # cap: the Run is stopping and takes no more.
            self._jobs.append(self._worker.submit(self._lock_one, capture, config, queued=False))
            raise
        try:
            self._jobs.append(self._worker.submit(self._lock_one, capture, config, queued=True))
        except BaseException:
            self._room.release()
            raise

    def finish(self) -> BackupResults:
        """Lock every config already taken, write the manifest, and say what was written.

        Safe to call after Ctrl+C or an error: what was captured is still locked (story 84).

        Raises:
            Exception: whatever the worker met that was not a file error, such as
                `audit.log` failing; only after every Backup and the manifest are done.
        """
        self._finished = True
        self._jobs.append(self._worker.submit(self._write_manifest))  # last, on the worker
        self._worker.shutdown(wait=True)
        for job in self._jobs:
            failure = job.exception()
            if failure is not None:
                raise failure
        return BackupResults(
            backups=tuple(self._records),
            lock_seconds=self._lock_seconds,
            manifest_path=str(self._shown / MANIFEST_NAME) if self._manifest_written else None,
            manifest_problem=None if self._manifest_written else MANIFEST_NOT_WRITTEN,
        )

    # -- The worker -------------------------------------------------------------------------

    def _lock_one(self, capture: BackupCapture, config: str, *, queued: bool) -> None:
        try:
            plaintext = config.encode("utf-8", errors="backslashreplace")
            started = time.monotonic()
            locked = self._passphrase.lock(plaintext)
            seconds = time.monotonic() - started
            self._lock_seconds += seconds
            self._store(capture, plaintext, locked, seconds)
        finally:
            if queued:
                self._room.release()

    def _store(
        self, capture: BackupCapture, plaintext: bytes, locked: bytes, seconds: float
    ) -> None:
        level = scrypt_level(locked)
        name = self._name(capture)
        try:
            _write_new(self._folder, name, locked)
        except OSError as error:
            self._records.append(
                BackupRecord(capture.ip, capture.hostname, None, None, None, seconds, NOT_WRITTEN)
            )
            self._emit(error_event(error, step="write Backup", ip=capture.ip, messages=_MESSAGES))
            return
        self._taken_names.add(name)
        digest = hashlib.sha256(locked).hexdigest()
        shown = str(self._shown / name)
        self._records.append(
            BackupRecord(capture.ip, capture.hostname, shown, digest, level, seconds)
        )
        self._entries.append(self._entry(capture, name, plaintext, digest))
        self._emit(BackupWritten(capture.ip, shown, digest, level))

    def _name(self, capture: BackupCapture) -> str:
        """`<hostname>__<chassis serial>`, else the serial, else an index; never taken."""
        serial = _serial(capture)
        hostname = None
        if serial is not None and isinstance(capture.hostname, str):
            hostname = sanitised(capture.hostname, NAME_MAX - 2 - len(serial))
        candidates = [f"{hostname}__{serial}" if hostname and serial else None, serial]
        stem = next((c for c in candidates if c is not None and self._usable(c)), None)
        if stem is None:
            stem = f"backup-{len(self._records) + 1}"
        name = f"{stem}{BACKUP_SUFFIX}"
        number = 1
        while name in self._taken_names or (self._folder / name).exists():
            number += 1
            suffix = f"-{number}"
            name = f"{stem[: NAME_MAX - len(suffix)]}{suffix}{BACKUP_SUFFIX}"
        return name

    def _usable(self, stem: str) -> bool:
        reserved = stem.split(".", 1)[0].upper() in _WINDOWS_DEVICES
        return not reserved and not self._scan.holds_secret(stem)

    def _entry(
        self, capture: BackupCapture, name: str, plaintext: bytes, digest: str
    ) -> dict[str, object]:
        """One Backup's line in the locked manifest (story 98)."""
        stamp = capture.captured_at.isoformat(timespec="seconds").replace("+00:00", "Z")
        return {
            "file": name,
            "ip": str(capture.ip),
            "hostname": None if isinstance(capture.hostname, Unknown) else capture.hostname,
            "serials": None if isinstance(capture.serials, Unknown) else list(capture.serials),
            "platform": capture.platform.value,
            "command": capture.command,
            "captured_at": stamp,
            "tool_version": self._tool_version,
            "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
            "ciphertext_sha256": digest,
        }

    # -- The manifest -----------------------------------------------------------------------

    def _write_manifest(self) -> None:
        document = {
            "format_version": MANIFEST_FORMAT,
            "tool_version": self._tool_version,
            "backups": self._entries,
        }
        plaintext = json.dumps(document, ensure_ascii=True, indent=1).encode("ascii")
        started = time.monotonic()
        locked = self._passphrase.lock(plaintext)
        self._lock_seconds += time.monotonic() - started
        try:
            _write_new(self._folder, MANIFEST_NAME, locked)
        except OSError as error:
            self._emit(error_event(error, step="write manifest", ip=None, messages=_MESSAGES))
            return
        self._manifest_written = True


def _serial(capture: BackupCapture) -> str | None:
    """The chassis serial, sanitised for a name; None when there is none to use."""
    if isinstance(capture.serials, Unknown) or not capture.serials:
        return None
    return sanitised(capture.serials[0], NAME_MAX)


def _write_new(folder: Path, name: str, locked: bytes) -> None:
    """Write ciphertext to a temporary name, flush it, then rename it into place.

    Raises:
        OSError: it could not be written, or a file is already there: never replaced.
    """
    folder.mkdir(exist_ok=True)
    final = folder / name
    temporary = folder / f".{name}.tmp-{secrets.token_hex(8)}"
    handle = os.open(temporary, _NEW_FILE, 0o600)
    try:
        view = memoryview(locked)
        while view:
            view = view[os.write(handle, view) :]
        os.fsync(handle)
    finally:
        os.close(handle)
    if final.exists():  # one worker and the single-instance lock: nothing else writes here
        raise FileExistsError(name)
    # On Windows, a rename never replaces a file either.
    retry_rename(lambda: temporary.rename(final))
