"""Re-locking Backups and Run manifests under a new Backup Passphrase (ticket #58; #22, #27).

Spec #37 stories 106-114. Each file is re-locked in place, one at a time (pyrage holds the
GIL, so overlapping gains nothing, #27):

1. its locked bytes are read and unlocked **in memory** with the old passphrase;
2. the plaintext is locked with the new passphrase, in memory;
3. the result is unlocked again with the new passphrase, to prove it opens to the same text;
4. only then is the new ciphertext written to a temporary name beside the file, flushed, and
   renamed over the original.

No plaintext ever reaches the disk, and a crash at any point leaves each file wholly old or
wholly new: the temporary file holds ciphertext only. After each file the change-pending
marker records it as done, so a rerun skips it; a file re-locked just before a crash, which
the marker missed, opens with the new passphrase and is counted done too.

In each Run folder the Backups go first and `manifest.age` last, updated with each Backup's
new fingerprint (SHA-256 of the locked file); the fingerprint of the config inside does not
change. A file that will not open with the old passphrase is skipped and listed. A Backup
whose config does not match its manifest fingerprint is re-locked unchanged and flagged
(story 113). Each Run folder then gets a plaintext re-lock record, `relock-<UTC start>.txt`,
listing every file's fingerprints before and after (story 114). Old Run reports are left as
they are.
"""

import hashlib
import json
import os
import secrets
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Final

from network_analyser._winsys import retry_rename
from network_analyser.backup_store.change_pending import Fingerprints, PendingChange
from network_analyser.backup_store.check_file import BackupPassphrase
from network_analyser.backup_store.locker import BACKUP_SUFFIX, BACKUPS_FOLDER, MANIFEST_NAME
from network_analyser.credentials import SecretScan

RECORD_PREFIX: Final = "relock-"
_READ_AT_MOST: Final = 64 * 1024 * 1024  # far more than a capped running config locks to

NOT_OPENED: Final = (
    "it does not open with the old passphrase (damaged, changed, or locked with another passphrase)"
)
NOT_READ: Final = "it could not be read"
TOO_BIG: Final = "it is too big to be a Backup"
NOT_CHECKED_OUT: Final = "the re-locked copy did not open to the same content; left as it was"
NOT_WRITTEN: Final = "the re-locked file could not be written; it is still under the old passphrase"
CONTENT_MISMATCH: Final = "content does not match its manifest"
NOT_LISTED: Final = "not listed in its manifest"
NOT_A_MANIFEST: Final = "it could not be read as a manifest; re-locked unchanged"
RECORD_NOT_WRITTEN: Final = "the re-lock record could not be written"

if sys.platform == "win32":
    _NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY
else:
    _NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL


def _same(path: Path) -> Path:
    return path


# -- What there is to re-lock (story 107) --------------------------------------------------


@dataclass(frozen=True, slots=True)
class RunFiles:
    """The locked files of one Run folder."""

    folder: Path
    """The Run folder's path as registered and shown."""
    io_folder: Path
    r"""The same path in the form file calls take (`\\?\` on Windows)."""
    backups: tuple[str, ...]
    """The names of its Backups (`*.cfg.age`) in the `backups` folder."""
    manifest: bool
    """Whether `backups/manifest.age` is there."""

    @property
    def files(self) -> int:
        """How many files there are to re-lock."""
        return len(self.backups) + int(self.manifest)


@dataclass(frozen=True, slots=True)
class RelockPlan:
    """Every Run folder found, and those not where the register or operator said."""

    runs: tuple[RunFiles, ...]
    not_found: tuple[Path, ...]

    @property
    def backups(self) -> int:
        """How many Backups there are, in every Run folder found."""
        return sum(len(run.backups) for run in self.runs)

    @property
    def files(self) -> int:
        """How many files there are to re-lock: Backups and manifests."""
        return sum(run.files for run in self.runs)

    @property
    def runs_with_files(self) -> int:
        """How many Run folders hold anything to re-lock."""
        return sum(1 for run in self.runs if run.files)


def plan_relock(folders: Iterable[Path], *, io_path: Callable[[Path], Path] = _same) -> RelockPlan:
    """Find the Backups and manifest of each Run folder, in the order given, each once.

    Args:
        folders: Run folders, from the Run register and `--run-folder`.
        io_path: turns a path into the form file calls take (`_winsys.os_path`).
    """
    runs: list[RunFiles] = []
    not_found: list[Path] = []
    for folder in dict.fromkeys(folders):
        io_folder = io_path(folder)
        if not io_folder.is_dir():
            not_found.append(folder)
            continue
        try:
            names = _locked_files(io_folder / BACKUPS_FOLDER)
        except OSError:
            not_found.append(folder)
            continue
        backups = tuple(sorted(n for n in names if n.endswith(BACKUP_SUFFIX)))
        runs.append(RunFiles(folder, io_folder, backups, MANIFEST_NAME in names))
    return RelockPlan(tuple(runs), tuple(not_found))


def _locked_files(backups: Path) -> frozenset[str]:
    if not backups.is_dir():
        return frozenset()
    return frozenset(
        p.name for p in backups.iterdir() if not p.name.startswith(".") and p.is_file()
    )


# -- Re-locking (stories 110-114) -----------------------------------------------------------


class FileOutcome(Enum):
    """What became of one file."""

    RELOCKED = "re-locked"
    DONE_EARLIER = "re-locked earlier in this change"
    SKIPPED = "not re-locked"


@dataclass(frozen=True, slots=True)
class FileResult:
    """One file's outcome, with its fingerprints (SHA-256 of the locked file)."""

    path: str
    """The file's path as shown, under the Run folder's registered path."""
    outcome: FileOutcome
    before: str | None = None
    after: str | None = None
    problem: str | None = None
    """Why it was not re-locked (SKIPPED only)."""
    flag: str | None = None
    """Something the operator should look at, though the file was re-locked."""


@dataclass(frozen=True, slots=True)
class RunResult:
    """One Run folder's outcome."""

    folder: Path
    files: tuple[FileResult, ...]
    record: Path | None
    """The re-lock record's shown path; None if there was nothing to record or it failed."""
    record_problem: str | None = None


@dataclass(slots=True)
class _Unlocked:
    """A file read and opened: under the old passphrase, or already under the new one."""

    locked: bytes
    plaintext: bytes
    already_new: bool


class Relocker:
    """Re-locks Run folders, one file at a time, from the old passphrase to the new."""

    def __init__(  # noqa: PLR0913 (both passphrases and what a re-lock records, by name)
        self,
        *,
        old: BackupPassphrase,
        new: BackupPassphrase,
        pending: PendingChange,
        scan: SecretScan,
        tool_version: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """Get ready to re-lock.

        Args:
            old: the passphrase the files are under now, checked against its check file.
            new: the new passphrase, which the check file now holds.
            pending: the change under way: skips files already done and records each one.
            scan: the command's secret scan; the re-lock record passes through it.
            tool_version: written in each re-lock record.
            clock: the time now (UTC), for the re-lock record.
        """
        self._old = old
        self._new = new
        self._pending = pending
        self._scan = scan
        self._tool_version = tool_version
        self._clock = clock

    def relock_run(
        self,
        run: RunFiles,
        *,
        each: Callable[[FileResult], None] = lambda _result: None,
        stop: Callable[[], bool] = lambda: False,
    ) -> RunResult | None:
        """Re-lock one Run folder's Backups, then its manifest, then write its record.

        Args:
            run: the Run folder's files, from `plan_relock`.
            each: told of each file as it is done, for progress.
            stop: asked before each file; True stops before it (Ctrl+C finishes the current
                file, then stops). The folder's record is then written by the rerun.

        Returns:
            The folder's outcome, or None when `stop` stopped it part way.
        """
        folder = _Folder(run)
        manifest = _ManifestState()
        if run.manifest:
            manifest = self._open_manifest(folder)
        results: list[FileResult] = []
        for name in run.backups:
            if stop():
                return None
            result = self._backup(folder, name, manifest)
            results.append(result)
            each(result)
        if run.manifest:
            if stop():
                return None
            result = self._finish_manifest(folder, manifest, results)
            results.append(result)
            each(result)
        record, problem = self._write_record(run, results) if results else (None, None)
        return RunResult(run.folder, tuple(results), record, problem)

    # -- Backups ----------------------------------------------------------------------------

    def _backup(self, folder: _Folder, name: str, manifest: _ManifestState) -> FileResult:
        shown = folder.shown(name)
        earlier = self._pending.done(shown)
        if earlier is not None:
            return FileResult(shown, FileOutcome.DONE_EARLIER, earlier.before, earlier.after)
        opened = self._open(folder.io(name))
        if isinstance(opened, str):
            return FileResult(shown, FileOutcome.SKIPPED, problem=opened)
        flag = manifest.flag(name, opened.plaintext)
        if opened.already_new:
            after = _sha(opened.locked)
            self._pending.mark_done(shown, Fingerprints(None, after))
            return FileResult(shown, FileOutcome.DONE_EARLIER, None, after, flag=flag)
        return self._relock(folder, name, opened, flag)

    def _relock(
        self, folder: _Folder, name: str, opened: _Unlocked, flag: str | None
    ) -> FileResult:
        shown = folder.shown(name)
        before = _sha(opened.locked)
        relocked = self._new.lock(opened.plaintext)
        if self._new.unlock(relocked) != opened.plaintext:
            return FileResult(shown, FileOutcome.SKIPPED, before, problem=NOT_CHECKED_OUT)
        try:
            _write_replacing(folder.io(name), relocked)
        except OSError:
            return FileResult(shown, FileOutcome.SKIPPED, before, problem=NOT_WRITTEN)
        after = _sha(relocked)
        self._pending.mark_done(shown, Fingerprints(before, after))
        return FileResult(shown, FileOutcome.RELOCKED, before, after, flag=flag)

    def _open(self, path: Path) -> _Unlocked | str:
        """Read and unlock a file in memory; return why not, as fixed text, if it fails."""
        try:
            with path.open("rb") as file:
                locked = file.read(_READ_AT_MOST + 1)
        except OSError:
            return NOT_READ
        if len(locked) > _READ_AT_MOST:
            return TOO_BIG
        plaintext = self._old.unlock(locked)
        if plaintext is not None:
            return _Unlocked(locked, plaintext, already_new=False)
        plaintext = self._new.unlock(locked)  # re-locked before an interruption?
        if plaintext is not None:
            return _Unlocked(locked, plaintext, already_new=True)
        return NOT_OPENED

    # -- The manifest -----------------------------------------------------------------------

    def _open_manifest(self, folder: _Folder) -> _ManifestState:
        shown = folder.shown(MANIFEST_NAME)
        earlier = self._pending.done(shown)
        if earlier is not None:
            return _ManifestState(earlier=earlier)
        opened = self._open(folder.io(MANIFEST_NAME))
        if isinstance(opened, str):
            return _ManifestState(problem=opened)
        return _ManifestState(opened=opened, document=_manifest_document(opened.plaintext))

    def _finish_manifest(
        self, folder: _Folder, manifest: _ManifestState, results: list[FileResult]
    ) -> FileResult:
        shown = folder.shown(MANIFEST_NAME)
        if manifest.earlier is not None:
            before, after = manifest.earlier.before, manifest.earlier.after
            return FileResult(shown, FileOutcome.DONE_EARLIER, before, after)
        if manifest.opened is None:
            return FileResult(shown, FileOutcome.SKIPPED, problem=manifest.problem)
        if manifest.opened.already_new:
            after = _sha(manifest.opened.locked)
            self._pending.mark_done(shown, Fingerprints(None, after))
            return FileResult(shown, FileOutcome.DONE_EARLIER, None, after)
        if manifest.document is None:
            return self._relock(folder, MANIFEST_NAME, manifest.opened, NOT_A_MANIFEST)
        afters = {Path(r.path).name: r.after for r in results if r.after is not None}
        plaintext = _updated_manifest(manifest.document, afters)
        updated = _Unlocked(manifest.opened.locked, plaintext, already_new=False)
        return self._relock(folder, MANIFEST_NAME, updated, None)

    # -- The re-lock record (story 114) -----------------------------------------------------

    def _write_record(
        self, run: RunFiles, results: list[FileResult]
    ) -> tuple[Path | None, str | None]:
        stamp = self._pending.started_at.strftime("%Y%m%dT%H%M%SZ")
        name = f"{RECORD_PREFIX}{stamp}.txt"
        text, _ = self._scan.contains_secret(self._record_text(run, results))
        try:
            _write_replacing(run.io_folder / name, text.encode("ascii"))
        except OSError:
            return None, RECORD_NOT_WRITTEN
        return run.folder / name, None

    def _record_text(self, run: RunFiles, results: list[FileResult]) -> str:
        lines = [
            "Network Analyser re-lock record",
            "",
            "The Backup Passphrase was changed, and the files below were re-locked in place",
            "under the new one. Fingerprints are SHA-256 of each locked file, before and after.",
            "Run reports written before the change still show the fingerprints from before.",
            "Nothing in this file is secret.",
            "",
            f"Run folder:     {_ascii(str(run.folder))}",
            f"Change started: {_utc_text(self._pending.started_at)}",
            f"Record written: {_utc_text(self._clock())}",
            f"Tool version:   {_ascii(self._tool_version)}",
            "",
        ]
        for result in results:
            lines.append(_ascii(f"{BACKUPS_FOLDER}/{Path(result.path).name}"))
            if result.outcome is FileOutcome.SKIPPED:
                lines.append(f"  not re-locked: {result.problem}")
                continue
            before = result.before or "unknown (re-locked before an interrupted run ended)"
            lines.extend((f"  before: {before}", f"  after:  {result.after}"))
            if result.flag is not None:
                lines.append(f"  flagged: {result.flag}")
        return "\n".join(lines) + "\n"


# -- Helpers ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Folder:
    run: RunFiles

    def shown(self, name: str) -> str:
        return str(self.run.folder / BACKUPS_FOLDER / name)

    def io(self, name: str) -> Path:
        return self.run.io_folder / BACKUPS_FOLDER / name


@dataclass(slots=True)
class _ManifestState:
    """What the manifest says, read before the Backups so each can be checked against it."""

    opened: _Unlocked | None = None
    document: dict[str, object] | None = None
    earlier: Fingerprints | None = None
    problem: str | None = None

    def flag(self, name: str, plaintext: bytes) -> str | None:
        """Say if a Backup's config does not match its manifest entry (story 113)."""
        if self.document is None:
            return None  # no manifest to check against
        digests = _plaintext_digests(self.document)
        if name not in digests:
            return NOT_LISTED
        return None if digests[name] == _sha(plaintext) else CONTENT_MISMATCH


def _manifest_document(plaintext: bytes) -> dict[str, object] | None:
    try:
        document: object = json.loads(plaintext)
    except ValueError:
        return None
    if not isinstance(document, dict) or not isinstance(document.get("backups"), list):
        return None
    return document


def _entries(document: dict[str, object]) -> list[dict[str, object]]:
    backups = document.get("backups")
    if not isinstance(backups, list):
        return []
    return [e for e in backups if isinstance(e, dict) and isinstance(e.get("file"), str)]


def _plaintext_digests(document: dict[str, object]) -> dict[str, object]:
    return {str(e["file"]): e.get("plaintext_sha256") for e in _entries(document)}


def _updated_manifest(document: dict[str, object], afters: dict[str, str]) -> bytes:
    """The manifest with each re-locked Backup's new fingerprint; nothing else changes."""
    for entry in _entries(document):
        after = afters.get(str(entry["file"]))
        if after is not None:
            entry["ciphertext_sha256"] = after
    return json.dumps(document, ensure_ascii=True, indent=1).encode("ascii")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc_text(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _ascii(text: str) -> str:
    """Printable ASCII, anything else escaped, so a path never garbles the record."""
    return "".join(
        c if " " <= c <= "~" else c.encode("unicode_escape").decode("ascii") for c in text
    )


def _write_replacing(path: Path, data: bytes) -> None:
    """Write ciphertext or the record to a temporary name beside `path`, then rename over it.

    The temporary file is in the same folder, so the rename is atomic: a crash leaves the
    old file or the new one, never part of either. Plaintext config never comes here.
    """
    temporary = path.with_name(f".{path.name}.relock-{secrets.token_hex(8)}")
    handle = os.open(temporary, _NEW_FILE, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(handle, view) :]
        os.fsync(handle)
    finally:
        os.close(handle)
    retry_rename(lambda: temporary.replace(path))
