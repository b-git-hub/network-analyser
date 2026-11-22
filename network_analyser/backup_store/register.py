"""The Run register: the Run folders the tool has created (GLOSSARY.md; decided on #22, #26).

A plain UTF-8 text file in the per-user data folder, one absolute Run folder path per line,
in the order the folders were made. It holds no secrets: only paths, whose last part is a
UTC time and the operator's `--label`. `change-passphrase` reads it to find every Backup, so
a Run folder is added the moment it is created (story 123). Entries are never removed: a
folder no longer where the register says is reported as "not found" (#58). The format is
part of the compatibility promise (decision #32).

Its text passes through the Run's secret scan (#42 follow-up, #48). A path cannot be written
as `[blocked]`, since `change-passphrase` could then never find its Backups, so a new entry
that holds a typed secret is refused instead and nothing is written. Earlier entries are
copied as they are: they were already on disk.
"""

import os
import secrets
from pathlib import Path

from network_analyser._winsys import retry_rename
from network_analyser.credentials import SecretScan


class RegisterRefusedError(Exception):
    """The Run folder's path holds a typed secret, so it was not added. Fixed text."""


def registered_run_folders(register: Path) -> tuple[Path, ...]:
    """Return every Run folder in the register, oldest first, each once."""
    try:
        text = register.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ()
    lines = (line.strip() for line in text.splitlines())
    return tuple(dict.fromkeys(Path(line) for line in lines if line))


def register_run_folder(register: Path, run_folder: Path, *, scan: SecretScan) -> None:
    """Add `run_folder` (an absolute path) to the register, unless it is already there.

    The new register is written to a temporary file beside the old one, flushed to disk,
    then renamed over it, so a crash leaves either the old list or the new one, never half.
    The caller holds the single-instance lock, so no other process writes it meanwhile.

    Raises:
        RegisterRefusedError: the path holds one of the Run's typed secrets.
    """
    folders = registered_run_folders(register)
    if run_folder in folders:
        return
    if scan.holds_secret(str(run_folder)):
        msg = "the Run folder's path holds text that is a typed secret"
        raise RegisterRefusedError(msg)
    text = "".join(f"{folder}\n" for folder in (*folders, run_folder))
    register.parent.mkdir(parents=True, exist_ok=True)
    temporary = register.with_name(f"{register.name}.tmp-{secrets.token_hex(8)}")
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(handle, text.encode("utf-8"))
        os.fsync(handle)
    finally:
        os.close(handle)
    retry_rename(lambda: temporary.replace(register))
