"""The lock and Run folder steps of the Run-start order (#42; spec #37 "Run-start order").

First, before any prompt: find the per-user data folder, take the single-instance lock, and
check a Run folder can be created and written where it will go (stories 16, 119-121). Last,
after the operator confirms: create the Run folder and add it to the Run register at once
(story 123).
"""

import sys
from datetime import datetime
from pathlib import Path

from network_analyser import _winsys, backup_store, run_output
from network_analyser.cli.parser import PROG
from network_analyser.credentials import SecretScan


class RefusedError(Exception):
    """A Run-start step refused; the message is fixed text, safe to print."""


def find_data_folder() -> run_output.DataFolder:
    """Return the per-user data folder under `%LOCALAPPDATA%`.

    Raises:
        RefusedError: `%LOCALAPPDATA%` is not set to an absolute path.
    """
    local_app_data = _winsys.local_app_data()
    if local_app_data is None:
        msg = "%LOCALAPPDATA% is not set, so the per-user data folder cannot be found."
        raise RefusedError(msg)
    return run_output.locate_data_folder(local_app_data)


def hold_instance_lock(data: run_output.DataFolder) -> run_output.InstanceLock:
    """Take the single-instance lock for a Run or `change-passphrase` (story 16).

    Raises:
        RefusedError: another Run or `change-passphrase` holds it.
    """
    lock = run_output.take_instance_lock(data)
    if lock is None:
        msg = (
            "another Run or change-passphrase is in progress for your account. "
            "Wait for it to finish, then try again."
        )
        raise RefusedError(msg)
    return lock


def check_where_run_folder_goes(
    data: run_output.DataFolder, runs_dir: str | None
) -> run_output.RunsParentCheck:
    """Check, before any prompt, that a Run folder can be made there; print any notice.

    The notice and warning are also returned, for the Run report (stories 119-121).

    Raises:
        RefusedError: no Run folder can be created and written there.
    """
    parent = Path(runs_dir) if runs_dir is not None else data.runs
    try:
        check = run_output.check_runs_parent(parent)
    except run_output.RunFolderError as error:
        msg = (
            f"a Run folder cannot be created and written under {console_text(str(parent))}. "
            "Choose another place with --runs-dir."
        )
        raise RefusedError(msg) from error
    for notice in check.notices:
        print(notice, file=sys.stderr)
    return check


def create_and_register(
    data: run_output.DataFolder,
    check: run_output.RunsParentCheck,
    started: datetime,
    label: str | None,
    scan: SecretScan,
) -> run_output.RunFolder:
    """Create the Run folder and add it to the Run register straight away (story 123).

    Called once the operator has confirmed the Run, before any device is contacted, while
    the single-instance lock is held. The register entry comes before anything is written
    into the folder, so `change-passphrase` finds the Backups even of a Run that crashed.

    Raises:
        RefusedError: the folder could not be created or registered.
    """
    try:
        folder = run_output.create_run_folder(check.parent, started, label)
    except run_output.RunFolderError as error:
        msg = f"the Run folder could not be created under {console_text(str(check.parent))}."
        raise RefusedError(msg) from error
    try:
        backup_store.register_run_folder(data.run_register, folder.path, scan=scan)
    except backup_store.RegisterRefusedError as error:
        msg = (
            "the Run folder was created, but its path holds text that is a typed secret, so "
            "it was not added to the Run register. No device was contacted."
        )
        raise RefusedError(msg) from error
    except OSError as error:
        msg = (
            "the Run folder was created but could not be added to the Run register, "
            f"{console_text(str(data.run_register))}. No device was contacted."
        )
        raise RefusedError(msg) from error
    return folder


def refuse(command: str, message: str) -> None:
    """Print a refusal's fixed message for `command`."""
    print(f"{PROG} {command}: refused: {message}", file=sys.stderr)


def fixed_message(error: RefusedError | backup_store.CheckFileError) -> str:
    """Return the fixed text one of the tool's own errors was raised with.

    Only errors the tool raises itself, always with fixed text, are accepted: never a
    library's, whose text could quote device output or a secret (CODING_STANDARDS 6).
    """
    return str(error.args[0])


def console_text(text: str) -> str:
    """Return `text` as printable ASCII, anything else escaped as hex (CODING_STANDARDS 5)."""
    return "".join(
        c if " " <= c <= "~" else c.encode("unicode_escape").decode("ascii") for c in text
    )
