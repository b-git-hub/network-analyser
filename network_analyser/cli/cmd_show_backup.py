"""`network-analyser show-backup [BACKUP_FILE]` (ticket #57; spec #37 stories 102 and 112).

Decided on #12 and #22 and ADR 0004. With a file named, it asks for the Backup Passphrase
at the same masked prompt, after the same crash-dump check, as a Run, and prints the config
to the console only. Nothing is written to disk: standard output must be a console window,
so a redirect or a pipe can never put the plaintext in a file.

It reads only, so it takes no single-instance lock: it works during a Run, and while a
`change-passphrase` is unfinished, when it says if a file is under the other passphrase.

With no file named, it lists the Runs in the Run register and the Backups of the latest one
that is still where the register says; `--run-folder DIR` lists that folder's Backups
instead, registered or not (#42 follow-up). Listing needs no passphrase: Backup names are
not secret. It never adds to the Run register: only a Run and `change-passphrase` do.

Exit codes: 0 shown or listed; 1 the passphrase is right but the Backup does not open
(damaged); 2 refused (no console, not a Backup, wrong or other passphrase).
"""

import argparse
import sys
from pathlib import Path
from typing import Final

from network_analyser import _winsys, backup_store, run_output
from network_analyser.backup_store import show
from network_analyser.backup_store.show import Unopened
from network_analyser.cli.crash_dump_guard import guard_crash_dumps
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import PROG
from network_analyser.cli.prompts import Prompter
from network_analyser.cli.run_folder import (
    RefusedError,
    console_text,
    find_data_folder,
    fixed_message,
    refuse,
)
from network_analyser.cli.text import escape_controls

_NOT_A_CONSOLE: Final = (
    "show-backup prints a Backup only to a console window, never to a file or a pipe, so "
    "the plaintext config never reaches disk. Run it again without redirecting its output."
)
_FILE_AND_FOLDER: Final = (
    "--run-folder lists a Run's Backups, so it cannot be given with BACKUP_FILE. Name the "
    "Backup file on its own."
)
_EMPTY_REGISTER: Final = (
    "No Run folder is in the Run register yet. List a Run folder's Backups with --run-folder DIR."
)


def show_backup(args: argparse.Namespace) -> ExitCode:
    """Print one Backup's config to the console, or list a Run's Backups."""
    if args.backup_file is not None and args.run_folder is not None:
        refuse(args.command, _FILE_AND_FOLDER)
        return ExitCode.REFUSED
    try:
        data = find_data_folder()
    except RefusedError as error:
        refuse(args.command, fixed_message(error))
        return ExitCode.REFUSED
    if args.run_folder is not None:
        return _list_one(args.command, Path(args.run_folder).absolute())
    if args.backup_file is None:
        return _list_latest(data)
    return _show(args.command, data, Path(args.backup_file).absolute())


# -- Listing (no passphrase needed: only file names, which are already in the clear) ------


def _list_one(command: str, folder: Path) -> ExitCode:
    backups = show.backup_files(_winsys.os_path(folder))
    if backups is None:
        refuse(command, f"{console_text(str(folder))}: not found.")
        return ExitCode.REFUSED
    print(f"Backups of {console_text(str(folder))}:")
    _print_backups(folder, backups)
    _how_to_show()
    return ExitCode.CLEAN


def _list_latest(data: run_output.DataFolder) -> ExitCode:
    folders = backup_store.registered_run_folders(data.run_register)
    if not folders:
        print(_EMPTY_REGISTER, file=sys.stderr)
        return ExitCode.CLEAN
    found = {folder: show.backup_files(_winsys.os_path(folder)) for folder in folders}
    print("Runs in the Run register, oldest first:")
    for folder, backups in found.items():
        print(f"  {console_text(str(folder))}  {_count(backups)}")
    latest = next((f for f in reversed(folders) if found[f] is not None), None)
    if latest is None:
        print("No Run folder in the Run register is where it was.", file=sys.stderr)
        return ExitCode.CLEAN
    print(f"Backups of the latest Run, {console_text(str(latest))}:")
    _print_backups(latest, found[latest] or ())
    _how_to_show()
    return ExitCode.CLEAN


def _count(backups: tuple[Path, ...] | None) -> str:
    if backups is None:
        return "not found"
    return f"{len(backups)} Backup{'' if len(backups) == 1 else 's'}"


def _print_backups(folder: Path, backups: tuple[Path, ...]) -> None:
    if not backups:
        print("  none")
    for backup in backups:  # shown by the plain path, not the long-path form
        print(f"  {console_text(str(folder / backup_store.BACKUPS_FOLDER / backup.name))}")


def _how_to_show() -> None:
    print(
        f'Show one with: {PROG} show-backup "BACKUP_FILE". List another Run with --run-folder DIR.',
        file=sys.stderr,
    )


# -- Showing one Backup -------------------------------------------------------------------


def _show(command: str, data: run_output.DataFolder, path: Path) -> ExitCode:
    shown = console_text(str(path))
    backup = show.load_backup(_winsys.os_path(path))
    if isinstance(backup, Unopened):
        refuse(command, f"{shown}: {backup.value}.")
        return ExitCode.REFUSED
    if not _winsys.stdout_is_console():
        refuse(command, _NOT_A_CONSOLE)
        return ExitCode.REFUSED
    ask = Prompter.for_this_process()
    if not guard_crash_dumps(ask):
        return ExitCode.REFUSED
    passphrase = ask.secret("Backup Passphrase: ")
    ask.say("Opening the Backup in memory (about a second)...")
    files = backup_store.PassphraseFiles(
        check_file=data.check_file,
        previous_check_file=data.previous_check_file,
        change_pending=data.change_pending,
    )
    config = show.open_backup(backup, passphrase, files)
    if isinstance(config, Unopened):
        print(f"Not shown: {shown}: {config.value}.", file=sys.stderr)
        return ExitCode.NEEDS_ATTENTION if config is Unopened.DAMAGED else ExitCode.REFUSED
    _print_config(config)
    return ExitCode.CLEAN


def _print_config(config: str) -> None:
    r"""Print `config` line by line, every other control character escaped as `\xNN`.

    Lines end only at `\n` (with an optional `\r` before it), never at the other breaks
    `str.splitlines` knows, so a form feed or `\x85` in device text is shown, not obeyed.
    """
    lines = config.split("\n")
    if lines[-1] == "":
        lines.pop()
    for line in lines:
        print(escape_controls(line.removesuffix("\r"), limit=None))
