"""What each command does. A command not built yet says so and exits 4."""

import argparse
import sys
from collections.abc import Callable

from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import PROG
from network_analyser.cli.run_folder import (
    RefusedError,
    check_where_run_folder_goes,
    find_data_folder,
    fixed_message,
    hold_instance_lock,
    refuse,
)

type Command = Callable[[argparse.Namespace], ExitCode]


def _not_built_yet(args: argparse.Namespace) -> ExitCode:
    print(f"{PROG} {args.command}: not built yet", file=sys.stderr)
    return ExitCode.INTERNAL_ERROR


def _run(args: argparse.Namespace) -> ExitCode:
    """Start a Run: the lock and Run folder checks come first, before any prompt (#42)."""
    try:
        data = find_data_folder()
        with hold_instance_lock(data):
            check_where_run_folder_goes(data, args.runs_dir)
            # Next in the Run-start order, from later tickets: Scope and Seeds (#41), the
            # crash-dump check (#43), the Backup Passphrase and Credential Sets (#45), then
            # cli.run_folder.create_and_register once the operator confirms.
            return _not_built_yet(args)
    except RefusedError as error:
        refuse(args.command, fixed_message(error))
        return ExitCode.REFUSED


def _change_passphrase(args: argparse.Namespace) -> ExitCode:
    """Re-lock every Backup: never while a Run or another change is in progress (story 16)."""
    try:
        data = find_data_folder()
        with hold_instance_lock(data):
            return _not_built_yet(args)  # the re-lock itself is #58
    except RefusedError as error:
        refuse(args.command, fixed_message(error))
        return ExitCode.REFUSED


COMMANDS: dict[str, Command] = {
    "run": _run,
    "render": _not_built_yet,
    "show-backup": _not_built_yet,
    "trust-key": _not_built_yet,
    "role-snippet": _not_built_yet,
    "change-passphrase": _change_passphrase,
}
