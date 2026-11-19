"""What each command does. A command not built yet says so and exits 4."""

import argparse
import sys
from collections.abc import Callable

from network_analyser.cli import cmd_role_snippet, cmd_run, cmd_show_backup, cmd_trust_key
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import PROG
from network_analyser.cli.run_folder import (
    RefusedError,
    find_data_folder,
    fixed_message,
    hold_instance_lock,
    refuse,
)

type Command = Callable[[argparse.Namespace], ExitCode]


def _not_built_yet(args: argparse.Namespace) -> ExitCode:
    print(f"{PROG} {args.command}: not built yet", file=sys.stderr)
    return ExitCode.INTERNAL_ERROR


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
    "run": cmd_run.run,
    "render": _not_built_yet,
    "show-backup": cmd_show_backup.show_backup,
    "trust-key": cmd_trust_key.trust_key,
    "role-snippet": cmd_role_snippet.role_snippet,
    "change-passphrase": _change_passphrase,
}
