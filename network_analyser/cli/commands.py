"""What each command does. A command not built yet says so and exits 4."""

import argparse
import sys
from collections.abc import Callable

from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import PROG

type Command = Callable[[argparse.Namespace], ExitCode]


def _not_built_yet(args: argparse.Namespace) -> ExitCode:
    print(f"{PROG} {args.command}: not built yet", file=sys.stderr)
    return ExitCode.INTERNAL_ERROR


COMMANDS: dict[str, Command] = {
    "run": _not_built_yet,
    "render": _not_built_yet,
    "show-backup": _not_built_yet,
    "trust-key": _not_built_yet,
    "role-snippet": _not_built_yet,
    "change-passphrase": _not_built_yet,
}
