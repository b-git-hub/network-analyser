"""What each command does: one function per command, each returning an exit code."""

import argparse
from collections.abc import Callable

from network_analyser.cli import (
    cmd_change_passphrase,
    cmd_render,
    cmd_role_snippet,
    cmd_run,
    cmd_show_backup,
    cmd_trust_key,
)
from network_analyser.cli.exit_codes import ExitCode

type Command = Callable[[argparse.Namespace], ExitCode]


COMMANDS: dict[str, Command] = {
    "run": cmd_run.run,
    "render": cmd_render.render,
    "show-backup": cmd_show_backup.show_backup,
    "trust-key": cmd_trust_key.trust_key,
    "role-snippet": cmd_role_snippet.role_snippet,
    "change-passphrase": cmd_change_passphrase.change_passphrase,
}
