"""`network-analyser run`: start a Run.

Until the Run-start ticket (#45) lands, `run` stops after showing the checked Scope and Seeds
(ticket #41). No packet is ever sent. Before anything else, and before any prompt, it takes
the single-instance lock and checks a Run folder can be made where it will go (#42); the
lock is held until `run` ends.
"""

import argparse
import sys

from network_analyser.cli import run_file, run_start
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import PROG
from network_analyser.cli.prompts import Prompter
from network_analyser.cli.run_folder import (
    RefusedError,
    check_where_run_folder_goes,
    find_data_folder,
    fixed_message,
    hold_instance_lock,
    refuse,
)
from network_analyser.cli.text import escape_controls


def run(args: argparse.Namespace) -> ExitCode:
    """Start a Run from flags, a run file and prompts; return its exit code."""
    try:
        data = find_data_folder()
        with hold_instance_lock(data):
            check_where_run_folder_goes(data, args.runs_dir)
            return _after_folder_checks(args)
    except RefusedError as error:
        refuse(args.command, fixed_message(error))
        return ExitCode.REFUSED


def _after_folder_checks(args: argparse.Namespace) -> ExitCode:
    loaded = _load_run_file(args.run_file)
    if isinstance(loaded, ExitCode):
        return loaded
    request = run_start.scope_and_seeds(args, loaded, Prompter.for_this_process())
    if isinstance(request, ExitCode):
        return request
    # Next, from later tickets: the crash-dump check, the Backup Passphrase and Credential
    # Sets (#45), then cli.run_folder.create_and_register once the operator confirms.
    print(
        f"{PROG} run: Scope and Seeds checked. "
        "The rest of the Run is not built yet; nothing was contacted.",
        file=sys.stderr,
    )
    return ExitCode.INTERNAL_ERROR


def _load_run_file(path: str | None) -> run_file.RunFile | ExitCode | None:
    if path is None:
        return None
    loaded = run_file.load(path)
    if isinstance(loaded, run_file.RunFile):
        return loaded
    lines = [f"Refused: run file {escape_controls(loaded.path, limit=200)}:"]
    lines.extend(f"  {problem}" for problem in loaded.problems)
    lines.append(f"{run_start.NOTHING_CONTACTED} Fix the run file and run again.")
    print("\n".join(lines), file=sys.stderr)
    return ExitCode.REFUSED
