"""`network-analyser run`: start a Run.

Until the Run-start ticket (#45) lands, `run` stops after showing the checked Scope and Seeds
(ticket #41). No packet is ever sent.
"""

import argparse
import sys

from network_analyser.cli import run_file, run_start
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import PROG
from network_analyser.cli.prompts import Prompter
from network_analyser.cli.text import escape_controls


def run(args: argparse.Namespace) -> ExitCode:
    """Start a Run from flags, a run file and prompts; return its exit code."""
    loaded = _load_run_file(args.run_file)
    if isinstance(loaded, ExitCode):
        return loaded
    request = run_start.scope_and_seeds(args, loaded, Prompter.for_this_process())
    if isinstance(request, ExitCode):
        return request
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
