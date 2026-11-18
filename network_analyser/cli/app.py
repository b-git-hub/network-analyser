"""The entry point: parse, dispatch, and map every outcome to an exit code."""

import faulthandler
import sys
from collections.abc import Callable, Sequence
from typing import NoReturn

from network_analyser import _winsys
from network_analyser.cli.commands import COMMANDS
from network_analyser.cli.crash import describe_internal_error, install_crash_hooks
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.library_loggers import silence_library_loggers
from network_analyser.cli.parser import build_parser

ELEVATED_WARNING = (
    "Warning: Network Analyser is running elevated (with admin rights). It is meant to run "
    "as a standard user and needs no admin rights."
)


def entry() -> NoReturn:
    """Start the program: `python -m network_analyser` and the frozen exe land here."""
    # faulthandler stays off (spec #37). PYTHONFAULTHANDLER or -X faulthandler could have
    # turned it on before we ran, so switch it off again.
    faulthandler.disable()
    install_crash_hooks()
    sys.exit(main())


def main(
    argv: Sequence[str] | None = None,
    *,
    elevated: Callable[[], bool] = _winsys.is_elevated,
) -> int:
    """Run one command and return its exit code.

    Args:
        argv: the arguments after the program name; None reads `sys.argv`.
        elevated: says whether the process runs elevated. A seam for tests, because the
            real check needs Windows.
    """
    silence_library_loggers()
    try:
        if elevated():
            print(ELEVATED_WARNING, file=sys.stderr)
        parser = build_parser()
        try:
            args = parser.parse_args(argv)
        except SystemExit as stop:  # --help, --version and refusals end here
            return int(stop.code or 0)
        command: str = args.command
        return COMMANDS[command](args)
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return ExitCode.STOPPED
    except Exception as error:  # noqa: BLE001 (the top-level handler, story 91)
        print(describe_internal_error(error), file=sys.stderr)
        return ExitCode.INTERNAL_ERROR
