"""What an internal error shows: the exception type and a file:line stack, nothing else.

Exception text can quote device output or a secret (Netmiko's read timeouts quote device
output), so it is never printed, and neither are local variables or source lines (spec #37,
story 91; decision #30). `faulthandler` stays off.
"""

import sys
import threading
import types

from network_analyser.cli.parser import PROG

_PACKAGE = "network_analyser"


def describe_internal_error(error: BaseException) -> str:
    """Return the short message for an internal error, without its text or values."""
    kind = type(error)
    name = (
        kind.__qualname__
        if kind.__module__ == "builtins"
        else f"{kind.__module__}.{kind.__qualname__}"
    )
    lines = [
        (
            f"{PROG}: internal error ({name}). Its details are not shown, in case they hold a "
            "secret or device output. Where it happened:"
        ),
    ]
    lines.extend(f"  {location}" for location in _stack(error.__traceback__))
    return "\n".join(lines)


def _stack(trace: types.TracebackType | None) -> list[str]:
    locations: list[str] = []
    while trace is not None:
        locations.append(f"{_short_path(trace.tb_frame.f_code.co_filename)}:{trace.tb_lineno}")
        trace = trace.tb_next
    return locations


def _short_path(filename: str) -> str:
    """Show our own files from the package folder down, and any other file by name only.

    A full path can name the operator's user folder, and it adds nothing to a bug report.
    """
    parts = filename.replace("\\", "/").split("/")
    if _PACKAGE in parts:
        start = len(parts) - 1 - parts[::-1].index(_PACKAGE)
        return "/".join(parts[start:])
    return parts[-1]


def install_crash_hooks() -> None:
    """Route every uncaught exception, in any thread, through `describe_internal_error`."""
    sys.excepthook = _excepthook
    threading.excepthook = _thread_excepthook
    sys.unraisablehook = _unraisablehook


def _excepthook(
    _kind: type[BaseException], error: BaseException, _trace: types.TracebackType | None
) -> None:
    print(describe_internal_error(error), file=sys.stderr)


def _thread_excepthook(hook_args: threading.ExceptHookArgs) -> None:
    if hook_args.exc_value is not None:
        print(describe_internal_error(hook_args.exc_value), file=sys.stderr)


def _unraisablehook(unraisable: sys.UnraisableHookArgs) -> None:
    if unraisable.exc_value is not None:
        print(describe_internal_error(unraisable.exc_value), file=sys.stderr)
