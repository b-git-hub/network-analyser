"""Exit codes for every command: the one place they are defined (spec #37, story 90)."""

from enum import IntEnum, unique


@unique
class ExitCode(IntEnum):
    """What a command's exit code tells a script about how it ended."""

    CLEAN = 0
    """Finished; nothing needs attention."""

    NEEDS_ATTENTION = 1
    """Finished; something needs attention (listed at the end and in the Run report)."""

    REFUSED = 2
    """Refused before any device was contacted (bad options, Scope or Seeds, and so on)."""

    STOPPED = 3
    """Stopped or cancelled by the operator (Ctrl+C, or "n" at the confirm)."""

    INTERNAL_ERROR = 4
    """Internal error: a short message, never a traceback with values."""
