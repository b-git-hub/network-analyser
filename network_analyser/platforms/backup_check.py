"""What every Platform's Backup acceptance check shares (ticket #51; story 95).

A reply counts as a Backup only if no error came back, its framing is right for the
Platform and it has a `hostname` line. Each reason is fixed text and never quotes the
device's reply: the config holds secrets, and it goes only to `backup_store`.
"""

import re
from typing import Final

NO_FULL_CONFIG: Final = "the account cannot read the full running config"
"""An error, or nothing, came back (story 97)."""
INCOMPLETE: Final = "the running config came back incomplete"
"""The Platform's framing is missing, so the config may have been cut short."""
NO_HOSTNAME: Final = "the running config has no hostname line"

# An error comes back in place of the config, so it shows on the first line: a caret under
# the failed word, a `%` message, or a command-authorisation refusal (TACACS+). A `%` line
# further down may be part of a banner, so it is never read as an error.
_ERROR_FIRST_LINE: Final = re.compile(
    r"^\s*\^\s*$|^\s*%|authori[sz]ation failed|permission denied", re.IGNORECASE
)
_HOSTNAME: Final = re.compile(r"^hostname \S+$", re.MULTILINE)


def lines(text: str) -> list[str]:
    """Return the reply's non-blank lines, trailing spaces removed."""
    return [line.rstrip() for line in text.splitlines() if line.strip()]


def common_problem(text: str) -> str | None:
    """Return why the reply is an error or has no hostname, or None."""
    shown = lines(text)
    if not shown or _ERROR_FIRST_LINE.search(shown[0]):
        return NO_FULL_CONFIG
    return None


def hostname_problem(text: str) -> str | None:
    """Return NO_HOSTNAME when the config has no top-level `hostname` line, else None."""
    return None if _HOSTNAME.search(text) else NO_HOSTNAME
