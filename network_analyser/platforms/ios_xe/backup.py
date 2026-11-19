"""IOS/IOS-XE: is a `show running-config view full` reply a whole config? (#51; story 95).

The framing is the header (`Current configuration : N bytes`, after an optional `Building
configuration...`) and a closing `end` as the last line: a reply cut short loses its `end`.
"""

import re
from typing import Final

from network_analyser.platforms.backup_check import (
    INCOMPLETE,
    common_problem,
    hostname_problem,
    lines,
)

_BUILDING: Final = "Building configuration..."
_HEADER: Final = re.compile(r"Current configuration : \d+ bytes")


def backup_problem(text: str) -> str | None:
    """Return why `text` is not a whole IOS/IOS-XE running config, or None when it is."""
    problem = common_problem(text)
    if problem is not None:
        return problem
    shown = lines(text)
    head = shown[1:] if shown[0] == _BUILDING else shown
    if not head or not _HEADER.fullmatch(head[0]) or shown[-1] != "end":
        return INCOMPLETE
    return hostname_problem(text)
