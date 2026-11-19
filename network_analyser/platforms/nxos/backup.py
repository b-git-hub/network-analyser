"""NX-OS: is a `show running-config` reply a whole config? (#51; story 95).

The framing is the `version` line NX-OS puts at the top of every running config.
"""

import re
from typing import Final

from network_analyser.platforms.backup_check import INCOMPLETE, common_problem, hostname_problem

_VERSION: Final = re.compile(r"^version \S+", re.MULTILINE)


def backup_problem(text: str) -> str | None:
    """Return why `text` is not a whole NX-OS running config, or None when it is."""
    problem = common_problem(text)
    if problem is not None:
        return problem
    if not _VERSION.search(text):
        return INCOMPLETE
    return hostname_problem(text)
