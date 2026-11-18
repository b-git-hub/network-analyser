"""The IOS/IOS-XE allow-list: every command the tool may ever send to a Catalyst.

Compiled in, never read from a file (story 56). Adding a command is a breaking change
(decision #32): bump the minor version and list it in CHANGELOG.md. Ticket #49 holds only
what identification needs; later tickets add entries.
"""

from typing import Final

from network_analyser.platforms.allowlist import AllowList, Exact

TERMINAL_LENGTH: Final = "terminal length 0"
TERMINAL_WIDTH: Final = "terminal width 511"
SHOW_VERSION: Final = "show version"
SHOW_PRIVILEGE: Final = "show privilege"
"""Reports the landing privilege level (provisional: lab checks A5 and C6)."""

ALLOW_LIST: Final = AllowList(
    (
        Exact(TERMINAL_LENGTH),
        Exact(TERMINAL_WIDTH),
        Exact(SHOW_VERSION),
        Exact(SHOW_PRIVILEGE),
    )
)
