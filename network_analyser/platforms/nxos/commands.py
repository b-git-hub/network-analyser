"""The NX-OS allow-list: every command the tool may ever send to a Nexus.

Compiled in, never read from a file (story 56). Adding a command is a breaking change
(decision #32): bump the minor version and list it in CHANGELOG.md. Ticket #49 holds only
what identification needs; later tickets add entries.
"""

from typing import Final

from network_analyser.platforms.allowlist import AllowList, Exact, Template

TERMINAL_LENGTH: Final = "terminal length 0"
TERMINAL_WIDTH: Final = "terminal width 511"
SHOW_VERSION: Final = "show version"

USERNAME_PATTERN: Final = r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}"
"""An NX-OS username: a letter or digit, then letters, digits, `.`, `_` or `-`, 32 at most."""

SHOW_USER_ACCOUNT: Final = Template("show user-account {username}", {"username": USERNAME_PATTERN})
"""Reports the login's own roles (provisional: lab checks A5 and C10)."""
SHOW_RUNNING_CONFIG: Final = "show running-config"
"""The Backup (#51): the running config as NX-OS shows it."""
SHOW_CDP_NEIGHBORS_DETAIL: Final = "show cdp neighbors detail | json"
SHOW_LLDP_NEIGHBORS_DETAIL: Final = "show lldp neighbors detail | json"
"""The CDP and LLDP Neighbours the crawl follows (#50; the `| json` forms are provisional)."""

ALLOW_LIST: Final = AllowList(
    (
        Exact(TERMINAL_LENGTH),
        Exact(TERMINAL_WIDTH),
        Exact(SHOW_VERSION),
        SHOW_USER_ACCOUNT,
        Exact(SHOW_RUNNING_CONFIG),
        Exact(SHOW_CDP_NEIGHBORS_DETAIL),
        Exact(SHOW_LLDP_NEIGHBORS_DETAIL),
    )
)
