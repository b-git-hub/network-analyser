"""What every Platform's Device Role shares (stories 167-173; ADR 0005; decided on #14).

A Device Role is generated from the compiled-in allow-list, never re-typed, so the role and
the commands the tool sends stay identical (security test 2). The text is only printed;
nothing here, or anywhere in the tool, configures a device (story 170).

Text conventions, so an administrator can paste the whole snippet: a line a device acts on
has no prefix; a prose comment is `! ` then text; a command to type by hand (it holds a
secret, or is optional) is `!` then three or more spaces, then the command.
"""

import re
from typing import Final

from network_analyser.platforms.allowlist import AllowList, Exact

ROLE_NAME: Final = "NA-READ"
"""The CLI view (IOS/IOS-XE) and custom role (NX-OS) the snippet defines."""

USERNAME_PLACEHOLDER: Final = "<username>"
"""Stands for the account's name when `--username` is not given."""

ROLE_USERNAME_PATTERN: Final = r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}"
"""An account name the snippet will print: one word, safe in a device config and on any
console, and the same form NX-OS's `show user-account` template accepts."""

_TEMPLATE_USERNAME: Final = "username"
_ERE_SPECIAL: Final = re.compile(r"([\\.^$*+?()\[\]{}|])")


class RoleError(ValueError):
    """The allow-list holds an entry the role generator cannot express exactly."""


def username_problem(username: str) -> str | None:
    """Return why `username` cannot go in a snippet, or None when it can.

    The reason never quotes the name.
    """
    if re.fullmatch(ROLE_USERNAME_PATTERN, username, flags=re.ASCII):
        return None
    return (
        "the username must be 1 to 32 characters: a letter or digit, then letters, "
        "digits, '.', '_' or '-'"
    )


def role_commands(allow_list: AllowList, username: str | None) -> tuple[str, ...]:
    """Return every command on `allow_list`, in order, as the role must permit it.

    A template whose only parameter is the account's name is filled with `username` (or
    the placeholder). Any other template has no exact role form yet, so it is refused
    rather than widened: the ticket that adds one decides how its role rule looks.
    """
    if username is not None and username_problem(username) is not None:
        msg = "the username does not fit the role-snippet pattern"
        raise RoleError(msg)
    name = USERNAME_PLACEHOLDER if username is None else username
    commands: list[str] = []
    for entry in allow_list.entries:
        if isinstance(entry, Exact):
            commands.append(entry.command)
            continue
        if set(entry.parameters) != {_TEMPLATE_USERNAME}:
            msg = "a template parameter other than the username has no role form yet"
            raise RoleError(msg)
        commands.append(entry.text.replace("{username}", name))
    return tuple(commands)


def ise_command_set_rows(commands: tuple[str, ...]) -> list[str]:
    """Return an ISE TACACS command set permitting exactly `commands`, as comment lines.

    ISE matches a command's first word, then its arguments as a regular expression; an
    unanchored pattern also matches longer argument lists, so each row is anchored and
    escaped to permit one command only. "Permit any command that is not listed below"
    must stay unticked.
    """
    rows = [("Grant", "Command", "Arguments")]
    for command in commands:
        word, _, arguments = command.partition(" ")
        rows.append(("PERMIT", word, f"^{_ERE_SPECIAL.sub(r'\\\1', arguments)}$"))
    width = max(len(word) for _, word, _ in rows)
    return [f"!     {grant:<7} {word:<{width}}  {args}".rstrip() for grant, word, args in rows]


def header(platform_name: str, account: str, what: list[str]) -> list[str]:
    """The opening comment every snippet shares: what it is, and the dedicated account."""
    return [
        f"! Device Role for the Network Analyser account {account} on {platform_name}",
        "! (ADR 0005).",
        *(f"! {line}" for line in what),
        "! The tool only prints this role. It never configures a device.",
        "!",
        "! Give the tool its own dedicated account, used by nothing and nobody else, so",
        "! device and AAA accounting can tell its sessions apart. There is no enable",
        "! step: the account must land at its working rights when it logs in.",
    ]


RADIUS_NOTE: Final = (
    "! RADIUS cannot authorise commands, so use TACACS+, not RADIUS, for this account."
)
