"""What every Platform's Device Role shares (stories 167-173; ADR 0005; decided on #14).

A Device Role is generated from the compiled-in allow-list, never re-typed, so the role and
the commands the tool sends stay identical (security test 2). The text is only printed;
nothing here, or anywhere in the tool, configures a device (story 170).

Text conventions, so an administrator can paste the whole snippet: a line a device acts on
has no prefix; a prose comment is `! ` then text; a command to type by hand (it holds a
secret, or is optional) is `!` then three or more spaces, then the command.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from network_analyser.platforms.allowlist import AllowList, Exact, Template

ROLE_NAME: Final = "NA-READ"
"""The CLI view (IOS/IOS-XE) and custom role (NX-OS) the snippet defines."""

USERNAME_PLACEHOLDER: Final = "<username>"
"""Stands for the account's name when `--username` is not given."""

ROLE_USERNAME_PATTERN: Final = r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}"
"""An account name the snippet will print: one word, safe in a device config and on any
console, and the same form NX-OS's `show user-account` template accepts."""

_TEMPLATE_USERNAME: Final = "username"
_ERE_SPECIAL: Final = re.compile(r"([\\.^$*+?()\[\]{}|])")
_PARAMETER: Final = re.compile(r"\{([a-z_]+)\}")
_ERE_SAFE: Final = re.compile(r"[A-Za-z0-9\[\]{},._:-]+")
"""A parameter pattern ISE can take as it is: bracket classes and counts, no escapes or
groups, so Python and POSIX extended regular expressions read it the same way."""


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


@dataclass(frozen=True, slots=True)
class RoleRule:
    """One allow-list entry as a Device Role permits it.

    Attributes:
        command: what a CLI view, a privilege level or an NX-OS rule names: the exact
            command, or for a template with a parameter other than the username (a VRF name,
            #59) its words before the first parameter. A view or privilege level cannot name
            every value, so the rule stops there (provisional: lab check C14).
        arguments: the anchored regular expression an ISE command set row matches the
            command's arguments (every word after the first) against: the exact arguments,
            or for a template its literal words and each parameter's own pattern.
    """

    command: str
    arguments: str


def role_rules(
    allow_list: AllowList, username: str | None, *, parameters: bool
) -> tuple[RoleRule, ...]:
    """Return every entry on `allow_list`, in order, as the role must permit it.

    A template whose only parameter is the account's name is filled with `username` (or the
    placeholder). A template with any other parameter is refused unless `parameters`, for a
    Platform whose role can express it (IOS/IOS-XE, #59); it is never widened beyond its
    words before the parameter, and its ISE row keeps the parameter's strict pattern.
    """
    if username is not None and username_problem(username) is not None:
        msg = "the username does not fit the role-snippet pattern"
        raise RoleError(msg)
    name = USERNAME_PLACEHOLDER if username is None else username
    rules: list[RoleRule] = []
    for entry in allow_list.entries:
        if isinstance(entry, Exact):
            rules.append(_exact_rule(entry.command))
        elif set(entry.parameters) == {_TEMPLATE_USERNAME}:
            rules.append(_exact_rule(entry.text.replace("{username}", name)))
        elif parameters:
            rules.append(_template_rule(entry))
        else:
            msg = "a template parameter other than the username has no role form yet"
            raise RoleError(msg)
    return tuple(rules)


def role_commands(allow_list: AllowList, username: str | None) -> tuple[str, ...]:
    """Return every command on `allow_list`, in order, as the role must permit it.

    Only exact commands and the username template: any other template is refused rather
    than widened (`role_rules` with `parameters` gives the per-VRF form).
    """
    return tuple(r.command for r in role_rules(allow_list, username, parameters=False))


def _exact_rule(command: str) -> RoleRule:
    _, _, arguments = command.partition(" ")
    return RoleRule(command, f"^{_ERE_SPECIAL.sub(r'\\\1', arguments)}$")


def _template_rule(template: Template) -> RoleRule:
    pieces = _PARAMETER.split(template.text)
    before = pieces[0].rstrip()
    if " " not in before or not pieces[0].endswith(" "):
        msg = "a template's parameter must follow its command's first words"
        raise RoleError(msg)
    if not all(_ERE_SAFE.fullmatch(p) for p in template.parameters.values()):
        msg = "a template parameter's pattern is not a plain regular expression"
        raise RoleError(msg)
    _, _, literal = pieces[0].partition(" ")
    arguments = _ERE_SPECIAL.sub(r"\\\1", literal) + "".join(
        template.parameters[piece] if index % 2 == 0 else _ERE_SPECIAL.sub(r"\\\1", piece)
        for index, piece in enumerate(pieces[1:])
    )
    return RoleRule(before, f"^{arguments}$")


def ise_command_set_rows(commands: Sequence[str | RoleRule]) -> list[str]:
    """Return an ISE TACACS command set permitting exactly `commands`, as comment lines.

    ISE matches a command's first word, then its arguments as a regular expression; an
    unanchored pattern also matches longer argument lists, so each row is anchored and
    escaped to permit one command only. "Permit any command that is not listed below"
    must stay unticked.
    """
    rows = [("Grant", "Command", "Arguments")]
    for command in commands:
        rule = command if isinstance(command, RoleRule) else _exact_rule(command)
        rows.append(("PERMIT", rule.command.partition(" ")[0], rule.arguments))
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
