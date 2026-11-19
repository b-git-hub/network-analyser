"""The IOS/IOS-XE Device Role: a CLI view cut exactly to the allow-list (story 168; ADR 0005).

Cisco's Role-Based CLI Access guide: a view made without `inclusive` starts empty and holds
only the commands added with `commands exec include` (without `all`, no subcommands); it
needs `aaa new-model`, root view, and a `secret` before commands can be added. A local user
is placed in it with `username <name> view <view>`; TACACS+ with the `cli-view-name`
attribute. The fallback, for a device that cannot take a view, is a custom privilege level;
Cisco's subset rule then moves each command's shorter forms with it, so the snippet puts
the first keywords back at level 1. `file privilege` is never set (ADR 0005: a STIG finding,
and it may let the level write files).
"""

from typing import Final

from network_analyser.platforms.allowlist import AllowList
from network_analyser.platforms.ios_xe.commands import ALLOW_LIST
from network_analyser.platforms.roles import (
    RADIUS_NOTE,
    ROLE_NAME,
    USERNAME_PLACEHOLDER,
    RoleError,
    header,
    ise_command_set_rows,
    role_commands,
)

FALLBACK_LEVEL: Final = 7
_TYPE_9_HASHING: Final = "algorithm-type scrypt secret <password>"
"""Cisco's hardening guide: a type 9 (scrypt) secret for every local account."""
_USER_LEVEL: Final = 1
_LEVEL_1_KEYWORDS: Final = frozenset({"show", "terminal"})
"""First keywords that sit at level 1 by default, so may be put back there. A command that
starts with any other keyword needs its default level checked before it joins this list."""


def role_snippet(username: str | None, *, tacacs: bool, allow_list: AllowList = ALLOW_LIST) -> str:
    """Return the CLI view, local or TACACS+ form, permitting exactly `allow_list`."""
    commands = role_commands(allow_list, username)
    account = USERNAME_PLACEHOLDER if username is None else username
    lines = header(
        "IOS/IOS-XE",
        account,
        ["A CLI view that permits exactly the commands the tool sends, and no more."],
    )
    lines += _before_you_paste(tacacs=tacacs)
    lines += [f"parser view {ROLE_NAME}"]
    lines += [f" commands exec include {command}" for command in commands]
    lines += ["!"]
    if tacacs:
        lines += _tacacs_part(commands, account)
    else:
        lines += _local_part(commands, account)
    return "\n".join(lines) + "\n"


def _before_you_paste(*, tacacs: bool) -> list[str]:
    group = "group <your TACACS+ group> local" if tacacs else "local"
    return [
        "!",
        "! The view needs aaa new-model, and exec authorisation that places the account",
        "! in its view at login, for example:",
        f"!   aaa authorization exec default {group}",
        "! Check your existing AAA method lists first and keep a second session open.",
        "! Cisco advises never removing aaa new-model once it is set.",
        "!",
        '! Work in root view ("enable view"). Set the view secret by hand first, never',
        "! pasting a secret:",
        f"!   parser view {ROLE_NAME}",
        "!    secret <view secret>",
        "!",
    ]


def _local_part(commands: tuple[str, ...], account: str) -> list[str]:
    return [
        "! Then create the account, typing its password by hand:",
        f"!   username {account} view {ROLE_NAME} {_TYPE_9_HASHING}",
        "!",
        *_reapply_and_file_privilege(),
        "!",
        *_fallback(commands, account),
    ]


def _reapply_and_file_privilege() -> list[str]:
    return [
        "! To re-apply after an upgrade, also remove any commands line in the view that",
        "! is not listed above.",
        "!",
        "! This role never sets file privilege: the DISA STIG flags any value but 15, and",
        "! it may let the level write files. Where show running-config view full prints",
        "! nothing without it, use the TACACS+ form at level 15 instead (role-snippet",
        "! ios-xe --tacacs); a local-only site gets no full Backup from that device.",
    ]


def _fallback(commands: tuple[str, ...], account: str) -> list[str]:
    keywords = list(dict.fromkeys(command.split()[0] for command in commands))
    if not set(keywords) <= _LEVEL_1_KEYWORDS:
        msg = "an allow-list command starts with a keyword whose default level is unchecked"
        raise RoleError(msg)
    return [
        "! Fallback, only for a device that cannot take aaa new-model or a view: a",
        f"! custom privilege level {FALLBACK_LEVEL}. It changes command levels for every user",
        "! on the device, and the account can also run every level 1 command.",
        "! Cisco's subset rule moves each command's shorter forms too, so the last lines",
        "! put the first keywords back at level 1. Paste these lines without the leading",
        "! '!' and spaces, and type the username line by hand:",
        *(f"!   privilege exec level {FALLBACK_LEVEL} {command}" for command in commands),
        *(f"!   privilege exec level {_USER_LEVEL} {keyword}" for keyword in keywords),
        f"!   username {account} privilege {FALLBACK_LEVEL} {_TYPE_9_HASHING}",
    ]


def _tacacs_part(commands: tuple[str, ...], account: str) -> list[str]:
    return [
        "! On ISE (Work Centers > Device Administration > Policy Elements > Results):",
        "!",
        f'! TACACS Profile "{ROLE_NAME}", in its Raw View, which places the account in',
        "! the view:",
        f"!   cli-view-name={ROLE_NAME}",
        "!",
        f'! TACACS Command Set "{ROLE_NAME}", with "Permit any command that is not listed',
        "! below\" unticked. Each row's arguments are an anchored regular expression,",
        "! so the row permits that one command only:",
        *ise_command_set_rows(commands),
        "!",
        f"! Then a device administration authorisation rule for {account} that returns",
        "! this profile and this command set.",
        "!",
        "! The command set is checked only where TACACS+ command authorisation is on",
        '! ("aaa authorization commands <level> default group <your TACACS+ group>").',
        "! A command in the view must then also pass the command set.",
        "!",
        "! Where show running-config view full needs a file privilege (ADR 0005), return",
        "! priv-lvl=15 in the profile instead of the view, with command authorisation",
        "! for level 15. Turning that on makes the command set the only check, and a",
        "! local fallback account at level 15 is unrestricted.",
        "!",
        *_reapply_and_file_privilege()[:2],
        "!",
        RADIUS_NOTE,
    ]
