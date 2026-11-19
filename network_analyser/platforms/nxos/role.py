"""The NX-OS Device Role: one custom role cut exactly to the allow-list (story 169; ADR 0005).

Cisco's NX-OS RBAC guide: a role holds up to 256 rules, `rule <n> permit command <string>`;
a user's roles are unioned, so the account must hold this role only, never
`network-operator` (which NX-OS may give a new account by default) and never a
`permit read` rule (which also opens `debug`). The allow-list's own session set-up,
`terminal length 0` and `terminal width 511`, is on it, so the role permits it too. TACACS+
names the role with `shell:roles`; TACACS+ command authorisation switches the role checks
off, so the ISE command set then becomes the only command check.
"""

from typing import Final

from network_analyser.platforms.allowlist import AllowList
from network_analyser.platforms.nxos.commands import ALLOW_LIST
from network_analyser.platforms.roles import (
    RADIUS_NOTE,
    ROLE_NAME,
    USERNAME_PLACEHOLDER,
    RoleError,
    header,
    ise_command_set_rows,
    role_commands,
)

MAX_RULES: Final = 256


def role_snippet(username: str | None, *, tacacs: bool, allow_list: AllowList = ALLOW_LIST) -> str:
    """Return the custom role, local or TACACS+ form, permitting exactly `allow_list`."""
    commands = role_commands(allow_list, username)
    if len(commands) > MAX_RULES:
        msg = "an NX-OS role holds at most 256 rules"
        raise RoleError(msg)
    account = USERNAME_PLACEHOLDER if username is None else username
    lines = header(
        "NX-OS",
        account,
        [
            "One custom role that permits exactly the commands the tool sends, and no",
            "more, including its session set-up (terminal length 0, terminal width 511).",
            "It never uses network-operator or a read rule.",
        ],
    )
    lines += ["!"]
    if tacacs:
        lines += ["! On each device, define the role locally: TACACS+ only names it.", "!"]
    lines += [f"role name {ROLE_NAME}", "  description Network Analyser read-only Device Role"]
    lines += [f"  rule {n} permit command {c}" for n, c in enumerate(commands, start=1)]
    lines += ["!"]
    lines += _tacacs_part(commands, account) if tacacs else _local_part(account)
    return "\n".join(lines) + "\n"


def _local_part(account: str) -> list[str]:
    return [
        "! Then create the account with this role only, typing its password by hand.",
        "! NX-OS may give a new account network-operator by default, so take it away:",
        f"!   username {account} password <password> role {ROLE_NAME}",
        f"!   no username {account} role network-operator",
        f'! "show user-account {account}" must then list {ROLE_NAME} as its only role.',
        "!",
        *_reapply(),
    ]


def _reapply() -> list[str]:
    return [
        "! To re-apply after an upgrade, also remove any rule in the role that is not",
        '! listed above ("no rule <number>").',
    ]


def _tacacs_part(commands: tuple[str, ...], account: str) -> list[str]:
    return [
        "! On ISE (Work Centers > Device Administration > Policy Elements > Results):",
        "!",
        f'! TACACS Profile "{ROLE_NAME}", in its Raw View, which gives the account this',
        "! role only:",
        f'!   shell:roles="{ROLE_NAME}"',
        "!",
        f'! TACACS Command Set "{ROLE_NAME}", with "Permit any command that is not listed',
        "! below\" unticked. Each row's arguments are an anchored regular expression,",
        "! so the row permits that one command only:",
        *ise_command_set_rows(commands),
        "!",
        f"! Then a device administration authorisation rule for {account} that returns",
        "! this profile and this command set. If a local account has the same name,",
        "! NX-OS applies that account's roles instead, so give it this role only.",
        "!",
        '! Turning on TACACS+ command authorisation ("aaa authorization commands default',
        "! group <your TACACS+ group>\") switches the device's role checks off, default",
        "! roles included, so this command set becomes the only command check.",
        "!",
        *_reapply(),
        "!",
        RADIUS_NOTE,
    ]
