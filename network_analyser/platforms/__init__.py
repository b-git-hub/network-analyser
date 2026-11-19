"""The `platforms` module: what the tool knows about each supported Platform.

One subpackage per Platform (`ios_xe`, `nxos`), built in: identification patterns, the
compiled-in command allow-list, parsers from command output to plain records, the
Backup acceptance check and role-snippet generation (ADR 0005). Nothing is loaded from
a plugins folder. Calls no other module.

`device_gateway`'s one gate asks `permits(platform, command)` before every command. Before
the Platform is known (platform None), only the commands every Platform allows may be sent:
the session set-up and `show version`.
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from network_analyser.platforms import neighbours
from network_analyser.platforms.allowlist import AllowList, Exact, Template
from network_analyser.platforms.collection import Collection, Problem, Send
from network_analyser.platforms.hints import neighbour_hint
from network_analyser.platforms.identify import (
    Hint,
    Unsupported,
    identify,
    is_config_prompt,
    ssh_id_hint,
)
from network_analyser.platforms.ios_xe import backup as ios_xe_backup
from network_analyser.platforms.ios_xe import collect as ios_xe_collect
from network_analyser.platforms.ios_xe import commands as ios_xe_commands
from network_analyser.platforms.ios_xe import identify as ios_xe
from network_analyser.platforms.ios_xe import role as ios_xe_role
from network_analyser.platforms.neighbours import NeighbourProtocol
from network_analyser.platforms.nxos import backup as nxos_backup
from network_analyser.platforms.nxos import collect as nxos_collect
from network_analyser.platforms.nxos import commands as nxos_commands
from network_analyser.platforms.nxos import identify as nxos
from network_analyser.platforms.nxos import role as nxos_role
from network_analyser.platforms.roles import RoleError, username_problem
from network_analyser.records import Platform
from network_analyser.records.collected import Neighbour
from network_analyser.records.device import LandingPrivilege, Unknown, VersionFacts

ALLOW_LISTS: Final[Mapping[Platform, AllowList]] = MappingProxyType(
    {
        Platform.IOS_XE: ios_xe_commands.ALLOW_LIST,
        Platform.NX_OS: nxos_commands.ALLOW_LIST,
    }
)

SESSION_SETUP: Final = (ios_xe_commands.TERMINAL_LENGTH, ios_xe_commands.TERMINAL_WIDTH)
"""The session set-up, sent before identification: paging off, then the widest lines."""
SHOW_VERSION: Final = ios_xe_commands.SHOW_VERSION

_BEFORE_IDENTIFICATION: Final = frozenset.intersection(
    *(a.exact_commands for a in ALLOW_LISTS.values())
)


def permits(platform: Platform | None, command: str) -> bool:
    """Say whether `command` may be sent, exactly as given, to a device of `platform`.

    With None (not identified yet), only exact commands on every Platform's list pass.
    """
    if platform is None:
        return command in _BEFORE_IDENTIFICATION
    return ALLOW_LISTS[platform].permits(command)


def read_version(platform: Platform, text: str) -> VersionFacts:
    """Return what `show version` says: hostname, model, software version, serials."""
    reader = ios_xe.read_version if platform is Platform.IOS_XE else nxos.read_version
    return reader(text)


def privilege_command(platform: Platform, username: str) -> str | None:
    """Return the command that reports the landing privilege; None if none fits."""
    if platform is Platform.IOS_XE:
        return ios_xe.privilege_command(username)
    return nxos.privilege_command(username)


def read_privilege(platform: Platform, text: str) -> LandingPrivilege | Unknown:
    """Read the landing privilege from the output of `privilege_command`."""
    reader = ios_xe.read_privilege if platform is Platform.IOS_XE else nxos.read_privilege
    return reader(text)


_NEIGHBOUR_COMMANDS: Final[Mapping[Platform, tuple[tuple[NeighbourProtocol, str], ...]]] = (
    MappingProxyType(
        {
            Platform.IOS_XE: (
                (NeighbourProtocol.CDP, ios_xe_commands.SHOW_CDP_NEIGHBORS_DETAIL),
                (NeighbourProtocol.LLDP, ios_xe_commands.SHOW_LLDP_NEIGHBORS_DETAIL),
            ),
            Platform.NX_OS: (
                (NeighbourProtocol.CDP, nxos_commands.SHOW_CDP_NEIGHBORS_DETAIL),
                (NeighbourProtocol.LLDP, nxos_commands.SHOW_LLDP_NEIGHBORS_DETAIL),
            ),
        }
    )
)
_NEIGHBOUR_READERS: Final = MappingProxyType(
    {
        (Platform.IOS_XE, NeighbourProtocol.CDP): neighbours.read_ios_cdp,
        (Platform.IOS_XE, NeighbourProtocol.LLDP): neighbours.read_ios_lldp,
        (Platform.NX_OS, NeighbourProtocol.CDP): neighbours.read_nxos_cdp,
        (Platform.NX_OS, NeighbourProtocol.LLDP): neighbours.read_nxos_lldp,
    }
)
NEIGHBOUR_PARSER: Final = "Network Analyser neighbour reader"
"""The parser's name in a `parse_failed` Audit log event for a CDP or LLDP table."""


def neighbour_commands(platform: Platform) -> tuple[tuple[NeighbourProtocol, str], ...]:
    """Return the CDP then LLDP neighbour-detail command for `platform` (#50)."""
    return _NEIGHBOUR_COMMANDS[platform]


def read_neighbours(
    platform: Platform, protocol: NeighbourProtocol, text: str
) -> tuple[Neighbour, ...] | Unknown:
    """Read a CDP or LLDP neighbour-detail table; unknown when refused or not understood."""
    return _NEIGHBOUR_READERS[platform, protocol](text)


def backup_command(platform: Platform) -> str:
    """Return the command whose reply is the Backup (#51; story 96)."""
    if platform is Platform.IOS_XE:
        return ios_xe_commands.SHOW_RUNNING_CONFIG
    return nxos_commands.SHOW_RUNNING_CONFIG


def backup_problem(platform: Platform, text: str) -> str | None:
    """Return why a reply to `backup_command` is not a Backup, as fixed text; None if it is.

    It is one only if no error came back, its framing is right and it has a `hostname`
    line (story 95). The reason never quotes the reply.
    """
    check = (
        ios_xe_backup.backup_problem if platform is Platform.IOS_XE else nxos_backup.backup_problem
    )
    return check(text)


def collect(platform: Platform, send: Send, version: VersionFacts) -> Collection | None:
    """Send `platform`'s collection commands through `send`; return what they told the tool.

    Every part of the result is a reading or unknown (#52); a denied or unreadable command
    leaves its own data unknown and is listed as a problem, never ending the visit. None
    when this version of the tool collects nothing from `platform`.
    """
    if platform is Platform.NX_OS:
        return nxos_collect.collect(send, version)
    return ios_xe_collect.collect(send, version)


def role_snippet(platform: Platform, username: str | None, *, tacacs: bool) -> str:
    """Return the Device Role for `platform`, generated from its allow-list (ADR 0005).

    Local form, or with `tacacs` the TACACS+ form (an ISE profile and command set). With
    no `username`, a placeholder stands for the account's name. Only text: nothing here
    configures a device.
    """
    if platform is Platform.IOS_XE:
        return ios_xe_role.role_snippet(username, tacacs=tacacs)
    return nxos_role.role_snippet(username, tacacs=tacacs)


def role_username_problem(username: str) -> str | None:
    """Return why `username` cannot go in a Device Role snippet, or None when it can."""
    return username_problem(username)


__all__ = [
    "ALLOW_LISTS",
    "NEIGHBOUR_PARSER",
    "SESSION_SETUP",
    "SHOW_VERSION",
    "AllowList",
    "Collection",
    "Exact",
    "Hint",
    "NeighbourProtocol",
    "Problem",
    "RoleError",
    "Send",
    "Template",
    "Unsupported",
    "backup_command",
    "backup_problem",
    "collect",
    "identify",
    "is_config_prompt",
    "neighbour_commands",
    "neighbour_hint",
    "permits",
    "privilege_command",
    "read_neighbours",
    "read_privilege",
    "read_version",
    "role_snippet",
    "role_username_problem",
    "ssh_id_hint",
]
