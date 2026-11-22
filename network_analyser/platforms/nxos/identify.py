"""NX-OS: the facts in `show version`, and the landing roles (stories 57, 59)."""

import re
from typing import Final

from network_analyser.platforms import fields
from network_analyser.platforms.nxos.commands import SHOW_USER_ACCOUNT, SHOW_VERSION
from network_analyser.platforms.textfsm_parse import parse
from network_analyser.records.device import LandingPrivilege, Unknown, VersionFacts
from network_analyser.records.lookup_values import strip_release_suffix

_TEMPLATES: Final = "cisco_nxos"
_ROLES: Final = re.compile(r"^\s*roles:(.*)$", re.MULTILINE)
_ROLE: Final = re.compile(r"[A-Za-z0-9._-]{1,64}")
_NEXUS_SERIES: Final = re.compile(r"\bNexus[0-9]{4}\b")
"""The Nexus series token NX-OS prints beside the model: `cisco Nexus9000 C93180YC-EX
Chassis`. The model alone names no series, so this token is the fallback series source when
`show inventory` is refused (#159)."""
_TOO_LOW_ROLES: Final = frozenset({"priv-0", "priv-1"})
"""Roles that hold no more than user EXEC rights. Any other role may be the exact custom
role of ADR 0005, so it is never flagged here."""


def read_version(text: str) -> VersionFacts:
    """Return the hostname, model, software version, chassis serial and Nexus series token."""
    rows = parse(_TEMPLATES, SHOW_VERSION, text)
    row = rows[0] if rows else None
    return VersionFacts(
        hostname=fields.word(row, "hostname", "hostname"),
        model=fields.word(row, "platform", "model"),
        software_version=fields.word(
            {"os": strip_release_suffix(fields.text(row, "os"))}, "os", "software version"
        ),
        serials=fields.serials(fields.text_list(row, "serial")),
        hardware_series=_hardware_series(text),
    )


def _hardware_series(text: str) -> str | None:
    """Return the one Nexus series token `show version` names; None when none or several."""
    tokens = {found.group(0) for found in _NEXUS_SERIES.finditer(text)}
    return tokens.pop() if len(tokens) == 1 else None


def privilege_command(username: str) -> str | None:
    """Return `show user-account <username>`, or None when the name breaks its pattern."""
    return SHOW_USER_ACCOUNT.fill(username=username)


def read_privilege(text: str) -> LandingPrivilege | Unknown:
    """Read the login's roles from `show user-account`."""
    found = _ROLES.search(text)
    roles = found.group(1).split() if found else []
    if not roles or not all(_ROLE.fullmatch(r) for r in roles):
        return Unknown("show user-account not understood")
    return LandingPrivilege(
        f"roles {', '.join(roles)}", too_low=all(r in _TOO_LOW_ROLES for r in roles)
    )
