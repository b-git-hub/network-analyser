"""IOS/IOS-XE: the facts in `show version`, and the landing privilege (stories 57, 59)."""

import re
from typing import Final

from network_analyser.platforms import fields
from network_analyser.platforms.ios_xe.commands import SHOW_PRIVILEGE, SHOW_VERSION
from network_analyser.platforms.textfsm_parse import parse
from network_analyser.records.device import LandingPrivilege, Unknown, VersionFacts

_TEMPLATES: Final = "cisco_ios"
_LEVEL: Final = re.compile(r"privilege level (?:is )?(\d{1,2})\b", re.IGNORECASE)
_VIEW: Final = re.compile(r"\bview\b", re.IGNORECASE)
_LOWEST_WORKING_LEVEL: Final = 2
"""Levels 0 and 1 are user EXEC: too low for any Backup (ADR 0005). Any higher level may
be the custom-level fallback, so it is never flagged here."""


def read_version(text: str) -> VersionFacts:
    """Return the hostname, model, software version and every stack serial."""
    rows = parse(_TEMPLATES, SHOW_VERSION, text)
    row = rows[0] if rows else None
    return VersionFacts(
        hostname=fields.word(row, "hostname", "hostname"),
        model=fields.word(row, "hardware", "model"),
        software_version=fields.word(row, "version", "software version"),
        serials=fields.serials(fields.text_list(row, "serial")),
    )


def privilege_command(_username: str) -> str:
    """Return the command that reports the landing privilege."""
    return SHOW_PRIVILEGE


def read_privilege(text: str) -> LandingPrivilege | Unknown:
    """Read `show privilege`: a level, or a CLI view's context (ADR 0005).

    A view is cut to the allow-list by the operator, so it is never flagged as too low.
    """
    level = _LEVEL.search(text)
    if level is None:
        return Unknown("show privilege not understood")
    number = int(level.group(1))
    if _VIEW.search(text):
        return LandingPrivilege(f"view, level {number}", too_low=False)
    return LandingPrivilege(f"level {number}", too_low=number < _LOWEST_WORKING_LEVEL)
