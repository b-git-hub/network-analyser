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
_RELEASE: Final = re.compile(r"^(\d{1,3})\.(\d{1,3})(?:\.(\d{1,3}))?")
_INSECURE_CONFIGURATION_FLOOR: Final = (17, 18, 2)
"""The first IOS-XE release with `show system insecure configuration` (story 68; #97)."""
_ROUTER_OPERATING_MODE: Final = re.compile(
    r"^\s*Router operating mode:\s*([A-Za-z][A-Za-z -]{0,30}[A-Za-z])\s*$",
    re.IGNORECASE | re.MULTILINE,
)
"""Cisco's `Router operating mode:` line, which an SD-WAN edge router prints (#147).

The value is kept as a short word or phrase only, so arbitrary device text never reaches a
record. The line is absent on classic IOS and Catalyst 9000 switches, so absence is None.
"""
_LOWEST_WORKING_LEVEL: Final = 2
"""Levels 0 and 1 are user EXEC: too low for any Backup (ADR 0005). Any higher level may
be the custom-level fallback, so it is never flagged here."""


def supports_insecure_configuration(version: VersionFacts) -> bool:
    """Say whether the release can run `show system insecure configuration` (story 68).

    True only for IOS-XE 17.18.2 and later. A classic IOS release (`15.2(7)E7`) and an
    unreadable one are always False, so an older or unknown device is never sent a command
    it may not have.
    """
    shown = version.software_version
    if isinstance(shown, Unknown):
        return False
    match = _RELEASE.match(shown)
    if match is None:
        return False
    numbers = (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))
    return numbers >= _INSECURE_CONFIGURATION_FLOOR


def is_router(version: VersionFacts) -> bool:
    """Say whether `show version` marks the device as an IOS-XE router (#72).

    Only a router prints `Router operating mode:` (autonomous or controller-managed); a
    Catalyst switch and classic IOS print none, so an unmarked device keeps every switch
    command and no switch data is ever skipped on a guess.
    """
    return version.router_operating_mode is not None


def read_version(text: str) -> VersionFacts:
    """Return the hostname, model, software version, stack serials and operating mode."""
    rows = parse(_TEMPLATES, SHOW_VERSION, text)
    row = rows[0] if rows else None
    mode = _ROUTER_OPERATING_MODE.search(text)
    return VersionFacts(
        hostname=fields.word(row, "hostname", "hostname"),
        model=fields.word(row, "hardware", "model"),
        software_version=fields.word(row, "version", "software version"),
        serials=fields.serials(fields.text_list(row, "serial")),
        router_operating_mode=None if mode is None else mode.group(1),
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
