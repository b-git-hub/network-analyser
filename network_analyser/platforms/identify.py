"""Identifying the Platform inside one SSH session (stories 57-58; decided on #3).

The SSH identification string is only a hint (`CISCO_WLC` is rejected before login). The
Platform itself is decided after login from `show version`: NX-OS on `Cisco Nexus Operating
System`; IOS/IOS-XE on `Cisco IOS XE Software`, `IOS-XE Software` or `Cisco IOS Software`.
ASA, IOS-XR and anything else are rejected explicitly, so no command a Platform's allow-list
was not written for is ever sent.
"""

import re
from dataclasses import dataclass
from enum import Enum, unique
from typing import Final

from network_analyser.records import Platform

# Checked first, so a banner naming an unsupported Platform always wins.
_REJECTED: Final = (
    ("ASA", re.compile(r"Cisco Adaptive Security Appliance Software")),
    ("FTD", re.compile(r"Cisco Firepower Threat Defense|Cisco Secure Firewall")),
    ("IOS-XR", re.compile(r"Cisco IOS[ -]XR Software")),
)
_SUPPORTED: Final = (
    (Platform.NX_OS, re.compile(r"Cisco Nexus Operating System")),
    (Platform.IOS_XE, re.compile(r"Cisco IOS XE Software|IOS-XE Software|Cisco IOS Software")),
)

# Provisional, from the spec's Sweep gate; confirmed by lab checks A1 and A2.
_SSH_ID_REJECTED: Final = re.compile(r"^SSH-2\.0-CISCO_WLC\b")
_SSH_ID_HINTS: Final = (
    (Platform.IOS_XE, re.compile(r"^SSH-2\.0-Cisco-")),
    (Platform.NX_OS, re.compile(r"^SSH-2\.0-OpenSSH_\S+ FIPS\b")),
)

# `host(config)#`, `host(config-if)#`, `host(config-router)#` and so on (story 55).
_CONFIG_PROMPT: Final = re.compile(r"\(config[^)]*\)#\s*$")


@dataclass(frozen=True, slots=True)
class Unsupported:
    """A device identified after login as a Platform v1 does not support.

    Attributes:
        name: `ASA`, `FTD`, `IOS-XR` or `unrecognised`.
    """

    name: str


@unique
class Hint(Enum):
    """What the SSH identification string says before login, beyond a Platform."""

    REJECT = "rejected before login"
    """A wireless LAN controller (`CISCO_WLC`): never logged into."""


def identify(show_version: str) -> Platform | Unsupported:
    """Return the Platform `show version` names, or why it is not supported."""
    for name, pattern in _REJECTED:
        if pattern.search(show_version):
            return Unsupported(name)
    for platform, pattern in _SUPPORTED:
        if pattern.search(show_version):
            return platform
    return Unsupported("unrecognised")


def ssh_id_hint(ssh_id: str) -> Platform | Hint | None:
    """Return what the identification string suggests; None when it suggests nothing."""
    if _SSH_ID_REJECTED.match(ssh_id):
        return Hint.REJECT
    return next((p for p, pattern in _SSH_ID_HINTS if pattern.match(ssh_id)), None)


def is_config_prompt(prompt: str) -> bool:
    """Say whether a prompt is a configuration-mode prompt (story 55)."""
    return _CONFIG_PROMPT.search(prompt) is not None
