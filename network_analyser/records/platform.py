"""Platforms, and the plain view of a Credential Set (GLOSSARY.md; ADR 0003).

v1 supports two Platforms (CLAUDE.md: Cisco only). Their names are the ones the operator
sees in the Platform-limit menu, the Ready-to-start block and the Run report.
"""

from dataclasses import dataclass
from enum import Enum, unique


@unique
class Platform(Enum):
    """A supported Platform: the operating system family that decides the commands sent."""

    IOS_XE = "IOS/IOS-XE"
    NX_OS = "NX-OS"


@dataclass(frozen=True, slots=True)
class CredentialSetView:
    """What may be shown or recorded about a Credential Set: never its password.

    Usernames are not secret (decided on #6). Not even the password's length is here.

    Attributes:
        number: the set's place in the order the operator gave, from 1.
        username: the username, as typed.
        platform_limit: the only Platform the set is tried on; None for any Platform.
    """

    number: int
    username: str
    platform_limit: Platform | None


@dataclass(frozen=True, slots=True)
class CredentialSetResult:
    """How one Credential Set fared this Run, for the summary and the Run report (#54).

    Attributes:
        view: the set, as it may be shown.
        successes: logins it made.
        failures: failed logins it spent of its failure budget.
        retired: True once it is a Retired Credential Set.
    """

    view: CredentialSetView
    successes: int
    failures: int
    retired: bool
