"""One record per device: an IP found to be a device already examined this Run (story 73).

The identity checks run in this order (decided on #10): the Trust Store first (a changed
key is always a hard stop); then the host-key alias check, before any password, when the key
was already seen this Run at another IP; then the chassis serial(s) from `show version`,
before the Backup. CDP Device IDs and hostnames are never used (story 74).
"""

from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address


@unique
class AliasEvidence(Enum):
    """What showed that two IPs are one device."""

    HOST_KEY = "same host key"
    """Seen before login: the session was left before any password was sent."""
    SERIAL = "same chassis serial"
    """Seen after login, in `show version`: the session was left before the Backup."""


@dataclass(frozen=True, slots=True)
class Alias:
    """Another IP of a device already examined this Run; examined (and backed up) once.

    Attributes:
        ip: the address this alias was reached at.
        same_as: the address the device was first examined at.
        evidence: how the tool knows.
    """

    ip: IPv4Address
    same_as: IPv4Address
    evidence: AliasEvidence
