"""What a Sweep found, kept for the Run report (ticket #55; story 71).

`device_gateway` probes, `discovery` decides which addresses may be logged into, and the
report (#66) lists every probe. The identification string is printable ASCII. No probe
result holds a password or a live socket.
"""

from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address


@unique
class ProbeFailure(Enum):
    """Why a Sweep probe did not read an SSH identification string."""

    TIMED_OUT = "timed out"
    REFUSED = "refused"
    UNREACHABLE = "unreachable"
    FAILED = "failed"
    NO_BANNER = "no SSH identification string"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """One TCP port 22 probe, closed before key exchange.

    Attributes:
        ip: the address probed.
        open: whether TCP connected.
        ssh_id: the server's identification string, printable; None when none was read.
        failure: why no identification string was read; None when one was.
    """

    ip: IPv4Address
    open: bool
    ssh_id: str | None
    failure: ProbeFailure | None


@dataclass(frozen=True, slots=True)
class SweepResult:
    """Every probe, in ascending address order, and the addresses a Sweep may log into.

    Attributes:
        probes: one result per address the Scope allows, lowest address first.
        login_seeds: addresses whose identification string matches a supported Platform,
            in ascending order. The operator's own Seeds are not included here: they are
            logged into even when the banner does not match (story 64).
    """

    probes: tuple[ProbeResult, ...]
    login_seeds: tuple[IPv4Address, ...]
