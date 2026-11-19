"""The device record `device_gateway` hands back, and the values inside it (ticket #49).

One plain record per device the tool tried, with no live session (ADR 0003): the Topology,
Backup and crawl tickets build on it. The running config never rides in it
(spec-37-implementation-calls, call 4). A field that does not apply, because the tool never
got that far, is None; a value the tool tried to learn and could not is `Unknown(reason)`,
never None or empty (CODING_STANDARDS.md, "Data").
"""

from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address

from network_analyser.records.events import DeviceOutcome
from network_analyser.records.host_keys import HostKeyCheck
from network_analyser.records.identity import Alias
from network_analyser.records.neighbour import NeighbourRecord
from network_analyser.records.platform import CredentialSetView, Platform
from network_analyser.records.unknown import Unknown

__all__ = [
    "DeviceRecord",
    "LandingPrivilege",
    "Unknown",
    "UnvisitedReason",
    "VersionFacts",
]


@unique
class UnvisitedReason(Enum):
    """The 13 fixed reasons a device is an Unvisited Device (spec #37, "Discovery and identity").

    Defined once and used everywhere: the report, the Topology and the summary.
    """

    OUTSIDE_SCOPE = "outside Scope"
    EXCLUDED = "excluded by operator"
    IPV6_ONLY = "IPv6 only (not supported in v1)"
    UNSUPPORTED_ADVERTISED = "unsupported Platform (advertised)"
    UNSUPPORTED_IDENTIFIED = "unsupported Platform (identified after login)"
    UNREACHABLE = "unreachable"
    ALGORITHMS_TOO_OLD = "SSH algorithms too old"
    HOST_KEY_CHANGED = "host key changed"
    HOST_KEY_NOT_TRUSTED = "host key not yet trusted (strict mode)"
    AUTHENTICATION_FAILED = "authentication failed (every eligible set tried)"
    SETS_RETIRED = "not attempted (Credential Sets retired)"
    RUN_STOPPED = "not attempted (Run stopped)"
    ROUTING_OR_ARP_ONLY = "seen only in routing or ARP data (not crawled)"


@dataclass(frozen=True, slots=True)
class LandingPrivilege:
    """The privilege a login landed with, as the device reported it (story 59; ADR 0005).

    Attributes:
        shown: what to show, such as `level 15`, `view NA-READ` or `roles NA-READ`.
        too_low: True only when it is too low for the tool's commands. A privilege higher
            than needed is never flagged.
    """

    shown: str
    too_low: bool


@dataclass(frozen=True, slots=True)
class VersionFacts:
    """What `show version` says about a device (ticket #49)."""

    hostname: str | Unknown
    model: str | Unknown
    software_version: str | Unknown
    serials: tuple[str, ...] | Unknown
    """Every chassis serial: one per stack member, in the order shown."""


@dataclass(frozen=True, slots=True)
class DeviceRecord:
    """What the tool learned from one device, and how it left it.

    Attributes:
        ip: the address logged into (always by IP).
        outcome: visited, partial or unvisited.
        unvisited_reason: one of the 13 reasons when `outcome` is UNVISITED; else None.
        partial_reason: why the examination stopped short, as fixed text, when `outcome`
            is PARTIAL; else None.
        ssh_id: the SSH identification string the device sent, made printable; None when
            no SSH session was reached.
        host_key: the Trust Store's verdict on the device's key; None when none was read.
        credential_set: the set that logged in; None when no login succeeded.
        platform: the Platform identified after login; None when not identified.
        landing_privilege: the privilege the login landed with; None when not reached.
        version: what `show version` said; None when not reached.
        cdp_neighbours: the CDP table's Neighbours; None when not reached (#50).
        lldp_neighbours: the LLDP table's Neighbours; None when not reached (#50).
        aliases: the other IPs this device was found at this Run (story 73, #50).
    """

    ip: IPv4Address
    outcome: DeviceOutcome
    unvisited_reason: UnvisitedReason | None = None
    partial_reason: str | None = None
    ssh_id: str | None = None
    host_key: HostKeyCheck | None = None
    credential_set: CredentialSetView | None = None
    platform: Platform | None = None
    landing_privilege: LandingPrivilege | Unknown | None = None
    version: VersionFacts | None = None
    cdp_neighbours: tuple[NeighbourRecord, ...] | Unknown | None = None
    lldp_neighbours: tuple[NeighbourRecord, ...] | Unknown | None = None
    aliases: tuple[Alias, ...] = ()
