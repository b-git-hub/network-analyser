"""The Audit log's events: one record type per thing the tool does (spec #37 stories 161-166).

Decided on #30 (sections 5-8 and 12). `audit.log` is the evidence that a Run stayed
read-only and inside the Scope, so it records what the tool *did*, in order: the Run's start
and end, every connection attempt and Scope refusal, every host-key check, every login
attempt by username, identification and landing privilege, every command sent as its exact
allow-listed string, every Backup written, every device outcome and every Ctrl+C.

Each event is a plain record with a fixed field list, and `run_output`'s writer refuses any
field not on that list. No event carries device output, not even a line that failed to
parse: a parser problem is the command, the parser and a fixed reason. A library exception
becomes an `ErrorRaised` holding the exception's type and a fixed message, never its text.

Run start and end are emitted by `cli` (#48); the tickets that make connections, log in,
send commands and lock Backups emit the rest (#49 onwards).
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address
from typing import override

from network_analyser.records.host_keys import HostKeyVerdict
from network_analyser.records.platform import Platform
from network_analyser.records.scope import Placement

SCRYPT_LEVEL_WARNED_BELOW = 18
"""A Backup locked with a scrypt work factor below 2^18 is flagged (#27, #30)."""

UNEXPECTED_ERROR = "an unexpected error"
"""The fixed message for an exception type no module has given a message for."""


@unique
class Severity(Enum):
    """How much an event matters. The Audit log has no log levels, only this (#30 section 6)."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class AuditEvent:
    """The base of every Audit log event. Each subclass is a frozen dataclass."""

    __slots__ = ()

    @property
    def severity(self) -> Severity:
        """How much this event matters; most events are information."""
        return Severity.INFO


# -- Run ------------------------------------------------------------------------------------


@unique
class RunEnding(Enum):
    """How a Run ended."""

    COMPLETED = "completed"
    STOPPED = "stopped"
    """Stopped with Ctrl+C, or because `audit.log` could not be written (story 86)."""
    CRASHED = "crashed"


@dataclass(frozen=True, slots=True)
class RunStarted(AuditEvent):
    r"""The Run was confirmed and its folder created: the first line of `audit.log`.

    Attributes:
        tool_version: the SemVer version that made the Run (story 178).
        windows_account: `DOMAIN\user` the tool ran as; None when Windows did not say.
        pc_name: the PC's name; None when Windows did not say.
        run_folder: the Run folder's absolute path.
        scope: the merged Scope ranges, as shown to the operator.
        exclusions: the merged exclusions.
        seeds: the Seeds, in the order given.
        label: the Run label; None for none.
        parallel: devices worked on at once.
        failure_budget: failed logins a Credential Set may spend before it is retired.
        sweep: whether the Scope is swept for more Seeds.
        credential_sets: the usernames of the Credential Sets, in order. Never a password.
    """

    tool_version: str
    windows_account: str | None
    pc_name: str | None
    run_folder: str
    scope: tuple[str, ...]
    exclusions: tuple[str, ...]
    seeds: tuple[IPv4Address, ...]
    label: str | None
    parallel: int
    failure_budget: int
    sweep: bool
    credential_sets: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RunEnded(AuditEvent):
    """The Run ended: the last line of `audit.log`.

    Attributes:
        ended: how it ended.
        devices_visited: Visited Devices.
        devices_unvisited: Unvisited Devices.
        backups_written: Backups locked and written.
        secret_scan_hits: stretches of output the secret scan replaced with `[blocked]`.
    """

    ended: RunEnding
    devices_visited: int
    devices_unvisited: int
    backups_written: int
    secret_scan_hits: int

    @property
    @override
    def severity(self) -> Severity:
        """A crash is an error; a stop or a secret-scan hit needs attention."""
        if self.ended is RunEnding.CRASHED:
            return Severity.ERROR
        if self.ended is RunEnding.STOPPED or self.secret_scan_hits:
            return Severity.WARNING
        return Severity.INFO


@dataclass(frozen=True, slots=True)
class CtrlCPressed(AuditEvent):
    """The operator pressed Ctrl+C during the Run (stories 82-83).

    Attributes:
        press: 1 for the first press (stop gracefully), 2 for the second (close at once).
        sessions_running: device sessions still open when it was pressed.
    """

    press: int
    sessions_running: int

    @property
    @override
    def severity(self) -> Severity:
        """A stop always needs attention."""
        return Severity.WARNING


# -- Connections, host keys and logins --------------------------------------------------------


@unique
class ConnectionResult(Enum):
    """What came of one attempt to open a TCP connection to a device."""

    CONNECTED = "connected"
    REFUSED = "refused"
    TIMED_OUT = "timed out"
    UNREACHABLE = "unreachable"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ConnectionAttempted(AuditEvent):
    """One attempt to connect to a device.

    Attributes:
        ip: the address connected to (always by IP, never by name).
        port: the TCP port.
        result: what came of it.
        retry: whether this was the one connection retry.
    """

    ip: IPv4Address
    port: int
    result: ConnectionResult
    retry: bool

    @property
    @override
    def severity(self) -> Severity:
        """A failed connection needs attention."""
        return Severity.INFO if self.result is ConnectionResult.CONNECTED else Severity.WARNING


@dataclass(frozen=True, slots=True)
class ProbeAttempted(AuditEvent):
    """One Sweep probe: TCP port 22, closed before key exchange (ticket #55).

    The identification string itself is not recorded. It is device text, and it is kept
    on the Sweep result for the report instead.

    Attributes:
        ip: the address probed.
        port: the TCP port. A Sweep always uses 22.
        result: what came of the TCP connection.
        banner_read: whether an SSH identification string was read before the socket closed.
    """

    ip: IPv4Address
    port: int
    result: ConnectionResult
    banner_read: bool

    @property
    @override
    def severity(self) -> Severity:
        """A probe that did not connect needs attention."""
        return Severity.INFO if self.result is ConnectionResult.CONNECTED else Severity.WARNING


@dataclass(frozen=True, slots=True)
class OutOfScopeRefused(AuditEvent):
    """A socket was not opened because the address is not inside the Scope (story 39).

    Attributes:
        ip: the address refused.
        port: the TCP port it would have used.
        placement: where the address stands against the Scope.
    """

    ip: IPv4Address
    port: int
    placement: Placement

    @property
    @override
    def severity(self) -> Severity:
        """The fence held, but something tried to cross it."""
        return Severity.WARNING


@dataclass(frozen=True, slots=True)
class HostKeyChecked(AuditEvent):
    """A device's host key was checked against the Trust Store (ADR 0002).

    Attributes:
        ip: the device's address.
        port: the TCP port.
        key_type: the key type offered, such as `ssh-ed25519`.
        fingerprint: the SHA-256 fingerprint of the key offered.
        verdict: known, new (trusted on first use), changed or not trusted (strict mode).
        trusted_fingerprint: the fingerprint already trusted when the key changed; else None.
    """

    ip: IPv4Address
    port: int
    key_type: str
    fingerprint: str
    verdict: HostKeyVerdict
    trusted_fingerprint: str | None

    @property
    @override
    def severity(self) -> Severity:
        """A changed key is a hard stop; an untrusted one is never logged into."""
        if self.verdict is HostKeyVerdict.CHANGED:
            return Severity.ERROR
        if self.verdict is HostKeyVerdict.NOT_TRUSTED:
            return Severity.WARNING
        return Severity.INFO


@unique
class LoginResult(Enum):
    """What came of one login attempt."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class LoginAttempted(AuditEvent):
    """One password login attempt (usernames are not secret, decided on #6).

    Attributes:
        ip: the device's address.
        credential_set: the set's number, from 1.
        username: the set's username.
        result: what came of it.
    """

    ip: IPv4Address
    credential_set: int
    username: str
    result: LoginResult

    @property
    @override
    def severity(self) -> Severity:
        """A failed login spends the set's failure budget."""
        return Severity.INFO if self.result is LoginResult.SUCCEEDED else Severity.WARNING


@dataclass(frozen=True, slots=True)
class CredentialSetRetired(AuditEvent):
    """A Credential Set spent its failure budget and is tried no more this Run.

    Attributes:
        credential_set: the set's number, from 1.
        username: the set's username.
        failures: the failed logins it spent.
    """

    credential_set: int
    username: str
    failures: int

    @property
    @override
    def severity(self) -> Severity:
        """A retired set needs checking against AAA lockout (story 88)."""
        return Severity.WARNING


# -- Devices --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeviceIdentified(AuditEvent):
    """A device was identified after login.

    Attributes:
        ip: the device's address.
        platform: the Platform found.
        landing_privilege: the privilege level or roles the login landed with, as reported.
    """

    ip: IPv4Address
    platform: Platform
    landing_privilege: str


@unique
class CommandResult(Enum):
    """What came of one command."""

    OK = "ok"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class CommandSent(AuditEvent):
    """One command sent to a device, the evidence that the Run stayed read-only.

    Attributes:
        ip: the device's address.
        command: the exact allow-listed string sent.
        duration_ms: how long it took, in milliseconds.
        bytes_received: how much output came back. The output itself is never recorded.
        result: what came of it.
    """

    ip: IPv4Address
    command: str
    duration_ms: int
    bytes_received: int
    result: CommandResult

    @property
    @override
    def severity(self) -> Severity:
        """A command that did not finish leaves its data unknown."""
        return Severity.INFO if self.result is CommandResult.OK else Severity.WARNING


@dataclass(frozen=True, slots=True)
class ParseFailed(AuditEvent):
    """A command's output could not be parsed, so its data is unknown (#30 section 8).

    Only the command, the parser and a fixed reason: never the output, nor the line that
    failed.

    Attributes:
        ip: the device's address.
        command: the allow-listed command whose output it was.
        parser: the parser's name.
        reason: why, as fixed text.
    """

    ip: IPv4Address
    command: str
    parser: str
    reason: str

    @property
    @override
    def severity(self) -> Severity:
        """Unknown data skips checks the report lists."""
        return Severity.WARNING


@dataclass(frozen=True, slots=True)
class BackupWritten(AuditEvent):
    """A Backup was locked and written (#12, #51).

    Attributes:
        ip: the device's address.
        path: the Backup's path.
        ciphertext_sha256: the SHA-256 of the locked file, in hex.
        scrypt_level: the scrypt work factor (log2) read from its header.
    """

    ip: IPv4Address
    path: str
    ciphertext_sha256: str
    scrypt_level: int

    @property
    @override
    def severity(self) -> Severity:
        """A Backup locked below 2^18 is flagged."""
        if self.scrypt_level < SCRYPT_LEVEL_WARNED_BELOW:
            return Severity.WARNING
        return Severity.INFO


@unique
class DeviceOutcome(Enum):
    """How the tool left a device."""

    VISITED = "visited"
    PARTIAL = "partial"
    UNVISITED = "unvisited"


@dataclass(frozen=True, slots=True)
class DeviceFinished(AuditEvent):
    """The tool is done with a device.

    Attributes:
        ip: the device's address.
        outcome: visited, partial or unvisited.
        reason: the Unvisited reason or why it was left partial, as fixed text; None when
            it was visited in full.
    """

    ip: IPv4Address
    outcome: DeviceOutcome
    reason: str | None

    @property
    @override
    def severity(self) -> Severity:
        """A partial or Unvisited Device is listed for attention."""
        return Severity.INFO if self.outcome is DeviceOutcome.VISITED else Severity.WARNING


@dataclass(frozen=True, slots=True)
class AliasFound(AuditEvent):
    """An IP turned out to be a device already examined this Run, so it was left (story 73).

    Attributes:
        ip: the address the alias was reached at.
        same_as: the address the device was first examined at.
        evidence: `same host key` (left before any password) or `same chassis serial`.
    """

    ip: IPv4Address
    same_as: IPv4Address
    evidence: str


@dataclass(frozen=True, slots=True)
class NeighbourNotVisited(AuditEvent):
    """A device known from a Neighbour advertisement was never dialled (stories 62, 66-67).

    Attributes:
        reported_by: the Visited Device that advertised it; None for a Seed never tried.
        addresses: the IPv4 addresses it advertised (an IPv6-only one has none here).
        reason: its Unvisited reason, one of the fixed strings.
    """

    reported_by: IPv4Address | None
    addresses: tuple[IPv4Address, ...]
    reason: str


# -- Errors ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ErrorRaised(AuditEvent):
    """An exception was caught. Its text is never kept: it can quote device output (#30).

    Build it with `error_event`, which gives the fixed message for the exception's type.

    Attributes:
        ip: the device it concerns; None for none.
        step: what the tool was doing, as fixed text, such as `login`.
        error_type: the exception's type, `module.Name`.
        message: the fixed message for that type.
    """

    ip: IPv4Address | None
    step: str
    error_type: str
    message: str

    @property
    @override
    def severity(self) -> Severity:
        """Every caught exception is an error."""
        return Severity.ERROR


def error_event(
    error: BaseException,
    *,
    step: str,
    ip: IPv4Address | None,
    messages: Mapping[type[BaseException], str],
) -> ErrorRaised:
    """Return the Audit log event for a caught exception, without its text (story 166).

    Args:
        error: the exception. Only its type is read: never its text, args or `str()`.
        step: what the tool was doing, as fixed text.
        ip: the device it concerns, if any.
        messages: the fixed message per exception type, owned by the module that catches
            them (`device_gateway` for Netmiko and Paramiko). The nearest type wins.
    """
    kind = type(error)
    message = next((messages[k] for k in kind.__mro__ if k in messages), UNEXPECTED_ERROR)
    return ErrorRaised(
        ip=ip, step=step, error_type=f"{kind.__module__}.{kind.__qualname__}", message=message
    )
