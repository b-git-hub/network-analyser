"""A TCP port 22 probe that closes before key exchange (ticket #55; stories 69 and 71).

The Scope is checked in `open_tcp`, the function that opens the socket, and again in
`probe` before that function is called. Nothing is sent on the socket: the server's
identification string is read and the socket is closed before key exchange, so this stage
never offers a password and never starts a key exchange. The connect and the read share
one 2 second budget. ICMP is never used.

`open_tcp` is the only place in this file that calls `socket.create_connection`. Tests
replace `connect` and never open a real connection.
"""

import errno
import socket
import time
from collections.abc import Callable
from ipaddress import IPv4Address
from typing import Final, Protocol

from network_analyser.device_gateway.text import printable
from network_analyser.records import Placement, ScopeRecord
from network_analyser.records.events import (
    AuditEvent,
    ConnectionResult,
    OutOfScopeRefused,
    ProbeAttempted,
)
from network_analyser.records.sweep import ProbeFailure, ProbeResult

SSH_PORT: Final = 22
"""The only port a Sweep probes."""

PROBE_TIMEOUT_S: Final = 2.0
"""The whole probe, connect and banner read together, in seconds (story 69)."""

_BANNER_CAP: Final = 1024
"""How many bytes of preamble and identification string are read at most (RFC 4253)."""

_ID_LIMIT: Final = 255
"""The most characters kept of an identification string (RFC 4253 section 4.2)."""

_UNREACHABLE: Final = frozenset({errno.ENETUNREACH, errno.EHOSTUNREACH})


class OutOfScopeError(Exception):
    """A probe was asked for an address the Scope does not allow. No socket was opened."""


class _Stream(Protocol):
    """The few socket calls a probe makes. Tests substitute an in-memory fake."""

    def recv(self, size: int) -> bytes:
        """Read the next bytes the server sent."""
        ...

    def close(self) -> None:
        """Close the socket."""
        ...

    def settimeout(self, timeout: float | None) -> None:
        """Set the read timeout, in seconds."""
        ...


class _TcpFailed:
    """TCP did not connect. Holds no socket."""

    __slots__ = ("failure",)

    def __init__(self, failure: ProbeFailure) -> None:
        self.failure = failure


class Connect(Protocol):
    """Open one TCP connection, or say why it did not connect. Checks the Scope first."""

    def __call__(
        self, scope: ScopeRecord, ip: IPv4Address, port: int, timeout: float
    ) -> _Stream | _TcpFailed:
        """Return the connected socket, or why TCP did not connect."""
        ...


def open_tcp(
    scope: ScopeRecord, ip: IPv4Address, port: int, timeout: float
) -> socket.socket | _TcpFailed:
    """Open a TCP connection to `ip` itself, or say why not.

    Raises:
        OutOfScopeError: `ip` is not inside `scope`. No socket is opened.
    """
    if not scope.contains(ip):
        msg = "refused: the address is not inside the Scope"
        raise OutOfScopeError(msg)
    try:
        return socket.create_connection((str(ip), port), timeout)
    except TimeoutError:
        return _TcpFailed(ProbeFailure.TIMED_OUT)
    except ConnectionRefusedError:
        return _TcpFailed(ProbeFailure.REFUSED)
    except OSError as error:
        if error.errno in _UNREACHABLE:
            return _TcpFailed(ProbeFailure.UNREACHABLE)
        return _TcpFailed(ProbeFailure.FAILED)


def probe(
    scope: ScopeRecord,
    ip: IPv4Address,
    *,
    emit: Callable[[AuditEvent], None],
    connect: Connect = open_tcp,
) -> ProbeResult:
    """Probe `ip` on TCP 22, read the SSH banner, and close before key exchange.

    Raises:
        OutOfScopeError: `ip` is not inside `scope`. The refusal is audited and no socket
            is opened, including when `connect` is a substitute.
    """
    placement = scope.placement(ip)
    if placement is not Placement.INSIDE:
        emit(OutOfScopeRefused(ip, SSH_PORT, placement))
        msg = "refused: the address is not inside the Scope"
        raise OutOfScopeError(msg)
    started = time.monotonic()
    opened = connect(scope, ip, SSH_PORT, PROBE_TIMEOUT_S)
    if isinstance(opened, _TcpFailed):
        result = ProbeResult(ip, open=False, ssh_id=None, failure=opened.failure)
        emit(_attempt(ip, SSH_PORT, result))
        return result
    try:
        ssh_id = _read_id(opened, PROBE_TIMEOUT_S - (time.monotonic() - started))
    finally:
        opened.close()
    if ssh_id is None:
        result = ProbeResult(ip, open=True, ssh_id=None, failure=ProbeFailure.NO_BANNER)
    else:
        result = ProbeResult(ip, open=True, ssh_id=ssh_id, failure=None)
    emit(_attempt(ip, SSH_PORT, result))
    return result


def _attempt(ip: IPv4Address, port: int, result: ProbeResult) -> ProbeAttempted:
    if result.failure is ProbeFailure.TIMED_OUT:
        connection = ConnectionResult.TIMED_OUT
    elif result.failure is ProbeFailure.REFUSED:
        connection = ConnectionResult.REFUSED
    elif result.failure is ProbeFailure.UNREACHABLE:
        connection = ConnectionResult.UNREACHABLE
    elif result.failure is ProbeFailure.FAILED:
        connection = ConnectionResult.FAILED
    else:
        connection = ConnectionResult.CONNECTED
    return ProbeAttempted(ip, port, connection, banner_read=result.ssh_id is not None)


def _read_id(sock: _Stream, timeout: float) -> str | None:
    """Return the server's identification string, or None when none arrived in time."""
    if timeout <= 0:
        return None
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < _BANNER_CAP:
        try:
            chunk = sock.recv(_BANNER_CAP - len(buf))
        except TimeoutError:
            return _id_in(buf, partial=True)
        except OSError:
            return _id_in(buf, partial=True)
        if not chunk:
            return _id_in(buf, partial=True)
        buf += chunk
        found = _id_in(buf, partial=False)
        if found is not None:
            return found
    return None


def _id_in(buf: bytearray, *, partial: bool) -> str | None:
    """Return the first SSH identification line in `buf`, made printable."""
    text = bytes(buf).decode("ascii", errors="replace")
    pieces = text.split("\n")
    lines = pieces if partial or text.endswith("\n") else pieces[:-1]
    for line in lines:
        candidate = line.rstrip("\r")
        if candidate.startswith("SSH-"):
            return printable(candidate, _ID_LIMIT)
    return None
