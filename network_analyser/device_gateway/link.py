"""The seam between the gateway's rules and the SSH library (ADR 0003; spec-37 notes).

`ssh.dial` is the real one: it opens the socket, runs the SSH handshake, and hands back a
`Link`. Everything above it (the Scope check, the Trust Store before any password, the
allow-list gate, identification) works on these few calls, so tests fake a device here,
with no SSH server (deferred by #28). Nothing in this file touches Netmiko or Paramiko.

A failure the library reports never crosses this seam as an exception: `ssh` maps it to a
plain outcome holding a fixed message (story 166), so no exception text can travel on.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address
from typing import Final, Protocol

from network_analyser.credentials import Secret
from network_analyser.device_gateway.stop import RunStop
from network_analyser.records import HostKey, ScopeRecord
from network_analyser.records.events import CommandResult, ConnectionResult, ErrorRaised
from network_analyser.records.run_request import Timeouts


@dataclass(frozen=True, slots=True)
class DialFailed:
    """The device could not be reached over SSH.

    Attributes:
        connection: what came of the TCP connection.
        algorithms_too_old: True when TCP connected but the device offered no algorithm the
            tool accepts (story 47); with a pinned key type, that it did not offer that type.
        error: the library's failure as a fixed message; None when there was none.
    """

    connection: ConnectionResult
    algorithms_too_old: bool = False
    error: ErrorRaised | None = None


@unique
class LoginResult(Enum):
    """What came of the one password attempt on a connection."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    """The device refused the password: it was sent."""
    LOST = "lost"
    """The connection failed before the device answered."""


@dataclass(frozen=True, slots=True)
class Reply:
    """What came of one line sent to the shell.

    Attributes:
        text: everything read back up to and including the prompt line; None when no
            complete reply came.
        result: ok, timeout or error.
        too_large: the reply passed the output cap, so reading stopped.
        error: the library's failure as a fixed message; None when there was none.
    """

    text: str | None
    result: CommandResult
    too_large: bool = False
    error: ErrorRaised | None = None


class Shell(Protocol):
    """An interactive CLI session on a device, after login."""

    def prompt(self) -> str | ErrorRaised:
        """Return the prompt the device shows now."""
        ...

    def run(self, line: str, timeout: float) -> Reply:
        """Send one line, then read up to and including the next prompt."""
        ...

    def close(self) -> None:
        """Leave at once: close the channel. Never sends `exit` or anything else."""
        ...


class Link(Protocol):
    """One SSH connection, after the handshake and before any password."""

    @property
    def ssh_id(self) -> str:
        """The identification string the device sent, such as `SSH-2.0-Cisco-1.25`."""
        ...

    @property
    def host_key(self) -> HostKey:
        """The host key the device proved it holds."""
        ...

    def log_in(self, username: str, password: Secret) -> LoginResult:
        """Make the connection's one password attempt (story 38)."""
        ...

    def open_shell(self, permits: Callable[[str], bool]) -> Shell | ErrorRaised:
        """Open the CLI. `permits` is the gate for anything the library itself would send."""
        ...

    def close(self) -> None:
        """Close the connection."""
        ...


CONNECT_RETRY_DELAY_S: Final = 30
"""How long to wait before the one retry of a failed connection (story 51)."""


def wait_before_retry(stop: RunStop | None = None) -> None:
    """Wait before the one connection retry. A seam: tests replace it, so none waits.

    The wait ends early when the Run starts stopping (Ctrl+C), and the retry is not made.
    """
    if stop is None:
        time.sleep(CONNECT_RETRY_DELAY_S)
    else:
        stop.pause(CONNECT_RETRY_DELAY_S)


class Dial(Protocol):
    """Open an SSH connection to `ip` and run the handshake, or say why not."""

    def __call__(
        self,
        scope: ScopeRecord,
        ip: IPv4Address,
        port: int,
        *,
        key_types: tuple[str, ...],
        timeouts: Timeouts,
    ) -> Link | DialFailed:
        """`key_types` limits the host key types asked for; empty asks for any (story 44)."""
        ...
