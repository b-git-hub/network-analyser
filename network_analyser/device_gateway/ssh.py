"""The real SSH connection: the only file in the tool that touches Netmiko, Paramiko or sockets.

Security test 3 keeps Netmiko and Paramiko inside `device_gateway`; tests/arch keeps them
in this one file. What it does (ADR 0002, ADR 0003; stories 38-41, 47-48, 53-55, 165-166):

- The Scope is checked again right here, before the socket opens (story 39), and the
  socket is opened to the IP itself, never a name (story 40).
- Paramiko's `Transport` is driven by hand, not `SSHClient.connect`: there is no key file,
  no agent and no `known_hosts` lookup, and the host key is handed back for the Trust
  Store before any password exists on the connection. `log_in` makes exactly one password
  attempt (story 38).
- Only modern algorithms are offered: no SHA-1 key exchange, no `ssh-rsa` signatures, no
  CBC ciphers, no SHA-1 or MD5 MACs. SSHv2 only; Telnet is never used (story 47). A known
  device is asked only for the key type trusted for it (story 44).
- The client calls itself `SSH-2.0-NetworkAnalyser_<version>` (story 48).
- The CLI is a Netmiko connection whose every write passes the allow-list gate (only a bare
  RETURN, or a permitted line and RETURN), whose session log is off, whose reads stop at the
  output cap, and which never sends `exit`, `end` or any config-mode command.
- Every library failure becomes a plain outcome with a fixed message per exception type
  (`records.events.error_event`): exception text, which can quote device output, never
  leaves this file.
"""

import errno
import socket
from collections.abc import Callable, Mapping
from ipaddress import IPv4Address
from typing import Final, NoReturn, override

import paramiko
from netmiko.channel import SSHChannel
from netmiko.cisco_base_connection import CiscoBaseConnection
from netmiko.exceptions import NetmikoBaseException, ReadTimeout

from network_analyser._version import __version__
from network_analyser.credentials import Secret
from network_analyser.device_gateway.gate import CommandRefusedError
from network_analyser.device_gateway.link import DialFailed, Link, LoginResult, Reply, Shell
from network_analyser.device_gateway.text import OUTPUT_CAP
from network_analyser.records import HostKey, MalformedHostKeyError, ScopeRecord
from network_analyser.records.events import (
    CommandResult,
    ConnectionResult,
    ErrorRaised,
    error_event,
)
from network_analyser.records.run_request import Timeouts

CLIENT_ID: Final = f"NetworkAnalyser_{__version__}"
"""The software version in the client's identification string (story 48)."""

DISABLED_ALGORITHMS: Final[Mapping[str, tuple[str, ...]]] = {
    "kex": (
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    ),
    "keys": ("ssh-rsa", "ssh-dss"),
    "pubkeys": ("ssh-rsa", "ssh-dss"),
    "ciphers": ("3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"),
    "macs": ("hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96"),
}
"""Never offered, whatever Paramiko's defaults become (story 47)."""

HOST_KEY_ALGORITHMS: Final[Mapping[str, tuple[str, ...]]] = {
    "ssh-ed25519": ("ssh-ed25519",),
    "ecdsa-sha2-nistp256": ("ecdsa-sha2-nistp256",),
    "ecdsa-sha2-nistp384": ("ecdsa-sha2-nistp384",),
    "ecdsa-sha2-nistp521": ("ecdsa-sha2-nistp521",),
    "ssh-rsa": ("rsa-sha2-512", "rsa-sha2-256"),  # an RSA key, signed with SHA-2 only
}
"""The host key algorithms that prove a key of each `known_hosts` key type."""

ERROR_MESSAGES: Final[Mapping[type[BaseException], str]] = {
    paramiko.ssh_exception.IncompatiblePeer: "the device offered no SSH algorithm accepted",
    paramiko.AuthenticationException: "the device refused the login",
    paramiko.SSHException: "the SSH connection failed",
    ReadTimeout: "the device did not finish its reply in time",
    NetmikoBaseException: "the CLI session failed",
    MalformedHostKeyError: "the device's host key could not be read",
    EOFError: "the device closed the connection",
    TimeoutError: "the device did not answer in time",
    OSError: "the network connection failed",
    ValueError: "the device's prompt was not recognised",
}
"""The fixed message per library exception type (story 166). The nearest type wins."""

_UNREACHABLE: Final = frozenset({errno.ENETUNREACH, errno.EHOSTUNREACH})
_RETURN: Final = "\n"
_TERMINAL_WIDTH: Final = 511
_TERMINAL_HEIGHT: Final = 1000


class OutOfScopeError(Exception):
    """A caller asked to dial an address outside the Scope; nothing was opened.

    Always a bug in the caller, which must check the Scope first. The message is fixed.
    """


class _OutputCapError(Exception):
    """A reply passed the output cap, so reading stopped."""


class _Transport(paramiko.Transport):
    """Paramiko's transport, identifying itself as Network Analyser (story 48)."""

    _CLIENT_ID = CLIENT_ID


def disabled_algorithms(key_types: tuple[str, ...]) -> dict[str, list[str]]:
    """Return what Paramiko must never offer; with `key_types`, every other host key too."""
    disabled = {kind: list(names) for kind, names in DISABLED_ALGORITHMS.items()}
    if key_types:
        wanted = {name for kind in key_types for name in HOST_KEY_ALGORITHMS.get(kind, ())}
        disabled["keys"] += [a for a in _host_key_algorithms() if a not in wanted]
    return disabled


def _host_key_algorithms() -> tuple[str, ...]:
    """Every host key algorithm Paramiko might offer, and every one named here."""
    offered = getattr(paramiko.Transport, "_preferred_keys", ())  # not in its type stubs
    ours = (name for names in HOST_KEY_ALGORITHMS.values() for name in names)
    return tuple(dict.fromkeys((*(str(a) for a in offered), *ours)))


def dial(
    scope: ScopeRecord,
    ip: IPv4Address,
    port: int,
    *,
    key_types: tuple[str, ...],
    timeouts: Timeouts,
) -> Link | DialFailed:
    """Open a TCP connection to `ip` and run the SSH handshake; send no password.

    Raises:
        OutOfScopeError: `ip` is not inside `scope`; no socket was opened.
    """
    if not scope.contains(ip):  # story 39: the fence holds here, whatever the caller did
        msg = "refused: the address is not inside the Scope"
        raise OutOfScopeError(msg)
    try:
        sock = socket.create_connection((str(ip), port), timeout=timeouts.connect)
    except TimeoutError:
        return DialFailed(ConnectionResult.TIMED_OUT)
    except ConnectionRefusedError:
        return DialFailed(ConnectionResult.REFUSED)
    except OSError as error:
        unreachable = error.errno in _UNREACHABLE
        return DialFailed(
            ConnectionResult.UNREACHABLE if unreachable else ConnectionResult.FAILED,
            error=library_error(error, "connect", ip),
        )
    transport = _Transport(sock, disabled_algorithms=disabled_algorithms(key_types))
    transport.banner_timeout = timeouts.login
    transport.handshake_timeout = timeouts.login
    transport.auth_timeout = timeouts.login
    try:
        transport.start_client(timeout=timeouts.login)
        key = transport.get_remote_server_key()
        host_key = HostKey(key.get_name(), key.get_base64())
    except paramiko.ssh_exception.IncompatiblePeer as error:
        _close(transport, sock)
        return DialFailed(
            ConnectionResult.CONNECTED,
            algorithms_too_old=True,
            error=library_error(error, "SSH handshake", ip),
        )
    except (paramiko.SSHException, MalformedHostKeyError, EOFError, OSError) as error:
        _close(transport, sock)
        return DialFailed(ConnectionResult.FAILED, error=library_error(error, "SSH handshake", ip))
    return _ParamikoLink(transport, sock, ip, host_key, timeouts)


def _close(transport: paramiko.Transport, sock: socket.socket) -> None:
    """Close the transport and its socket (Paramiko leaves the socket open if never active)."""
    transport.close()
    sock.close()


def library_error(error: BaseException, step: str, ip: IPv4Address) -> ErrorRaised:
    """Return the Audit log event for a library exception: its type, a fixed message."""
    return error_event(error, step=step, ip=ip, messages=ERROR_MESSAGES)


class _ParamikoLink:
    """One handshaken SSH connection, before and after its one password attempt."""

    def __init__(
        self,
        transport: paramiko.Transport,
        sock: socket.socket,
        ip: IPv4Address,
        key: HostKey,
        timeouts: Timeouts,
    ) -> None:
        self._transport = transport
        self._sock = sock
        self._ip = ip
        self._key = key
        self._timeouts = timeouts

    @property
    def ssh_id(self) -> str:
        return str(self._transport.remote_version)

    @property
    def host_key(self) -> HostKey:
        return self._key

    def log_in(self, username: str, password: Secret) -> LoginResult:
        try:
            self._transport.auth_password(username, password.reveal())
        except paramiko.AuthenticationException:
            return LoginResult.FAILED
        except paramiko.SSHException, EOFError, OSError:
            return LoginResult.LOST
        return LoginResult.SUCCEEDED if self._transport.is_authenticated() else LoginResult.FAILED

    def open_shell(self, permits: Callable[[str], bool]) -> Shell | ErrorRaised:
        try:
            channel = self._transport.open_session(timeout=self._timeouts.login)
            channel.get_pty(term="vt100", width=_TERMINAL_WIDTH, height=_TERMINAL_HEIGHT)
            channel.invoke_shell()
            connection = GuardedCisco(channel, permits, host=str(self._ip))
            connection.prepare()
        except CommandRefusedError:
            raise
        except (
            paramiko.SSHException,
            NetmikoBaseException,
            EOFError,
            OSError,
            ValueError,
        ) as error:
            return library_error(error, "open the CLI", self._ip)
        return _NetmikoShell(connection, self._ip)

    def close(self) -> None:
        _close(self._transport, self._sock)


class _NetmikoShell:
    """The CLI, through Netmiko's prompt handling."""

    def __init__(self, connection: GuardedCisco, ip: IPv4Address) -> None:
        self._connection = connection
        self._ip = ip

    def prompt(self) -> str | ErrorRaised:
        try:
            return self._connection.find_prompt()
        except (
            paramiko.SSHException,
            NetmikoBaseException,
            EOFError,
            OSError,
            ValueError,
        ) as error:
            return library_error(error, "read the prompt", self._ip)

    def run(self, line: str, timeout: float) -> Reply:
        try:
            text = self._connection.send_command(
                line, read_timeout=timeout, strip_prompt=False, strip_command=True
            )
        except ReadTimeout:
            return Reply(None, CommandResult.TIMEOUT)
        except _OutputCapError:
            return Reply(None, CommandResult.ERROR, too_large=True)
        except (
            paramiko.SSHException,
            NetmikoBaseException,
            EOFError,
            OSError,
            ValueError,
        ) as error:
            return Reply(
                None, CommandResult.ERROR, error=library_error(error, "send a command", self._ip)
            )
        return Reply(str(text), CommandResult.OK)

    def close(self) -> None:
        self._connection.leave()


class GuardedCisco(CiscoBaseConnection):
    """A Netmiko Cisco connection that can only ever send allow-listed lines.

    Built on a channel `_ParamikoLink` opened; Netmiko never connects, logs in or logs.
    """

    def __init__(
        self, channel: paramiko.Channel, permits: Callable[[str], bool], *, host: str
    ) -> None:
        """Wrap an open, interactive channel; `permits` is the allow-list gate."""
        super().__init__(
            host=host,
            device_type="cisco_ios",
            password=None,
            auto_connect=False,
            session_log=None,
        )
        self._permits = permits
        self._read_since_write = 0
        self.remote_conn = channel
        self.remote_conn_pre = None
        self.channel = SSHChannel(conn=channel, encoding=self.encoding)
        self.ansi_escape_codes = True

    def prepare(self) -> None:
        """Wait for the first prompt and learn it. Sends only RETURN.

        Netmiko's own session preparation (`terminal width`, `terminal length`) is not
        used: the gateway sends those through the gate itself, so they are audited too.
        """
        self.write_channel(self.RETURN)
        self._test_channel_read(pattern=r"[>#]")
        self.set_base_prompt()

    @override
    def write_channel(self, out_data: str) -> None:
        """Write a bare RETURN, or one permitted line and RETURN; refuse anything else."""
        line = out_data.removesuffix(_RETURN)
        if out_data != _RETURN and (line == out_data or not self._permits(line)):
            msg = "the command is not on the Platform's allow-list, so it was not sent"
            raise CommandRefusedError(msg)
        self._read_since_write = 0
        self.channel.write_channel(out_data)

    @override
    def read_channel(self) -> str:
        """Read what the device sent; stop once one reply passes the output cap."""
        data = super().read_channel()
        self._read_since_write += len(data)
        if self._read_since_write > OUTPUT_CAP:
            raise _OutputCapError
        return data

    def leave(self) -> None:
        """Close the channel at once: never `exit`, `end` or anything else."""
        self.disconnect()

    @override
    def cleanup(self, command: str = "") -> None:
        """Send nothing on the way out (Netmiko would send `exit`)."""

    @override
    def session_preparation(self) -> NoReturn:
        _never()

    @override
    def config_mode(self, *_args: object, **_kwargs: object) -> NoReturn:
        _never()

    @override
    def exit_config_mode(self, *_args: object, **_kwargs: object) -> NoReturn:
        _never()

    @override
    def check_config_mode(self, *_args: object, **_kwargs: object) -> NoReturn:
        _never()

    @override
    def send_config_set(self, *_args: object, **_kwargs: object) -> NoReturn:
        _never()

    @override
    def send_config_from_file(self, *_args: object, **_kwargs: object) -> NoReturn:
        _never()

    @override
    def enable(self, *_args: object, **_kwargs: object) -> NoReturn:
        _never()

    @override
    def exit_enable_mode(self, *_args: object, **_kwargs: object) -> NoReturn:
        _never()

    @override
    def save_config(self, *_args: object, **_kwargs: object) -> NoReturn:
        _never()

    @override
    def commit(self, *_args: object, **_kwargs: object) -> NoReturn:
        _never()


def _never() -> NoReturn:
    msg = "the tool is read-only: configuration and enable modes are never used"
    raise CommandRefusedError(msg)
