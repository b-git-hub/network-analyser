"""The real SSH adapter, `device_gateway.ssh`, with Paramiko faked at its edges (ticket #49).

There is no SSH server (deferred by #28), so these tests stop Paramiko where it would touch
the network: the socket is a local socket pair (the conftest refuses real connections), and
the handshake and login steps of the transport are replaced. Netmiko's CLI handling runs for
real against a fake channel that answers like a Cisco shell. What only a device can prove is
in the lab checklist (A1, A5-A7, C6, C10).
"""

import base64
import errno
import socket
from collections.abc import Callable, Iterator
from ipaddress import IPv4Address

import paramiko
import pytest

from network_analyser import scope
from network_analyser._version import __version__
from network_analyser.credentials import Secret
from network_analyser.device_gateway import CommandRefusedError, ssh
from network_analyser.device_gateway.link import DialFailed, LoginResult
from network_analyser.device_gateway.text import OUTPUT_CAP
from network_analyser.records import ScopeRecord
from network_analyser.records.events import CommandResult, ConnectionResult
from network_analyser.records.run_request import Timeouts
from tests.support.fake_device import DEVICE_CANARY, synthetic_key

DEVICE = IPv4Address("192.0.2.10")
TIMEOUTS = Timeouts(connect=3, login=4, command=5)


def _scope() -> ScopeRecord:
    fence = scope.parse(["192.0.2.0/24"], [])
    assert isinstance(fence, ScopeRecord)
    return fence


@pytest.fixture
def sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[tuple[object, float | None]]]:
    """Make `socket.create_connection` hand out one end of a local socket pair."""
    opened: list[tuple[object, float | None]] = []
    pairs: list[socket.socket] = []

    def create_connection(address: object, timeout: float | None = None) -> socket.socket:
        opened.append((address, timeout))
        ours, theirs = socket.socketpair()
        pairs.extend((ours, theirs))
        return ours

    monkeypatch.setattr(socket, "create_connection", create_connection)
    yield opened
    for end in pairs:
        end.close()


def _handshake(monkeypatch: pytest.MonkeyPatch, *, fails: Exception | None = None) -> None:
    """Replace the transport's network steps: the handshake, and the key it proves."""

    def start_client(self: paramiko.Transport, timeout: float | None = None) -> None:
        assert timeout == TIMEOUTS.login
        if fails is not None:
            raise fails
        self.remote_version = "SSH-2.0-Cisco-1.25"

    key = paramiko.Ed25519Key(data=base64.b64decode(synthetic_key().base64))
    monkeypatch.setattr(ssh._Transport, "start_client", start_client)  # noqa: SLF001
    monkeypatch.setattr(ssh._Transport, "get_remote_server_key", lambda _self: key)  # noqa: SLF001


def _dial(key_types: tuple[str, ...] = ()) -> object:
    return ssh.dial(_scope(), DEVICE, 22, key_types=key_types, timeouts=TIMEOUTS)


# -- Before the socket ----------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["198.51.100.1", "127.0.0.1", "224.0.0.1", "192.0.2.0"])
def test_the_scope_is_checked_where_the_socket_opens(
    ip: str, sockets: list[tuple[object, float | None]]
) -> None:
    with pytest.raises(ssh.OutOfScopeError):
        ssh.dial(_scope(), IPv4Address(ip), 22, key_types=(), timeouts=TIMEOUTS)

    assert sockets == []


@pytest.mark.parametrize(
    ("raised", "result"),
    [
        (TimeoutError(), ConnectionResult.TIMED_OUT),
        (ConnectionRefusedError(), ConnectionResult.REFUSED),
        (OSError(errno.EHOSTUNREACH, "no route"), ConnectionResult.UNREACHABLE),
        (OSError(errno.EPIPE, "broken"), ConnectionResult.FAILED),
    ],
)
def test_a_connection_failure_is_a_plain_outcome(
    monkeypatch: pytest.MonkeyPatch, raised: OSError, result: ConnectionResult
) -> None:
    opened: list[object] = []

    def create_connection(address: object, timeout: float | None = None) -> socket.socket:
        opened.append((address, timeout))
        raise raised

    monkeypatch.setattr(socket, "create_connection", create_connection)

    outcome = _dial()

    assert opened == [(("192.0.2.10", 22), TIMEOUTS.connect)]
    assert isinstance(outcome, DialFailed)
    assert outcome.connection is result


# -- The handshake --------------------------------------------------------------------------


def test_the_client_identifies_itself_as_network_analyser() -> None:
    ours, theirs = socket.socketpair()
    try:
        transport = ssh._Transport(ours)  # noqa: SLF001
        assert transport.local_version == f"SSH-2.0-NetworkAnalyser_{__version__}"
    finally:
        ours.close()
        theirs.close()


def _offered(key_types: tuple[str, ...] = ()) -> paramiko.Transport:
    ours, theirs = socket.socketpair()
    theirs.close()
    transport = ssh._Transport(ours, disabled_algorithms=ssh.disabled_algorithms(key_types))  # noqa: SLF001
    ours.close()
    return transport


def test_only_modern_algorithms_are_offered() -> None:
    transport = _offered()

    assert not [k for k in transport.preferred_kex if "sha1" in k]
    assert not [k for k in transport.preferred_keys if k.startswith("ssh-rsa")]
    assert not [c for c in transport.preferred_ciphers if "cbc" in c]
    assert not [m for m in transport.preferred_macs if "sha1" in m or "md5" in m]
    assert transport.preferred_kex
    assert transport.preferred_ciphers
    assert transport.preferred_macs


@pytest.mark.parametrize(
    ("trusted", "asked"),
    [
        (("ssh-ed25519",), ("ssh-ed25519",)),
        (("ssh-rsa",), ("rsa-sha2-512", "rsa-sha2-256")),
        (("ssh-dss",), ()),
    ],
)
def test_a_known_device_is_asked_only_for_its_trusted_key_type(
    trusted: tuple[str, ...], asked: tuple[str, ...]
) -> None:
    offered = _offered(trusted).preferred_keys
    # Paramiko also offers each type's certificate form, which carries the same key.
    assert tuple(k for k in offered if not k.endswith("-cert-v01@openssh.com")) == asked


def test_the_handshake_hands_back_the_identification_string_and_host_key(
    monkeypatch: pytest.MonkeyPatch, sockets: list[tuple[object, float | None]]
) -> None:
    _handshake(monkeypatch)

    link = _dial()

    assert not isinstance(link, DialFailed)
    assert sockets == [(("192.0.2.10", 22), TIMEOUTS.connect)]
    assert link.ssh_id == "SSH-2.0-Cisco-1.25"  # type: ignore[attr-defined]
    assert link.host_key == synthetic_key()  # type: ignore[attr-defined]
    link.close()  # type: ignore[attr-defined]


def test_no_algorithm_in_common_is_recorded_as_too_old(
    monkeypatch: pytest.MonkeyPatch, sockets: list[tuple[object, float | None]]
) -> None:
    _handshake(monkeypatch, fails=paramiko.ssh_exception.IncompatiblePeer("quoted text"))

    outcome = _dial()

    assert isinstance(outcome, DialFailed)
    assert outcome.algorithms_too_old
    assert outcome.error is not None
    assert "quoted text" not in repr(outcome.error)
    assert sockets


# -- The one password attempt ---------------------------------------------------------------


def _logged_in_link(
    monkeypatch: pytest.MonkeyPatch, auth: Callable[[str, str], None]
) -> tuple[object, list[tuple[str, str]]]:
    _handshake(monkeypatch)
    calls: list[tuple[str, str]] = []

    def auth_password(_self: paramiko.Transport, username: str, password: str) -> list[str]:
        calls.append((username, password))
        auth(username, password)
        return []

    monkeypatch.setattr(ssh._Transport, "auth_password", auth_password)  # noqa: SLF001
    monkeypatch.setattr(ssh._Transport, "is_authenticated", lambda _self: True)  # noqa: SLF001
    for never in ("auth_publickey", "auth_interactive_dumb", "auth_none"):
        monkeypatch.setattr(ssh._Transport, never, _fail_never)  # noqa: SLF001
    link = _dial()
    assert not isinstance(link, DialFailed)
    return link, calls


def _fail_never(*_args: object, **_kwargs: object) -> None:
    pytest.fail("only a password login is ever made")


def test_one_password_attempt_and_no_key_or_agent_lookup(
    monkeypatch: pytest.MonkeyPatch, sockets: list[tuple[object, float | None]]
) -> None:
    link, calls = _logged_in_link(monkeypatch, lambda _u, _p: None)

    result = link.log_in("netops-ro", Secret(DEVICE_CANARY))  # type: ignore[attr-defined]

    assert result is LoginResult.SUCCEEDED
    assert calls == [("netops-ro", DEVICE_CANARY)]
    assert sockets


def test_a_refused_password_is_a_failed_login(
    monkeypatch: pytest.MonkeyPatch, sockets: list[tuple[object, float | None]]
) -> None:
    def refuse(_username: str, _password: str) -> None:
        raise paramiko.AuthenticationException

    link, calls = _logged_in_link(monkeypatch, refuse)

    assert link.log_in("netops-ro", Secret("CANARY-pw-wrong")) is LoginResult.FAILED  # type: ignore[attr-defined]
    assert len(calls) == 1
    assert sockets


# -- The CLI: Netmiko, behind the gate ------------------------------------------------------


class FakeChannel:
    """Answers like a Cisco CLI on a Paramiko channel: echo, output, then the prompt."""

    def __init__(self, replies: dict[str, str], prompt: str = "sw-a#") -> None:
        self.replies = replies
        self.prompt = prompt
        self.sent: list[str] = []
        self.closed = False
        self._out = b"\r\n" + prompt.encode()

    def sendall(self, data: bytes) -> None:
        text = data.decode()
        self.sent.append(text)
        line = text.removesuffix("\n")
        reply = "" if not line else self.replies.get(line, "% Invalid input detected.")
        body = f"{line}\r\n{reply}\r\n" if line else "\r\n"
        self._out += (body + self.prompt).encode()

    def recv_ready(self) -> bool:
        return bool(self._out)

    def recv(self, size: int) -> bytes:
        chunk, self._out = self._out[:size], self._out[size:]
        return chunk

    def close(self) -> None:
        self.closed = True


def _cisco(channel: FakeChannel, permits: Callable[[str], bool]) -> ssh.GuardedCisco:
    connection = ssh.GuardedCisco(channel, permits, host=str(DEVICE))  # type: ignore[arg-type]
    connection.prepare()
    return connection


def test_the_cli_sends_a_permitted_command_and_reads_to_the_prompt() -> None:
    channel = FakeChannel({"show version": "Cisco IOS XE Software, Version 17.09.04a"})
    connection = _cisco(channel, lambda line: line == "show version")

    text = connection.send_command("show version", read_timeout=5, strip_prompt=False)

    assert "Cisco IOS XE Software" in str(text)
    assert str(text).rstrip().endswith("sw-a#")
    assert set(channel.sent) == {"\n", "show version\n"}


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.write_channel("configure terminal\n"),
        lambda c: c.write_channel("show version"),  # no RETURN: it could be finished later
        lambda c: c.write_channel("\x03"),
        lambda c: c.config_mode(),
        lambda c: c.send_config_set(["hostname x"]),
        lambda c: c.exit_config_mode(),
        lambda c: c.enable(),
        lambda c: c.save_config(),
        lambda c: c.disable_paging(command="terminal length 1"),
        lambda c: c.is_alive(),
    ],
    ids=[
        "configure",
        "no return",
        "control char",
        "config_mode",
        "send_config_set",
        "exit_config_mode",
        "enable",
        "save_config",
        "disable_paging",
        "is_alive",
    ],
)
def test_the_librarys_own_writes_are_refused_unless_permitted(
    call: Callable[[ssh.GuardedCisco], object],
) -> None:
    channel = FakeChannel({})
    connection = _cisco(channel, lambda _line: False)
    before = list(channel.sent)

    with pytest.raises(CommandRefusedError):
        call(connection)

    assert channel.sent == before
    assert set(before) == {"\n"}


def test_leaving_sends_nothing_and_closes_the_channel() -> None:
    channel = FakeChannel({})
    connection = _cisco(channel, lambda _line: False)
    before = list(channel.sent)

    connection.leave()

    assert channel.sent == before
    assert channel.closed


def test_a_reply_past_the_output_cap_stops_the_read() -> None:
    channel = FakeChannel({"show version": "x" * (OUTPUT_CAP + 10)})
    shell = ssh._NetmikoShell(_cisco(channel, lambda _line: True), DEVICE)  # noqa: SLF001

    reply = shell.run("show version", timeout=5)

    assert reply.too_large
    assert reply.text is None
    assert reply.result is CommandResult.ERROR
