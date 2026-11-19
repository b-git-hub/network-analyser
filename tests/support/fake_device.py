"""Fake Cisco devices at the `device_gateway` seam (`link.Dial`), for tests with no network.

There is no SSH server (deferred by #28), so a test builds `FakeDevice`s and hands a
`FakeNetwork`'s `dial` to the gateway, or installs it as the real one with `install`. Each
fake records what reached it (passwords as plain text, so a test can prove none arrived;
every line sent), so a test can check what the tool did. All data is synthetic.
"""

import base64
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import IPv4Address

import pytest

from network_analyser.credentials import Secret
from network_analyser.device_gateway import link, ssh
from network_analyser.device_gateway.link import DialFailed, Link, LoginResult, Reply, Shell
from network_analyser.records import HostKey, ScopeRecord
from network_analyser.records.events import CommandResult, ConnectionResult, ErrorRaised
from network_analyser.records.run_request import Timeouts
from tests.support import device_text

DEVICE_CANARY = "CANARY-pw-7c1d-device"
"""The password fake devices accept: a synthetic canary, never a real one."""


def synthetic_key(key_type: str = "ssh-ed25519", filler: int = 7) -> HostKey:
    """Return a well-formed SSH public key of `key_type` whose key bytes are all `filler`."""

    def ssh_string(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    blob = ssh_string(key_type.encode("ascii")) + ssh_string(bytes([filler]) * 32)
    return HostKey(key_type=key_type, base64=base64.b64encode(blob).decode("ascii"))


IOS_XE_REPLIES = {
    "terminal length 0": "",
    "terminal width 511": "",
    "show version": device_text.IOS_XE_SHOW_VERSION,
    "show privilege": device_text.IOS_XE_PRIVILEGE_15,
    "show cdp neighbors detail": "",
    "show lldp neighbors detail": "",
    "show running-config view full": device_text.IOS_XE_RUNNING_CONFIG,
}
NXOS_REPLIES = {
    "terminal length 0": "",
    "terminal width 511": "",
    "show version": device_text.NXOS_SHOW_VERSION,
    "show user-account netops-ro": device_text.NXOS_USER_ACCOUNT,
    "show cdp neighbors detail | json": "",
    "show lldp neighbors detail | json": "",
    "show running-config": device_text.NXOS_RUNNING_CONFIG,
}


class DialledOutOfScopeError(AssertionError):
    """The gateway dialled an address its own Scope check should have refused."""


@dataclass
class FakeDevice:
    """One fake device: what it presents, what it accepts, and what reached it."""

    ssh_id: str = "SSH-2.0-Cisco-1.25"
    host_key: HostKey = field(default_factory=synthetic_key)
    password: str = DEVICE_CANARY
    prompt: str = "sw-a#"
    replies: dict[str, str] = field(default_factory=lambda: dict(IOS_XE_REPLIES))
    connection: ConnectionResult = ConnectionResult.CONNECTED
    algorithms_too_old: bool = False
    config_prompt_after: str | None = None
    """After this line, the device shows a configuration-mode prompt."""
    hangs_on: frozenset[str] = frozenset()
    shell_fails: bool = False
    when_sent: dict[str, Callable[[], None]] = field(default_factory=dict)
    """Called as the line is run, before the reply: a test presses Ctrl+C this way (#56)."""

    passwords_received: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)
    key_types_asked: list[tuple[str, ...]] = field(default_factory=list)
    timeouts: list[float] = field(default_factory=list)
    """The timeout each line in `lines` was sent with."""
    open_links: int = 0
    gate: Callable[[str], bool] | None = None


class _FakeShell:
    def __init__(self, device: FakeDevice) -> None:
        self._device = device

    def prompt(self) -> str | ErrorRaised:
        return self._device.prompt

    def run(self, line: str, timeout: float) -> Reply:
        device = self._device
        assert timeout > 0
        device.lines.append(line)
        device.timeouts.append(timeout)
        if line in device.when_sent:
            device.when_sent[line]()
        if line in device.hangs_on:
            return Reply(None, CommandResult.TIMEOUT)
        if line == device.config_prompt_after:
            device.prompt = device.prompt.removesuffix("#") + "(config)#"
        text = device.replies.get(line, "                 ^\n% Invalid input detected.\n")
        return Reply(f"{text}{device.prompt}", CommandResult.OK)

    def close(self) -> None:
        return None


class _FakeLink:
    def __init__(self, device: FakeDevice) -> None:
        self._device = device
        self._logged_in = False
        device.open_links += 1

    @property
    def ssh_id(self) -> str:
        return self._device.ssh_id

    @property
    def host_key(self) -> HostKey:
        return self._device.host_key

    def log_in(self, username: str, password: Secret) -> LoginResult:
        assert username
        assert not self._logged_in, "one password attempt per connection"
        self._logged_in = True
        value = password.reveal()
        self._device.passwords_received.append(value)
        return LoginResult.SUCCEEDED if value == self._device.password else LoginResult.FAILED

    def open_shell(self, permits: Callable[[str], bool]) -> Shell | ErrorRaised:
        assert self._logged_in
        self._device.gate = permits
        if self._device.shell_fails:
            return ErrorRaised(None, "open shell", "builtins.EOFError", "the channel closed")
        return _FakeShell(self._device)

    def close(self) -> None:
        self._device.open_links -= 1


@dataclass
class FakeNetwork:
    """Fake devices by IP; its `dial` stands in for `device_gateway.ssh.dial`."""

    devices: dict[IPv4Address, FakeDevice] = field(default_factory=dict)
    dialled: list[IPv4Address] = field(default_factory=list)
    waits: int = 0
    """How often the gateway waited before a connection retry (it never really waits)."""
    on_wait: Callable[[], None] | None = None
    """Called during each wait before a retry: a test presses Ctrl+C this way (#56)."""

    def add(self, ip: str, device: FakeDevice | None = None) -> FakeDevice:
        added = device or FakeDevice()
        self.devices[IPv4Address(ip)] = added
        return added

    def dial(
        self,
        scope: ScopeRecord,
        ip: IPv4Address,
        port: int,
        *,
        key_types: tuple[str, ...],
        timeouts: Timeouts,
    ) -> Link | DialFailed:
        assert port == 22
        assert timeouts.connect > 0
        if not scope.contains(ip):
            raise DialledOutOfScopeError(str(ip))
        self.dialled.append(ip)
        device = self.devices.get(ip)
        if device is None:
            return DialFailed(ConnectionResult.TIMED_OUT)
        device.key_types_asked.append(key_types)
        if device.connection is not ConnectionResult.CONNECTED:
            return DialFailed(device.connection)
        if device.algorithms_too_old or (key_types and device.host_key.key_type not in key_types):
            return DialFailed(ConnectionResult.CONNECTED, algorithms_too_old=True)
        return _FakeLink(device)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Make this network the one `device_gateway` dials, in place of real SSH.

        The 30 s wait before a connection retry is counted instead of waited.
        """
        monkeypatch.setattr(ssh, "dial", self.dial)
        monkeypatch.setattr(link, "wait_before_retry", self.wait_before_retry)

    def wait_before_retry(self, _stop: object = None) -> None:
        """Count a wait before a connection retry, at once."""
        self.waits += 1
        if self.on_wait is not None:
            self.on_wait()
