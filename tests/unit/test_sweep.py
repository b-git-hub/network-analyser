"""The opt-in Sweep: a TCP 22 probe, then login only on a supported banner (ticket #55).

No test opens a real connection. The socket is either never reached, or `create_connection`
is replaced and hands back an in-memory fake. Addresses are RFC 5737 documentation ranges.
"""

import argparse
import errno
import importlib
import io
import json
import socket
import threading
from collections.abc import Callable
from dataclasses import replace
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, cast

import pytest

from network_analyser import scope
from network_analyser.cli import ExitCode, run_summary
from network_analyser.cli.parser import SWEEP_INFLIGHT_MAX
from network_analyser.cli.prompts import Prompter
from network_analyser.cli.run_file import RunFile
from network_analyser.cli.run_start import scope_and_seeds
from network_analyser.device_gateway.visit import SSH_PORT
from network_analyser.discovery.sweep import (
    ADDRESS_LIMIT,
    ADDRESS_WARNING,
    IN_FLIGHT_MAX,
    PROBE_TIMEOUT_S,
    SweepTooLargeError,
    addresses,
    combine_seeds,
    sweep,
)
from network_analyser.platforms.hints import sweep_platform
from network_analyser.records import Placement, Platform, ScopeRecord, Source
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.events import (
    AuditEvent,
    ConnectionResult,
    OutOfScopeRefused,
    ProbeAttempted,
)
from network_analyser.records.sweep import ProbeFailure, ProbeResult
from tests.support import fake_age
from tests.support.run_driver import Runner, data_folder, first_run
from tests.support.source_scan import REPO_ROOT

probe = cast("Any", importlib.import_module("network_analyser.device_gateway.probe"))

_Emit = Callable[[AuditEvent], None]


def _fence(*entries: str, exclude: tuple[str, ...] = ()) -> ScopeRecord:
    parsed = scope.parse(entries, exclude)
    assert isinstance(parsed, ScopeRecord)
    return parsed


def _ask() -> Prompter:
    return Prompter(console=None, stdin=io.StringIO(""), stderr=io.StringIO())


def _args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "scope": ["192.0.2.0/24"],
        "exclude": None,
        "seed": ["192.0.2.1"],
        "label": None,
        "parallel": None,
        "failure_budget": None,
        "sweep": False,
        "sweep_inflight": None,
        "connect_timeout": None,
        "login_timeout": None,
        "command_timeout": None,
        "backup_timeout": None,
        "device_timeout": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class _Sock:
    """An in-memory stand-in for the TCP socket. It records anything the probe sends."""

    def __init__(
        self, chunks: tuple[bytes, ...] = (), *, fail: BaseException | None = None
    ) -> None:
        self._chunks = list(chunks)
        self._fail = fail
        self.sent = bytearray()
        self.closed = False
        self.timeout: float | None = None

    def recv(self, _size: int) -> bytes:
        if self._fail is not None:
            raise self._fail
        if not self._chunks:
            return b""
        return self._chunks.pop(0)

    def send(self, data: bytes) -> int:
        self.sent += data
        return len(data)

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def close(self) -> None:
        self.closed = True

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout


def _open(sock: _Sock) -> Callable[..., _Sock]:
    def open_tcp(_scope: ScopeRecord, _ip: IPv4Address, _port: int, _timeout: float) -> _Sock:
        return sock

    return open_tcp


# -- The socket layer (story 69) --------------------------------------------------------------


def test_the_socket_opener_never_opens_an_address_outside_the_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[object] = []

    def create_connection(*args: object, **kwargs: object) -> socket.socket:
        opened.append((args, kwargs))
        msg = "a socket was opened"
        raise AssertionError(msg)

    monkeypatch.setattr(socket, "create_connection", create_connection)
    fence = _fence("192.0.2.0/24", exclude=("192.0.2.10",))

    for ip in ("198.51.100.9", "192.0.2.10", "192.0.2.0", "192.0.2.255"):
        with pytest.raises(probe.OutOfScopeError):
            probe.open_tcp(fence, IPv4Address(ip), SSH_PORT, PROBE_TIMEOUT_S)

    assert opened == []


def test_probe_does_not_ask_an_injected_opener_for_an_address_outside_the_scope() -> None:
    fence = _fence("192.0.2.0/24")
    events: list[object] = []

    def open_tcp(*_args: object, **_kwargs: object) -> _Sock:
        msg = "a socket was opened"
        raise AssertionError(msg)

    with pytest.raises(probe.OutOfScopeError):
        probe.probe(
            fence,
            IPv4Address("198.51.100.9"),
            emit=events.append,
            connect=open_tcp,
        )

    assert len(events) == 1
    refused = events[0]
    assert isinstance(refused, OutOfScopeRefused)
    assert refused.ip == IPv4Address("198.51.100.9")
    assert refused.port == SSH_PORT
    assert refused.placement is Placement.OUTSIDE
    assert not any(isinstance(event, ProbeAttempted) for event in events)


def test_an_in_scope_probe_uses_tcp_22_with_a_two_second_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[tuple[object, float | None]] = []

    def create_connection(address: object, timeout: float | None = None) -> _Sock:
        opened.append((address, timeout))
        raise TimeoutError

    monkeypatch.setattr(socket, "create_connection", create_connection)
    events: list[object] = []
    result = probe.probe(_fence("192.0.2.0/24"), IPv4Address("192.0.2.10"), emit=events.append)

    assert opened == [(("192.0.2.10", 22), 2.0)]
    assert probe.SSH_PORT == SSH_PORT == 22
    assert PROBE_TIMEOUT_S == 2.0
    assert result.open is False
    assert result.ssh_id is None
    assert result.failure is ProbeFailure.TIMED_OUT
    assert events == [
        ProbeAttempted(IPv4Address("192.0.2.10"), 22, ConnectionResult.TIMED_OUT, banner_read=False)
    ]


@pytest.mark.parametrize(
    ("raised", "failure", "connection"),
    [
        (ConnectionRefusedError(), ProbeFailure.REFUSED, ConnectionResult.REFUSED),
        (
            OSError(errno.EHOSTUNREACH, "no route"),
            ProbeFailure.UNREACHABLE,
            ConnectionResult.UNREACHABLE,
        ),
        (OSError(errno.EPIPE, "broken"), ProbeFailure.FAILED, ConnectionResult.FAILED),
    ],
)
def test_a_failed_connect_is_a_plain_outcome(
    monkeypatch: pytest.MonkeyPatch,
    raised: OSError,
    failure: ProbeFailure,
    connection: ConnectionResult,
) -> None:
    def create_connection(*_args: object, **_kwargs: object) -> _Sock:
        raise raised

    monkeypatch.setattr(socket, "create_connection", create_connection)
    events: list[object] = []
    result = probe.probe(_fence("192.0.2.0/24"), IPv4Address("192.0.2.10"), emit=events.append)

    assert result == ProbeResult(
        IPv4Address("192.0.2.10"), open=False, ssh_id=None, failure=failure
    )
    assert events == [ProbeAttempted(IPv4Address("192.0.2.10"), 22, connection, banner_read=False)]


def test_the_banner_is_read_and_the_socket_closes_before_any_byte_is_sent() -> None:
    sock = _Sock((b"Please wait\r\n", b"SSH-2.0-Cis", b"co-1.25\r\n"))
    events: list[object] = []

    result = probe.probe(
        _fence("192.0.2.0/24"),
        IPv4Address("192.0.2.10"),
        emit=events.append,
        connect=_open(sock),
    )

    assert result.open is True
    assert result.failure is None
    assert result.ssh_id == "SSH-2.0-Cisco-1.25"
    assert sock.sent == b""
    assert sock.closed is True
    assert events == [
        ProbeAttempted(IPv4Address("192.0.2.10"), 22, ConnectionResult.CONNECTED, banner_read=True)
    ]


def test_a_banner_is_kept_printable_and_a_silent_port_is_not_a_seed_banner() -> None:
    noisy = _Sock((b"SSH-2.0-Cisco-1.25\x1b[2J\r\n",))
    silent = _Sock(fail=TimeoutError())
    events: list[object] = []

    shown = probe.probe(
        _fence("192.0.2.0/24"),
        IPv4Address("192.0.2.10"),
        emit=events.append,
        connect=_open(noisy),
    )
    quiet = probe.probe(
        _fence("192.0.2.0/24"),
        IPv4Address("192.0.2.11"),
        emit=events.append,
        connect=_open(silent),
    )

    assert shown.ssh_id == "SSH-2.0-Cisco-1.25\\x1b[2J"
    assert quiet.open is True
    assert quiet.ssh_id is None
    assert quiet.failure is ProbeFailure.NO_BANNER
    assert silent.closed is True
    assert events[1] == ProbeAttempted(
        IPv4Address("192.0.2.11"), 22, ConnectionResult.CONNECTED, banner_read=False
    )


def test_the_probe_module_does_not_import_paramiko_or_speak_icmp() -> None:
    source = Path(probe.__file__).read_text(encoding="utf-8")

    assert "paramiko" not in source
    assert "netmiko" not in source
    assert "IPPROTO_ICMP" not in source
    assert "SOCK_RAW" not in source
    assert "SOCK_DGRAM" not in source


# -- Which banners may be logged into (story 71) ---------------------------------------------


@pytest.mark.parametrize(
    ("ssh_id", "platform"),
    [
        ("SSH-2.0-Cisco-1.25", Platform.IOS_XE),
        ("SSH-2.0-Cisco-2.0", Platform.IOS_XE),
        ("SSH-2.0-OpenSSH_8.9 FIPS", Platform.NX_OS),
        ("SSH-2.0-OpenSSH_9.0 FIPS", Platform.NX_OS),
    ],
)
def test_a_cisco_or_provisional_nxos_banner_may_be_logged_into(
    ssh_id: str, platform: Platform
) -> None:
    assert sweep_platform(ssh_id) is platform


@pytest.mark.parametrize(
    "ssh_id",
    [
        "SSH-2.0-OpenSSH_8.9",
        "SSH-2.0-OpenSSH_8.9p1",
        "SSH-2.0-CISCO_WLC-8.10",
        "SSH-1.99-Cisco-1.25",
        "SSH-2.0-Cisco",
        "",
    ],
)
def test_any_other_banner_is_not_logged_into(ssh_id: str) -> None:
    assert sweep_platform(ssh_id) is None


def test_the_nxos_pattern_is_marked_provisional_next_to_the_code() -> None:
    source = Path(sweep_platform.__code__.co_filename).read_text(encoding="utf-8")
    checklist = (REPO_ROOT / "docs" / "lab-checklist.md").read_text(encoding="utf-8")

    assert "provisional" in source.lower()
    assert "OpenSSH_" in source
    assert "A2" in checklist
    assert "provisional" in checklist.lower()


# -- Across the Scope (stories 69-70, 72) -----------------------------------------------------


def test_addresses_skip_exclusions_and_edges_and_rise() -> None:
    fence = _fence("203.0.113.5", "192.0.2.0/29", exclude=("192.0.2.2", "192.0.2.4"))

    assert addresses(fence) == (
        IPv4Address("192.0.2.1"),
        IPv4Address("192.0.2.3"),
        IPv4Address("192.0.2.5"),
        IPv4Address("192.0.2.6"),
        IPv4Address("203.0.113.5"),
    )


def test_only_matching_banners_become_seeds_and_results_stay_in_address_order() -> None:
    fence = _fence("192.0.2.10-192.0.2.14")
    banners = {
        IPv4Address("192.0.2.10"): "SSH-2.0-OpenSSH_8.9",
        IPv4Address("192.0.2.11"): "SSH-2.0-Cisco-1.25",
        IPv4Address("192.0.2.12"): "SSH-2.0-OpenSSH_8.9 FIPS",
        IPv4Address("192.0.2.13"): None,
        IPv4Address("192.0.2.14"): "SSH-2.0-CISCO_WLC-8.10",
    }
    seen: list[IPv4Address] = []

    def fake(scope_record: ScopeRecord, ip: IPv4Address, *, emit: _Emit) -> ProbeResult:
        seen.append(ip)
        assert scope_record.contains(ip)
        banner = banners[ip]
        emit(ProbeAttempted(ip, 22, ConnectionResult.CONNECTED, banner_read=banner is not None))
        failure = None if banner else ProbeFailure.NO_BANNER
        return ProbeResult(ip, open=True, ssh_id=banner, failure=failure)

    events: list[object] = []
    # Finish the higher addresses first. The stored order is still ascending.
    result = sweep(fence, inflight=1, emit=events.append, probe=fake)

    assert seen == list(addresses(fence))
    assert [item.ip for item in result.probes] == list(addresses(fence))
    assert result.login_seeds == (IPv4Address("192.0.2.11"), IPv4Address("192.0.2.12"))
    assert len(events) == 5


def test_operator_seeds_stay_first_even_when_their_banner_does_not_match() -> None:
    operator = (IPv4Address("192.0.2.10"), IPv4Address("192.0.2.5"))
    found = (IPv4Address("192.0.2.5"), IPv4Address("192.0.2.11"), IPv4Address("192.0.2.12"))

    assert combine_seeds(operator, found) == (
        IPv4Address("192.0.2.10"),
        IPv4Address("192.0.2.5"),
        IPv4Address("192.0.2.11"),
        IPv4Address("192.0.2.12"),
    )


def test_inflight_can_be_lowered_and_never_raised_above_100() -> None:
    assert IN_FLIGHT_MAX == 100
    assert SWEEP_INFLIGHT_MAX == IN_FLIGHT_MAX
    fence = _fence("192.0.2.0/24")
    peak = 0
    current = 0
    lock = threading.Lock()
    release = threading.Event()

    def fake(_scope: ScopeRecord, ip: IPv4Address, *, emit: _Emit) -> ProbeResult:
        nonlocal peak, current
        assert emit is not None
        with lock:
            current += 1
            peak = max(peak, current)
            filled = current >= IN_FLIGHT_MAX
        if filled:
            release.set()
        else:
            assert release.wait(2)
        with lock:
            current -= 1
        return ProbeResult(ip, open=False, ssh_id=None, failure=ProbeFailure.TIMED_OUT)

    sweep(fence, inflight=500, emit=lambda _event: None, probe=fake)

    assert peak == IN_FLIGHT_MAX
    assert peak <= 100


def test_two_in_flight_never_becomes_three() -> None:
    fence = _fence("192.0.2.1-192.0.2.4")
    peak = 0
    current = 0
    lock = threading.Lock()
    release = threading.Event()

    def fake(_scope: ScopeRecord, ip: IPv4Address, *, emit: _Emit) -> ProbeResult:
        nonlocal peak, current
        assert emit is not None
        with lock:
            current += 1
            peak = max(peak, current)
            filled = current >= 2
        if filled:
            release.set()
        else:
            assert release.wait(2)
        with lock:
            current -= 1
        return ProbeResult(ip, open=False, ssh_id=None, failure=ProbeFailure.REFUSED)

    sweep(fence, inflight=2, emit=lambda _event: None, probe=fake)

    assert peak == 2


def test_a_sweep_above_65536_addresses_does_not_probe() -> None:
    fence = replace(_fence("192.0.2.0/24"), address_count=ADDRESS_LIMIT + 1)
    called: list[IPv4Address] = []

    def fake(_scope: ScopeRecord, ip: IPv4Address, *, emit: _Emit) -> ProbeResult:
        assert emit is not None
        called.append(ip)
        return ProbeResult(ip, open=False, ssh_id=None, failure=ProbeFailure.TIMED_OUT)

    with pytest.raises(SweepTooLargeError):
        sweep(fence, inflight=10, emit=lambda _event: None, probe=fake)

    assert called == []
    assert ADDRESS_LIMIT == 65_536
    assert ADDRESS_WARNING == 4_096


def test_sweep_limits_are_refused_or_warned_before_any_seed_prompt(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    base = _fence("192.0.2.0/24")

    def parsed(count: int) -> ScopeRecord:
        return replace(base, address_count=count)

    monkeypatch.setattr(scope_and_seeds.__globals__["scope"], "parse", lambda *_a: parsed(65_537))
    refused = scope_and_seeds(_args(sweep=True), None, _ask())
    err = capsys.readouterr().err

    assert refused is ExitCode.REFUSED
    assert "65,537" in err
    assert "65,536" in err
    assert "Nothing was contacted." in err

    monkeypatch.setattr(scope_and_seeds.__globals__["scope"], "parse", lambda *_a: parsed(65_536))
    allowed = scope_and_seeds(_args(sweep=True), None, _ask())
    captured = capsys.readouterr()

    assert not isinstance(allowed, ExitCode)
    assert allowed.sweep.value is True
    assert "Refused" not in captured.err
    assert "Warning: Sweep covers 65,536" in captured.out

    monkeypatch.setattr(scope_and_seeds.__globals__["scope"], "parse", lambda *_a: parsed(4_096))
    quiet = scope_and_seeds(_args(sweep=True), None, _ask())
    assert "Warning: Sweep" not in capsys.readouterr().out
    assert not isinstance(quiet, ExitCode)

    monkeypatch.setattr(scope_and_seeds.__globals__["scope"], "parse", lambda *_a: parsed(4_097))
    warned = scope_and_seeds(_args(sweep=True), None, _ask())
    assert "Warning: Sweep covers 4,097" in capsys.readouterr().out
    assert not isinstance(warned, ExitCode)

    monkeypatch.setattr(scope_and_seeds.__globals__["scope"], "parse", lambda *_a: parsed(65_537))
    untouched = scope_and_seeds(_args(sweep=False), None, _ask())
    assert not isinstance(untouched, ExitCode)
    assert untouched.sweep.value is False


def test_a_run_file_cannot_raise_inflight_and_records_where_it_came_from(
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = scope_and_seeds(
        _args(sweep=None, sweep_inflight=50),
        RunFile(path="site.toml", sweep=True),
        _ask(),
    )
    capsys.readouterr()

    assert not isinstance(request, ExitCode)
    assert request.sweep.value is True
    assert request.sweep.source is Source.RUN_FILE
    assert request.sweep_inflight.value == 50
    assert request.sweep_inflight.source is Source.COMMAND_LINE

    defaulted = scope_and_seeds(_args(sweep=True), None, _ask())
    capsys.readouterr()
    assert not isinstance(defaulted, ExitCode)
    assert defaulted.sweep_inflight.value == 100
    assert defaulted.sweep_inflight.source is Source.DEFAULT


# -- Wired into a Run, after the confirm ------------------------------------------------------


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    fake_age.use_fake_age(monkeypatch)
    return Runner(monkeypatch, capsys)


def test_sweep_does_not_run_before_the_operator_confirms(run: Runner) -> None:
    got = run(
        "--scope", "192.0.2.0/24", "--seed", "192.0.2.1", "--sweep", typed=first_run(start="n")
    )

    assert got.code == ExitCode.STOPPED
    assert "cancelled" in got.err.lower() or "Nothing was contacted." in got.err


def test_a_confirmed_sweep_logs_in_only_to_matching_banners(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    banners = {
        "192.0.2.10": b"SSH-2.0-OpenSSH_8.9\r\n",
        "192.0.2.11": b"SSH-2.0-Cisco-1.25\r\n",
        "192.0.2.12": b"SSH-2.0-OpenSSH_8.9 FIPS\r\n",
        "192.0.2.13": b"SSH-2.0-OpenSSH_8.9\r\n",
    }
    opened: list[str] = []
    socks: list[_Sock] = []

    def create_connection(address: tuple[str, int], timeout: float | None = None) -> _Sock:
        ip, port = address
        assert port == 22
        assert timeout == 2.0
        opened.append(ip)
        sock = _Sock((banners[ip],))
        socks.append(sock)
        return sock

    monkeypatch.setattr(socket, "create_connection", create_connection)
    run.network.add("192.0.2.10")
    run.network.add("192.0.2.11")
    run.network.add("192.0.2.12")
    held: list[CrawlResult] = []
    real_summary = run_summary.summary

    def grab(result: CrawlResult) -> str:
        held.append(result)
        return real_summary(result)

    monkeypatch.setattr(run_summary, "summary", grab)

    got = run(
        "--scope",
        "192.0.2.10-192.0.2.13",
        "--seed",
        "192.0.2.10",
        "--sweep",
        "--sweep-inflight",
        "2",
        typed=first_run(),
    )

    assert got.code in (ExitCode.CLEAN, ExitCode.NEEDS_ATTENTION)
    assert sorted(opened) == ["192.0.2.10", "192.0.2.11", "192.0.2.12", "192.0.2.13"]
    assert all(sock.sent == b"" and sock.closed for sock in socks)
    dialled = [str(ip) for ip in run.network.dialled]
    assert "192.0.2.10" in dialled  # the operator's Seed, whatever its banner
    assert "192.0.2.11" in dialled  # Cisco-*
    assert "192.0.2.12" in dialled  # provisional NX-OS
    assert "192.0.2.13" not in dialled  # other SSH: listed, never offered a password
    assert held
    swept = getattr(held[0], "sweep", None)
    assert swept is not None
    assert swept.login_seeds == (IPv4Address("192.0.2.11"), IPv4Address("192.0.2.12"))
    (folder,) = data_folder().runs.iterdir()
    lines = [
        json.loads(line) for line in (folder / "audit.log").read_text(encoding="ascii").splitlines()
    ]
    probes = [line for line in lines if line["event"] == "probe_attempted"]
    assert sorted(line["ip"] for line in probes) == [
        "192.0.2.10",
        "192.0.2.11",
        "192.0.2.12",
        "192.0.2.13",
    ]
    assert all(line["port"] == 22 and line["banner_read"] is True for line in probes)
    logins = [line["ip"] for line in lines if line["event"] == "login_attempted"]
    assert "192.0.2.13" not in logins
