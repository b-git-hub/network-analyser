"""The fenced transport: hosts, port, TLS, redirects, caps, timeouts and proxy (#95).

Every test here runs the real `HttpsTransport` with `open_https` replaced by a fake, so the
transport's own decisions are exercised without a socket (the conftest fixture would refuse
one anyway). The Windows proxy setting is injected too; no registry is read.
"""

import socket
import ssl

import pytest
import truststore

from network_analyser._winsys import WindowsProxy
from network_analyser.advisories import transport
from network_analyser.advisories.proxy import (
    ProxyConfig,
    ProxyMode,
    ProxyNotUsable,
    resolve_proxy,
    wpad_ignored,
)
from network_analyser.advisories.transport import (
    HttpRequest,
    HttpResponse,
    HttpsTransport,
    TransportFailed,
)
from tests.support.fake_cisco import FakeConnection, FakeOpener, FakeResponse


def request(**overrides: object) -> HttpRequest:
    """Return a well-formed request to `apix.cisco.com`, with `overrides` applied."""
    fields: dict[str, object] = {
        "host": "apix.cisco.com",
        "port": 443,
        "method": "GET",
        "path": "/security/advisories/v2/OSType/iosxe?version=17.9.4a",
        "headers": (("Accept", "application/json"),),
    }
    fields.update(overrides)
    return HttpRequest(**fields)  # type: ignore[arg-type]  # test data fills the fields


def test_a_request_repr_never_shows_a_header_or_a_body() -> None:
    """A header carries the Basic value and the bearer token, and a body may carry one too."""
    canary = "CANARY-150-basic"
    made = request(headers=(("Authorization", f"Basic {canary}"),), body=b"CANARY-150-body")

    shown = repr(made)

    assert canary not in shown
    assert "CANARY-150-body" not in shown
    assert shown.startswith("HttpRequest(")


def transport_with(
    monkeypatch: pytest.MonkeyPatch,
    opener: FakeOpener,
    *,
    proxy: ProxyConfig | None = None,
    system: str | None = None,
    pac: str | None = None,
) -> HttpsTransport:
    """Return the real transport with `open_https` faked and Windows' setting injected."""
    monkeypatch.setattr(transport, "open_https", opener)
    setting = WindowsProxy(server=system, script=pac) if system or pac else None
    return HttpsTransport(proxy=proxy or ProxyConfig.direct(), system_proxy=lambda: setting)


def test_a_request_to_another_host_is_refused_before_any_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(monkeypatch, opener)

    reply = fenced(request(host="evil.example"))

    assert isinstance(reply, TransportFailed)
    assert "fence" in reply.reason
    assert opener.opened == []


def test_only_port_443_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(monkeypatch, opener)

    reply = fenced(request(port=8443))

    assert isinstance(reply, TransportFailed)
    assert "fence" in reply.reason
    assert opener.opened == []


def test_a_request_path_the_tool_did_not_build_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(monkeypatch, opener)

    reply = fenced(request(path="/security?version=17.9.4a x"))

    assert isinstance(reply, TransportFailed)
    assert "path" in reply.reason
    assert opener.opened == []


def test_cisco_is_reached_over_tls_with_the_windows_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection(response=FakeResponse(200, body=b'{"ok": true}'))
    opener = FakeOpener(connection=connection)
    fenced = transport_with(monkeypatch, opener)

    reply = fenced(request())

    assert reply == HttpResponse(status=200, headers=(), body=b'{"ok": true}')
    opened = opener.opened[0]
    assert (opened["host"], opened["port"]) == ("apix.cisco.com", 443)
    context = opened["context"]
    assert isinstance(context, truststore.SSLContext)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert opened["connect_timeout_s"] == transport.CONNECT_TIMEOUT_S
    assert opened["read_timeout_s"] == transport.READ_TIMEOUT_S
    assert connection.closed is True


def test_a_redirect_is_refused_and_never_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection(
        response=FakeResponse(
            302, headers=(("Location", "https://evil.example/"),), body=b"follow me"
        )
    )
    opener = FakeOpener(connection=connection)
    fenced = transport_with(monkeypatch, opener)

    reply = fenced(request())

    assert isinstance(reply, TransportFailed)
    assert "redirect" in reply.reason
    assert "evil.example" not in reply.reason
    assert len(opener.opened) == 1
    assert len(connection.requested) == 1
    assert connection.closed is True


def test_a_reply_above_the_cap_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection(response=FakeResponse(200, body=b"x" * 50))
    opener = FakeOpener(connection=connection)
    fenced = transport_with(monkeypatch, opener)

    reply = fenced(request(max_bytes=10))

    assert isinstance(reply, TransportFailed)
    assert "larger" in reply.reason
    assert connection.closed is True


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (ssl.SSLCertVerificationError("certificate verify failed"), "certificate was not trusted"),
        (TimeoutError("timed out"), "did not answer in time"),
        (ConnectionRefusedError("refused"), "connection to Cisco was refused"),
        (socket.gaierror("name not known"), "name was not found"),
        (ssl.SSLError("bad handshake"), "secure connection to Cisco failed"),
        (OSError("network down"), "connection to Cisco failed"),
    ],
)
def test_a_connection_failure_becomes_fixed_text(
    monkeypatch: pytest.MonkeyPatch, error: Exception, reason: str
) -> None:
    opener = FakeOpener(error=error)
    fenced = transport_with(monkeypatch, opener)

    reply = fenced(request())

    assert isinstance(reply, TransportFailed)
    assert reason in reply.reason
    assert "certificate verify failed" not in reply.reason
    assert "network down" not in reply.reason


def test_windows_proxy_setting_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(
        monkeypatch, opener, proxy=ProxyConfig(), system="http=proxy.example:8080"
    )

    fenced(request())

    assert opener.opened[0]["proxy"] == ("proxy.example", 8080)


def test_an_explicit_proxy_wins_over_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(
        monkeypatch,
        opener,
        proxy=ProxyConfig.explicit("chosen.example:3128"),
        system="proxy.example:8080",
    )

    fenced(request())

    assert opener.opened[0]["proxy"] == ("chosen.example", 3128)


def test_proxy_environment_variables_are_never_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://evil.example:3128")
    monkeypatch.setenv("https_proxy", "http://evil.example:3128")
    monkeypatch.setenv("ALL_PROXY", "http://evil.example:3128")
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(monkeypatch, opener, proxy=ProxyConfig(), system=None)

    fenced(request())

    assert opener.opened[0]["proxy"] is None


def test_a_proxy_setting_the_tool_cannot_use_stops_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(monkeypatch, opener, proxy=ProxyConfig(), system="socks=proxy:1080")

    reply = fenced(request())

    assert isinstance(reply, TransportFailed)
    assert "no HTTP proxy" in reply.reason
    assert opener.opened == []


def test_a_windows_pac_script_stops_the_run_before_any_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(
        monkeypatch, opener, proxy=ProxyConfig(), pac="http://wpad.example/wpad.dat"
    )

    reply = fenced(request())

    assert isinstance(reply, TransportFailed)
    assert "PAC script" in reply.reason
    assert reply.retryable is False
    assert opener.opened == []


def test_a_proxy_setting_with_a_password_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(
        monkeypatch, opener, proxy=ProxyConfig(), system="https=user:pw@proxy:8080"
    )

    reply = fenced(request())

    assert isinstance(reply, TransportFailed)
    assert "password" in reply.reason
    assert opener.opened == []


def test_the_https_entry_wins_in_a_windows_per_scheme_setting() -> None:
    target = resolve_proxy(
        ProxyConfig(), system=lambda: WindowsProxy(server="http=a.example:1;https=b.example:2")
    )

    assert not isinstance(target, ProxyNotUsable)
    assert target is not None
    assert (target.host, target.port) == ("b.example", 2)


def test_a_windows_pac_script_alone_is_refused_rather_than_ignored() -> None:
    """A PAC script names the proxy only when Windows runs it, and the tool never runs one."""
    target = resolve_proxy(
        ProxyConfig(), system=lambda: WindowsProxy(script="http://wpad.example/wpad.dat")
    )

    assert isinstance(target, ProxyNotUsable)
    assert "PAC script" in target.reason


def test_a_windows_fixed_proxy_is_used_beside_a_pac_script() -> None:
    """A fixed ProxyServer is the setting the tool can honour, so it wins over a PAC script."""
    target = resolve_proxy(
        ProxyConfig(),
        system=lambda: WindowsProxy(
            server="proxy.example:8080", script="http://wpad.example/wpad.dat"
        ),
    )

    assert not isinstance(target, ProxyNotUsable)
    assert target is not None
    assert (target.host, target.port) == ("proxy.example", 8080)


@pytest.mark.parametrize(
    "text",
    [
        "http://proxy.example:8080",
        "proxy.example",
        "proxy.example:99999",
        "user:pw@proxy.example:8080",
        "proxy.example:8080/path",
    ],
)
def test_an_explicit_proxy_must_be_a_host_and_port(text: str) -> None:
    with pytest.raises(ValueError, match="host:port"):
        ProxyConfig.explicit(text)


def test_direct_is_its_own_mode() -> None:
    assert ProxyConfig.direct().mode is ProxyMode.DIRECT
    assert (
        resolve_proxy(ProxyConfig.direct(), system=lambda: WindowsProxy(server="proxy.example:1"))
        is None
    )


@pytest.mark.parametrize(
    ("overrides", "system"),
    [
        ({"host": "evil.example"}, None),
        ({"port": 8443}, None),
        ({"path": "/security?version=17.9.4a x"}, None),
        ({}, "socks=proxy:1080"),
    ],
    ids=["host", "port", "path", "proxy"],
)
def test_a_refusal_before_any_connection_is_final(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object], system: str | None
) -> None:
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(monkeypatch, opener, proxy=ProxyConfig(), system=system)

    reply = fenced(request(**overrides))

    assert isinstance(reply, TransportFailed)
    assert reply.retryable is False


def test_a_refused_redirect_is_final(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection(response=FakeResponse(302, body=b""))
    fenced = transport_with(monkeypatch, FakeOpener(connection=connection))

    reply = fenced(request())

    assert isinstance(reply, TransportFailed)
    assert reply.retryable is False


def test_an_over_cap_reply_is_final_and_is_not_read_past_the_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = FakeResponse(200, body=b"x" * 500)
    fenced = transport_with(monkeypatch, FakeOpener(connection=FakeConnection(response=response)))

    reply = fenced(request(max_bytes=10))

    assert isinstance(reply, TransportFailed)
    assert reply.retryable is False
    assert sum(response.reads) <= 11  # the cap and one byte to prove it was passed


def test_the_fence_refusal_from_open_https_is_final(monkeypatch: pytest.MonkeyPatch) -> None:
    opener = FakeOpener(error=transport.NotFencedError("outside"))
    fenced = transport_with(monkeypatch, opener)

    reply = fenced(request())

    assert isinstance(reply, TransportFailed)
    assert reply.retryable is False


@pytest.mark.parametrize(
    "error",
    [TimeoutError("timed out"), ConnectionRefusedError("refused"), OSError("network down")],
)
def test_a_connection_failure_may_be_tried_once_more(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    fenced = transport_with(monkeypatch, FakeOpener(error=error))

    reply = fenced(request())

    assert isinstance(reply, TransportFailed)
    assert reply.retryable is True


def test_a_reply_is_read_in_chunks_and_arrives_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    body = b"y" * (transport.READ_CHUNK_BYTES * 2 + 5)
    response = FakeResponse(200, body=body)
    fenced = transport_with(monkeypatch, FakeOpener(connection=FakeConnection(response=response)))

    reply = fenced(request())

    assert isinstance(reply, HttpResponse)
    assert reply.body == body
    assert max(response.reads) <= transport.READ_CHUNK_BYTES


def test_a_reply_that_trickles_in_past_the_total_deadline_is_given_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [0.0]

    def trickle() -> None:
        now[0] += 50.0

    response = FakeResponse(200, body=b"z" * (transport.READ_CHUNK_BYTES * 6), on_read=trickle)
    connection = FakeConnection(response=response)
    monkeypatch.setattr(transport, "open_https", FakeOpener(connection=connection))
    fenced = HttpsTransport(
        proxy=ProxyConfig.direct(), system_proxy=lambda: None, clock=lambda: now[0]
    )

    reply = fenced(request(total_timeout_s=120.0))

    assert isinstance(reply, TransportFailed)
    assert "too long" in reply.reason
    assert len(response.reads) == 3  # 0 s, 50 s and 100 s are inside the 120 s; 150 s is not
    assert connection.closed is True


def test_a_reply_that_arrives_inside_the_deadline_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [0.0]

    def slow() -> None:
        now[0] += 10.0

    response = FakeResponse(200, body=b"ok", on_read=slow)
    monkeypatch.setattr(
        transport, "open_https", FakeOpener(connection=FakeConnection(response=response))
    )
    fenced = HttpsTransport(
        proxy=ProxyConfig.direct(), system_proxy=lambda: None, clock=lambda: now[0]
    )

    reply = fenced(request(total_timeout_s=120.0))

    assert isinstance(reply, HttpResponse)
    assert reply.body == b"ok"


def test_every_request_carries_a_total_deadline_by_default() -> None:
    assert request().total_timeout_s == transport.TOTAL_TIMEOUT_S
    assert transport.TOTAL_TIMEOUT_S >= transport.READ_TIMEOUT_S


def test_windows_auto_detect_alone_connects_directly() -> None:
    """WPAD alone is not a proxy the tool can use, so it connects directly (#192)."""
    target = resolve_proxy(ProxyConfig(), system=lambda: WindowsProxy(auto_detect=True))

    assert target is None


def test_a_windows_fixed_proxy_is_used_beside_auto_detect() -> None:
    """A fixed ProxyServer is still the setting the tool can honour (#192)."""
    target = resolve_proxy(
        ProxyConfig(), system=lambda: WindowsProxy(server="proxy.example:8080", auto_detect=True)
    )

    assert not isinstance(target, ProxyNotUsable)
    assert target is not None
    assert (target.host, target.port) == ("proxy.example", 8080)


def test_a_pac_script_beside_auto_detect_reads_as_a_pac_script() -> None:
    """A blob PAC URL is refused through the same text as `AutoConfigURL` (#192)."""
    target = resolve_proxy(
        ProxyConfig(),
        system=lambda: WindowsProxy(script="http://wpad.example/wpad.dat", auto_detect=True),
    )

    assert isinstance(target, ProxyNotUsable)
    assert "PAC script" in target.reason


def test_windows_auto_detect_alone_fetches_nothing_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One direct connection to Cisco, and no WPAD or PAC fetch (#192)."""
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    monkeypatch.setattr(transport, "open_https", opener)
    fenced = HttpsTransport(
        proxy=ProxyConfig(), system_proxy=lambda: WindowsProxy(auto_detect=True)
    )

    reply = fenced(request())

    assert isinstance(reply, HttpResponse)
    assert len(opener.opened) == 1
    assert opener.opened[0]["host"] == "apix.cisco.com"


@pytest.mark.parametrize(
    ("config", "setting", "expected"),
    [
        (ProxyConfig(), WindowsProxy(auto_detect=True), True),
        (ProxyConfig(), WindowsProxy(server="proxy.example:8080", auto_detect=True), False),
        (
            ProxyConfig(),
            WindowsProxy(script="http://wpad.example/wpad.dat", auto_detect=True),
            False,
        ),
        (ProxyConfig(), None, False),
        (ProxyConfig.direct(), WindowsProxy(auto_detect=True), False),
        (ProxyConfig.explicit("proxy.example:8080"), WindowsProxy(auto_detect=True), False),
    ],
)
def test_wpad_is_ignored_only_when_it_is_the_whole_windows_setting(
    config: ProxyConfig, setting: WindowsProxy | None, *, expected: bool
) -> None:
    assert wpad_ignored(config, system=lambda: setting) is expected
