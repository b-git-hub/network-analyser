"""The fenced transport: hosts, port, TLS, redirects, caps, timeouts and proxy (#95).

Every test here runs the real `HttpsTransport` with `open_https` replaced by a fake, so the
transport's own decisions are exercised without a socket (the conftest fixture would refuse
one anyway). The Windows proxy setting is injected too; no registry is read.
"""

import socket
import ssl

import pytest
import truststore

from network_analyser.advisories import transport
from network_analyser.advisories.proxy import ProxyConfig, ProxyMode, ProxyNotUsable, resolve_proxy
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


def transport_with(
    monkeypatch: pytest.MonkeyPatch,
    opener: FakeOpener,
    *,
    proxy: ProxyConfig | None = None,
    system: str | None = None,
) -> HttpsTransport:
    """Return the real transport with `open_https` faked and Windows' setting injected."""
    monkeypatch.setattr(transport, "open_https", opener)
    return HttpsTransport(proxy=proxy or ProxyConfig.direct(), system_proxy=lambda: system)


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

    assert opener.opened[0]["tunnel"] == ("proxy.example", 8080)


def test_an_explicit_proxy_wins_over_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(
        monkeypatch,
        opener,
        proxy=ProxyConfig.explicit("chosen.example:3128"),
        system="proxy.example:8080",
    )

    fenced(request())

    assert opener.opened[0]["tunnel"] == ("chosen.example", 3128)


def test_proxy_environment_variables_are_never_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://evil.example:3128")
    monkeypatch.setenv("https_proxy", "http://evil.example:3128")
    monkeypatch.setenv("ALL_PROXY", "http://evil.example:3128")
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(monkeypatch, opener, proxy=ProxyConfig(), system=None)

    fenced(request())

    assert opener.opened[0]["tunnel"] is None


def test_a_proxy_setting_the_tool_cannot_use_stops_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = FakeOpener(connection=FakeConnection(response=FakeResponse(200)))
    fenced = transport_with(monkeypatch, opener, proxy=ProxyConfig(), system="socks=proxy:1080")

    reply = fenced(request())

    assert isinstance(reply, TransportFailed)
    assert "no HTTP proxy" in reply.reason
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
    target = resolve_proxy(ProxyConfig(), system=lambda: "http=a.example:1;https=b.example:2")

    assert not isinstance(target, ProxyNotUsable)
    assert target is not None
    assert (target.host, target.port) == ("b.example", 2)


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
    assert resolve_proxy(ProxyConfig.direct(), system=lambda: "proxy.example:1") is None
