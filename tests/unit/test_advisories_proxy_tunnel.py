"""The proxy tunnel is built the right way round: proxy dialled, Cisco named in CONNECT (#132).

These tests run the real `HttpsTransport`, the real `open_https` and the real `http.client` on
in-memory sockets (`tests/support/fake_cisco.py`: `FakeNetwork`). Only the sockets and the TLS
handshake are faked, so a test sees the bytes a proxy and Cisco would receive, and the name the
certificate would be checked against. Before the fix the tool dialled Cisco directly and sent
the proxy's own name in the CONNECT line.
"""

import socket
import ssl
from typing import cast

import pytest

from network_analyser.advisories import transport
from network_analyser.advisories.proxy import ProxyConfig
from network_analyser.advisories.transport import (
    HttpRequest,
    HttpResponse,
    HttpsTransport,
    TransportFailed,
)
from tests.support.fake_cisco import CONNECT_ESTABLISHED, FakeNetwork

PROXY = "proxy.example:3128"


def network(
    monkeypatch: pytest.MonkeyPatch, proxy_says: bytes = CONNECT_ESTABLISHED
) -> FakeNetwork:
    """Put in-memory sockets and an in-memory TLS handshake under the real transport."""
    fake = FakeNetwork(proxy_says=proxy_says)
    monkeypatch.setattr(socket, "create_connection", fake.create_connection)
    monkeypatch.setattr(transport, "client_context", lambda: fake.context)
    return fake


def request(host: str) -> HttpRequest:
    """Return a well-formed request to `host`."""
    return HttpRequest(
        host=host,
        port=443,
        method="GET",
        path="/security/advisories/v2/OSType/iosxe?version=17.9.4a",
        headers=(("Accept", "application/json"),),
    )


def through_proxy() -> HttpsTransport:
    """Return the real transport told to use `--proxy proxy.example:3128`."""
    return HttpsTransport(proxy=ProxyConfig.explicit(PROXY), system_proxy=lambda: None)


@pytest.mark.parametrize("cisco_host", ["apix.cisco.com", "id.cisco.com"])
def test_the_proxy_is_dialled_and_asked_to_connect_to_cisco(
    monkeypatch: pytest.MonkeyPatch, cisco_host: str
) -> None:
    fake = network(monkeypatch)

    reply = through_proxy()(request(cisco_host))

    assert reply == HttpResponse(status=200, headers=(("Content-Length", "2"),), body=b"{}")
    assert fake.connected == [("proxy.example", 3128)]
    first_line = fake.sent_in_clear().split(b"\r\n", 1)[0]
    assert first_line == f"CONNECT {cisco_host}:443 HTTP/1.1".encode()


@pytest.mark.parametrize("cisco_host", ["apix.cisco.com", "id.cisco.com"])
def test_the_certificate_is_checked_against_cisco_not_the_proxy(
    monkeypatch: pytest.MonkeyPatch, cisco_host: str
) -> None:
    fake = network(monkeypatch)

    through_proxy()(request(cisco_host))

    assert fake.context.server_names == [cisco_host]
    assert fake.context.wrapped == [fake.plain_sockets[0]]


def test_nothing_is_dialled_directly_to_cisco_when_a_proxy_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = network(monkeypatch)

    through_proxy()(request("apix.cisco.com"))

    assert [host for host, _port in fake.connected if host.endswith("cisco.com")] == []
    assert b"proxy.example" not in fake.sent_in_clear()
    assert b"proxy.example" not in fake.sent_over_tls()


def test_the_request_itself_travels_inside_the_tunnel(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = network(monkeypatch)

    through_proxy()(request("apix.cisco.com"))

    assert fake.sent_over_tls().startswith(
        b"GET /security/advisories/v2/OSType/iosxe?version=17.9.4a HTTP/1.1\r\n"
    )
    assert b"GET /security" not in fake.sent_in_clear()


def test_a_proxy_that_refuses_the_tunnel_ends_the_call_before_any_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = network(monkeypatch, proxy_says=b"HTTP/1.1 403 Forbidden\r\n\r\n")

    reply = through_proxy()(request("apix.cisco.com"))

    assert isinstance(reply, TransportFailed)
    assert "403" not in reply.reason
    assert fake.context.server_names == []
    assert fake.sent_over_tls() == b""


def test_without_a_proxy_cisco_is_dialled_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = network(monkeypatch)
    direct = HttpsTransport(proxy=ProxyConfig.direct(), system_proxy=lambda: None)

    reply = direct(request("apix.cisco.com"))

    assert isinstance(reply, HttpResponse)
    assert fake.connected == [("apix.cisco.com", 443)]
    assert fake.context.server_names == ["apix.cisco.com"]
    assert b"CONNECT" not in fake.sent_in_clear()


def test_proxy_environment_variables_still_never_steer_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://evil.example:3128")
    monkeypatch.setenv("https_proxy", "http://evil.example:3128")
    monkeypatch.setenv("ALL_PROXY", "http://evil.example:3128")
    fake = network(monkeypatch)
    windows_without_proxy = HttpsTransport(proxy=ProxyConfig(), system_proxy=lambda: None)

    windows_without_proxy(request("apix.cisco.com"))

    assert fake.connected == [("apix.cisco.com", 443)]


@pytest.mark.parametrize(
    ("host", "port"), [("evil.example", 443), ("apix.cisco.com", 8443), ("proxy.example", 443)]
)
def test_open_https_itself_refuses_a_target_outside_the_fence(
    monkeypatch: pytest.MonkeyPatch, host: str, port: int
) -> None:
    fake = network(monkeypatch)

    with pytest.raises(OSError, match="fence"):
        transport.open_https(
            host,
            port,
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            context=cast("ssl.SSLContext", fake.context),
            proxy=("proxy.example", 3128),
        )

    assert fake.connected == []
