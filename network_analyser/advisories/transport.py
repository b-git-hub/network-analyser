"""The HTTP transport: the host fence, HTTPS on 443, redirects refused, replies capped.

The seam tests use is `Transport`: a callable that takes one `HttpRequest` and returns an
`HttpResponse` or a `TransportFailed` with a fixed reason. `HttpsTransport` is the real one,
and the only code in the tool that opens an outbound connection. Below it, `open_https` is a
second, smaller seam, so tests can prove what the real transport does (tunnel, timeouts, TLS
context, redirect refusal, cap) without a network.

Nothing from a reply's text is ever kept in a failure: a fixed reason is, so no reply can
quote itself into the Audit log or a report (stories 16, 117).
"""

import http.client
import socket
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final, Protocol

import truststore

from network_analyser._winsys import system_proxy as windows_proxy
from network_analyser.advisories.fence import is_fenced
from network_analyser.advisories.proxy import (
    ProxyConfig,
    ProxyNotUsable,
    resolve_proxy,
)

DEFAULT_MAX_REPLY_BYTES: Final = 4 * 1024 * 1024
"""The most any one reply may be, before it is refused: a few thousand EoX records."""

TOKEN_MAX_REPLY_BYTES: Final = 64 * 1024
"""A token reply is a small JSON object; anything larger is not a token."""

CONNECT_TIMEOUT_S: Final = 10.0
"""How long to wait for the TCP and TLS connection to Cisco."""

READ_TIMEOUT_S: Final = 60.0
"""How long to wait for each read of Cisco's reply."""

MINIMUM_TLS: Final = ssl.TLSVersion.TLSv1_2
"""Cisco serves TLS 1.2 and 1.3; older protocol versions are never offered."""

_REDIRECT_MIN = 300
_REDIRECT_MAX = 400
_CONTROL_MAX = 0x20


@dataclass(frozen=True, slots=True)
class HttpRequest:
    """One request to Cisco, built only from fenced parts and pattern-checked values.

    Attributes:
        host: exactly `id.cisco.com` or `apix.cisco.com`.
        port: 443.
        method: `GET` or `POST`.
        path: the path and query, starting with `/`. Every value in it passed its pattern.
        headers: the request headers, in order.
        body: the request body; empty when there is none.
        timeout_s: how long to wait for the reply, in seconds.
        max_bytes: the most reply bytes to accept.
    """

    host: str
    port: int
    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes = b""
    timeout_s: float = READ_TIMEOUT_S
    max_bytes: int = DEFAULT_MAX_REPLY_BYTES


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """One reply from Cisco.

    Attributes:
        status: the HTTP status.
        headers: the reply headers, in order.
        body: the reply body, at most the request's `max_bytes`.
    """

    status: int
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""


@dataclass(frozen=True, slots=True)
class TransportFailed:
    """The request brought back no reply.

    Attributes:
        reason: fixed text, never reply or exception text, such as
            `Cisco did not answer in time`.
    """

    reason: str


class Transport(Protocol):
    """Send one request to Cisco and bring back its reply, or a fixed reason."""

    def __call__(self, request: HttpRequest) -> HttpResponse | TransportFailed:
        """Make the request."""
        ...


class Response(Protocol):
    """The part of `http.client.HTTPResponse` the transport reads."""

    @property
    def status(self) -> int:
        """The HTTP status."""
        ...

    def getheaders(self) -> list[tuple[str, str]]:
        """The reply headers, in order."""
        ...

    def read(self, amt: int | None = None) -> bytes:
        """Read at most `amt` bytes of the body."""
        ...


class Connection(Protocol):
    """The part of `http.client.HTTPSConnection` the transport uses."""

    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: Mapping[str, str] = {},
        *,
        encode_chunked: bool = False,
    ) -> None:
        """Send one request on the open connection."""
        ...

    def getresponse(self) -> Response:
        """Read the reply."""
        ...

    def close(self) -> None:
        """Close the connection."""
        ...


_NOT_FENCED: Final = "refused a host outside the Cisco fence"


class NotFencedError(OSError):
    """`open_https` was asked for a host or port outside the Cisco fence."""


def client_context() -> ssl.SSLContext:
    """Return the TLS context: Cisco's certificate, checked against the Windows store."""
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = MINIMUM_TLS
    return context


def open_https(  # noqa: PLR0913 (a seam with every setting explicit, not a public call)
    host: str,
    port: int,
    *,
    connect_timeout_s: float,
    read_timeout_s: float,
    context: ssl.SSLContext,
    proxy: tuple[str, int] | None,
) -> Connection:
    """Open the TLS connection to Cisco, through the proxy at `proxy` when there is one.

    `host` and `port` are always the Cisco host: the fence is checked again here, so it holds
    whatever a caller passes. With a proxy, the tool dials the proxy, asks it with `CONNECT`
    for `host:port`, and only then starts TLS, with the certificate checked against `host`.
    The proxy never sees more than the Cisco host name and port. Without one, `host` is dialled
    directly. The read timeout is set once the connection is open.

    Raises:
        NotFencedError: `host` and `port` are not a fenced Cisco host and port. Nothing is dialled.
        OSError: the connection could not be opened. The transport maps it to fixed text.
        http.client.HTTPException: the proxy or Cisco answered with something unreadable.
    """
    if not is_fenced(host, port):
        raise NotFencedError(_NOT_FENCED)
    if proxy is None:
        connection = http.client.HTTPSConnection(
            host, port, timeout=connect_timeout_s, context=context
        )
    else:
        connection = http.client.HTTPSConnection(
            proxy[0], proxy[1], timeout=connect_timeout_s, context=context
        )
        connection.set_tunnel(host, port)
    connection.connect()
    if connection.sock is not None:
        connection.sock.settimeout(read_timeout_s)
    return connection


def header(response: HttpResponse, name: str) -> str | None:
    """Return the first header called `name`, in any case, or None when it is absent."""
    wanted = name.lower()
    return next((value for key, value in response.headers if key.lower() == wanted), None)


def _is_safe_path(path: str) -> bool:
    """Say whether a path is the one the caller built: no spaces, controls or backslashes."""
    return path.startswith("/") and not any(
        character.isspace() or character == "\\" or ord(character) < _CONTROL_MAX
        for character in path
    )


@dataclass(frozen=True, slots=True)
class HttpsTransport:
    """The real transport: HTTPS only, fenced hosts, no redirects, capped replies.

    Attributes:
        proxy: where the proxy setting comes from (Windows' setting by default).
        system_proxy: Windows' proxy setting; tests replace it, so no registry is read.
    """

    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    system_proxy: Callable[[], str | None] = windows_proxy

    def __call__(  # noqa: PLR0911 (one return per fixed outcome, each named)
        self, request: HttpRequest
    ) -> HttpResponse | TransportFailed:
        """Make the request, or say in fixed text why there is no reply."""
        if not is_fenced(request.host, request.port):
            return TransportFailed(_NOT_FENCED)
        if not _is_safe_path(request.path):
            return TransportFailed("refused a request path the tool did not build")
        target = resolve_proxy(self.proxy, system=self.system_proxy)
        if isinstance(target, ProxyNotUsable):
            return TransportFailed(target.reason)
        try:
            connection = open_https(
                request.host,
                request.port,
                connect_timeout_s=CONNECT_TIMEOUT_S,
                read_timeout_s=request.timeout_s,
                context=client_context(),
                proxy=None if target is None else (target.host, target.port),
            )
            try:
                connection.request(
                    request.method,
                    request.path,
                    body=request.body or None,
                    headers=dict(request.headers),
                )
                response = connection.getresponse()
                status = response.status
                headers = tuple(response.getheaders())
                if _REDIRECT_MIN <= status < _REDIRECT_MAX:
                    return TransportFailed(f"refused a redirect (HTTP {status})")
                body = response.read(request.max_bytes + 1)
            finally:
                connection.close()
        except (OSError, http.client.HTTPException) as error:
            return _failure(error)
        if len(body) > request.max_bytes:
            return TransportFailed("the reply was larger than the tool accepts")
        return HttpResponse(status=status, headers=headers, body=body)


def _failure(  # noqa: PLR0911 (one return per fixed reason, so each is reviewable)
    error: OSError | http.client.HTTPException,
) -> TransportFailed:
    """Map a connection failure to fixed text. Never its own text, which can quote a reply."""
    if isinstance(error, NotFencedError):
        return TransportFailed(_NOT_FENCED)
    if isinstance(error, ssl.SSLCertVerificationError):
        return TransportFailed("Cisco's certificate was not trusted")
    if isinstance(error, ssl.SSLError):
        return TransportFailed("the secure connection to Cisco failed")
    if isinstance(error, TimeoutError):
        return TransportFailed("Cisco did not answer in time")
    if isinstance(error, ConnectionRefusedError):
        return TransportFailed("the connection to Cisco was refused")
    if isinstance(error, socket.gaierror):
        return TransportFailed("Cisco's name was not found")
    if isinstance(error, http.client.HTTPException):
        return TransportFailed("Cisco's reply could not be read")
    return TransportFailed("the connection to Cisco failed")


__all__ = [
    "CONNECT_TIMEOUT_S",
    "DEFAULT_MAX_REPLY_BYTES",
    "READ_TIMEOUT_S",
    "TOKEN_MAX_REPLY_BYTES",
    "Connection",
    "HttpRequest",
    "HttpResponse",
    "HttpsTransport",
    "Transport",
    "TransportFailed",
    "client_context",
    "header",
    "open_https",
]
