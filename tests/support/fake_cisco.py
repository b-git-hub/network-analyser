"""A fake Cisco at the `advisories` transport seam, for tests with no network (#95).

`FakeCisco` is the `Transport` the module is handed: it answers the token, openVuln, EoX and
Software Suggestion paths from synthetic data, records every request, and is scriptable for a
redirect, a rate limit, a 5xx or an outage. It refuses a request that leaves the fence, carries
an undesired value, or lacks the token, so every test also proves the envelope held.

All data here is synthetic: made-up releases, PIDs, ids and text. No Cisco reply is committed.
A value Cisco has no data for answers in the shape #148 observed live: an EoX `EOXRecord` entry
with empty ids and a nested `EOXError`, and a Software Suggestion `productList` entry with no
`basePID` and the code in `suggestions[].errorDetailsResponse` (#166).

`FakeOpener` stands in for `transport.open_https`, so the real transport's own checks (TLS
context, timeouts, tunnel, redirect refusal, size cap) are tested without a socket.
`FakeNetwork` is lower still: the real `open_https` and `http.client` run on in-memory sockets,
so a test sees the bytes a proxy and Cisco would receive (the tunnel, #132).
"""

import base64
import io
import json
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final

from network_analyser.advisories import (
    HttpRequest,
    HttpResponse,
    TransportFailed,
)
from network_analyser.advisories.fence import FENCED_HOSTS, HTTPS_PORT
from network_analyser.advisories.patterns import is_safe_release

CLIENT_ID = "CANARY-client-id-95"
"""A synthetic client ID; the tool must never put it in an event or a record."""

CLIENT_SECRET = "CANARY-client-secret-95"
"""A synthetic client secret, handled the same way."""

TOKEN = "CANARY-access-token-95"
"""A synthetic bearer token, handled the same way."""

ADVISORY_PREFIX = "/security/advisories/v2/OSType/"
EOX_PREFIX = "/supporttools/eox/rest/5/"
SUGGESTION_PREFIX = "/software/suggestion/v2/suggestions/releases/productIds/"
COMPATIBLE_PREFIX = "/software/suggestion/v2/suggestions/compatible/productId/"
TOKEN_PATH = "/oauth2/default/v1/token"

_FAKE_PID_PATH: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}(?:/[A-Za-z0-9-]{1,16})?")
"""The fake's own literal PID path shape: letters, digits and hyphens, and at most one raw `/`.

It is deliberately not the tool's `is_safe_pid`, so a loosened pattern there cannot make the
fake accept a value Cisco would never receive (#155)."""


class LeftTheFenceError(AssertionError):
    """A request left the fence, so the module under test has a bug."""


class UnsafeValueSentError(AssertionError):
    """A request carried a value that is not safe, or the wrong one."""


@dataclass
class FakeCisco:
    """Cisco at the transport seam: records what arrives, answers from synthetic data."""

    advisories: dict[tuple[str, str, str | None], list[dict[str, Any]]] = field(
        default_factory=dict
    )
    """Advisories by (OS type, release, platform alias)."""

    eox_pid: dict[str, dict[str, Any]] = field(default_factory=dict)
    """An EoX record for a PID."""

    eox_release: dict[str, dict[str, Any]] = field(default_factory=dict)
    """An EoX record for a release string."""

    suggestions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    """Suggestion entries for a base PID."""

    compatible: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    """Compatible-release entries for a chassis PID."""

    compatible_pages: dict[tuple[str, int], list[dict[str, Any]]] = field(default_factory=dict)
    """Compatible-release entries for one PID's page, when a test needs paging."""

    compatible_last_page: dict[str, object] = field(default_factory=dict)
    """The `paginationResponseRecord.lastIndex` one PID reports."""

    advisory_errors: dict[tuple[str, str, str | None], tuple[int, str]] = field(
        default_factory=dict
    )
    """An HTTP status and error code (empty for a bare body) for one openVuln question."""

    compatible_errors: dict[str, tuple[int, str]] = field(default_factory=dict)
    """An HTTP status and error code (empty for a bare body) for one chassis PID."""

    page_records: dict[tuple[str, int], list[dict[str, Any]]] = field(default_factory=dict)
    """Records for one EoX page, when a test needs paging instead of the maps above."""

    last_page: dict[str, object] = field(default_factory=dict)
    """The `LastIndex` one EoX lookup kind reports."""

    scripted: list[tuple[str, HttpResponse | TransportFailed]] = field(default_factory=list)
    """Replies for the next requests whose path starts with the given prefix."""

    token_status: int = 200
    token_error: str = ""
    token_headers: tuple[tuple[str, str], ...] = ()
    token_expires_in: object = 3600
    """The token's `expires_in`, in seconds; any other shape stands for an odd reply."""

    outage: bool = False
    """Answer every request as if the connection failed."""

    on_request: Callable[[HttpRequest], None] | None = None
    """Called as each request arrives, for a test that checks ordering or state."""

    requests: list[HttpRequest] = field(default_factory=list)

    def __call__(  # noqa: C901, PLR0911 (one branch per path or scripted reply)
        self, request: HttpRequest
    ) -> HttpResponse | TransportFailed:
        """Answer one request, proving the envelope held as it arrives."""
        if request.host not in FENCED_HOSTS or request.port != HTTPS_PORT:
            msg = f"left the fence: {request.host}:{request.port}"
            raise LeftTheFenceError(msg)
        self.requests.append(request)
        if "currentRelease" in request.path:
            msg = "a path carried currentRelease, which is never sent"
            raise UnsafeValueSentError(msg)
        if self.on_request is not None:
            self.on_request(request)
        if self.outage:
            return TransportFailed("Cisco did not answer in time")
        for index, (prefix, reply) in enumerate(self.scripted):
            if request.path.startswith(prefix):
                del self.scripted[index]
                return reply
        if request.path == TOKEN_PATH:
            return self._token(request)
        _check_authorization(request)
        if request.path.startswith(ADVISORY_PREFIX):
            return self._advisories(request.path)
        if request.path.startswith(EOX_PREFIX):
            return self._eox(request.path)
        if request.path.startswith(SUGGESTION_PREFIX):
            return self._suggestions(request.path)
        if request.path.startswith(COMPATIBLE_PREFIX):
            return self._compatible(request.path)
        msg = f"asked a path the fake does not serve: {request.path}"
        raise UnsafeValueSentError(msg)

    def token_calls(self) -> int:
        """How many token requests arrived."""
        return sum(1 for request in self.requests if request.path == TOKEN_PATH)

    def api_requests(self) -> list[HttpRequest]:
        """Every request except the token's."""
        return [request for request in self.requests if request.path != TOKEN_PATH]

    def paths(self) -> list[str]:
        """Every path asked, in order."""
        return [request.path for request in self.requests]

    # -- replies ---------------------------------------------------------------------------

    def _token(self, request: HttpRequest) -> HttpResponse:
        if request.method != "POST":
            msg = f"token asked with {request.method}"
            raise UnsafeValueSentError(msg)
        if request.body != b"grant_type=client_credentials&scope=customscope":
            msg = f"token body was {request.body!r}"
            raise UnsafeValueSentError(msg)
        headers = dict(request.headers)
        encoded = headers.get("Authorization", "").removeprefix("Basic ")
        if base64.b64decode(encoded).decode() != f"{CLIENT_ID}:{CLIENT_SECRET}":
            msg = "the token request did not carry the expected client credentials"
            raise UnsafeValueSentError(msg)
        if self.token_status != 200:
            body = {} if not self.token_error else {"error": self.token_error}
            return _json(self.token_status, body, self.token_headers)
        return _json(
            200,
            {
                "access_token": TOKEN,
                "token_type": "Bearer",
                "expires_in": self.token_expires_in,
                "scope": "customscope",
            },
        )

    def _advisories(self, path: str) -> HttpResponse:
        rest = path.removeprefix(ADVISORY_PREFIX)
        os_type, _, query = rest.partition("?")
        params = _params(query)
        release = params.get("version", "")
        if not is_safe_release(release):
            msg = f"release left without its pattern: {release!r}"
            raise UnsafeValueSentError(msg)
        key = (os_type, release, params.get("platformAlias"))
        if key in self.advisory_errors:
            return _error(*self.advisory_errors[key])
        return _json(200, {"advisories": self.advisories.get(key, [])})

    def _eox(self, path: str) -> HttpResponse:
        rest = path.removeprefix(EOX_PREFIX)
        kind, _, tail = rest.partition("/")
        page_text, _, values_text = tail.partition("/")
        page = int(page_text)
        values = values_text.split(",")
        if kind == "EOXByProductID":
            values = [_pid_from_wire(value) for value in values]
        for value in values:
            if kind == "EOXBySWReleaseString" and not is_safe_release(value):
                msg = f"release left without its pattern: {value!r}"
                raise UnsafeValueSentError(msg)
        if (kind, page) in self.page_records:
            records = self.page_records[(kind, page)]
        else:
            known = self.eox_pid if kind == "EOXByProductID" else self.eox_release
            input_type = "PID" if kind == "EOXByProductID" else "Software"
            records = [
                known.get(value)
                or {
                    "EOLProductID": "",
                    "EOXInputValue": "",
                    "EOXInputType": input_type,
                    "EOXError": {
                        "ErrorID": "SSA_ERR_026",
                        "ErrorDescription": "synthetic",
                    },
                }
                for value in values
            ]
        return _json(
            200,
            {
                "EOXRecord": records,
                "PaginationResponseRecord": {"LastIndex": self.last_page.get(kind, 1)},
            },
        )

    def _suggestions(self, path: str) -> HttpResponse:
        values = [
            _pid_from_wire(value) for value in path.removeprefix(SUGGESTION_PREFIX).split(",")
        ]
        entries: list[dict[str, Any]] = []
        for value in values:
            if value in self.suggestions:
                entries.append(
                    {
                        "product": {"basePID": value, "productName": "synthetic product"},
                        "suggestions": self.suggestions[value],
                    }
                )
            else:
                entries.append(
                    {
                        "product": {},
                        "suggestions": [{"errorDetailsResponse": {"errorCode": "S3_INV_BASEPID"}}],
                    }
                )
        return _json(200, {"productList": entries})

    def _compatible(self, path: str) -> HttpResponse:
        rest = path.removeprefix(COMPATIBLE_PREFIX)
        wire_id, _, query = rest.partition("?")
        product_id = _pid_from_wire(wire_id)
        if product_id in self.compatible_errors:
            return _error(*self.compatible_errors[product_id])
        page_text = _params(query).get("pageIndex", "1")
        if not page_text.isdigit() or int(page_text) < 1:
            msg = f"pageIndex was not a page number: {page_text!r}"
            raise UnsafeValueSentError(msg)
        page = int(page_text)
        last = self.compatible_last_page.get(product_id, 1)
        if (product_id, page) in self.compatible_pages:
            entries = self.compatible_pages[(product_id, page)]
        elif product_id in self.compatible:
            entries = self.compatible[product_id]
        elif page == 1:
            return _json(200, {"errorDetailsResponse": {"errorCode": "S3_INV_BASEPID"}})
        else:
            entries = []
        return _json(
            200,
            {
                "suggestions": entries,
                "paginationResponseRecord": {"pageIndex": page, "lastIndex": last},
            },
        )


def _check_authorization(request: HttpRequest) -> None:
    headers = dict(request.headers)
    if headers.get("Authorization") != f"Bearer {TOKEN}":
        msg = "an API request did not carry the bearer token"
        raise UnsafeValueSentError(msg)
    if CLIENT_ID in request.path or CLIENT_SECRET in request.path:
        msg = "the client ID or secret reached an API path"
        raise UnsafeValueSentError(msg)


def _pid_from_wire(wire: str) -> str:
    """Return the PID a path segment names, proving it left the PC in its safe wire form.

    A licence suffix's `/` must arrive raw, the only form Cisco answers (#162): Cisco's gateway
    refuses `%2F` with HTTP 400, and no `%` is a PID character at all. This is the fake's own
    literal path rule, never the code's `is_safe_pid`, so a loosened pattern in the tool cannot
    make the fake accept a value Cisco would never receive (#155).
    """
    if "%" in wire:
        msg = f"a PID reached the path percent-encoded, which Cisco refuses: {wire!r}"
        raise UnsafeValueSentError(msg)
    if _FAKE_PID_PATH.fullmatch(wire) is None:
        msg = f"PID left without its path shape: {wire!r}"
        raise UnsafeValueSentError(msg)
    return wire


def _params(query: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for part in query.split("&"):
        if part:
            key, _, value = part.partition("=")
            params[key] = value
    return params


def _error(status: int, code: str) -> HttpResponse:
    return _json(status, {"errorCode": code, "errorMessage": "synthetic"} if code else {})


def _json(status: int, document: object, headers: tuple[tuple[str, str], ...] = ()) -> HttpResponse:
    body = json.dumps(document).encode()
    return HttpResponse(
        status=status, headers=(("Content-Type", "application/json"), *headers), body=body
    )


# -- the lower seam: the real transport's own checks -----------------------------------------


@dataclass
class FakeResponse:
    """The `http.client.HTTPResponse` calls the transport makes."""

    status: int
    body: bytes = b"{}"
    headers: tuple[tuple[str, str], ...] = ()
    on_read: Callable[[], None] | None = None
    """Called on every read, so a test can let time pass while a reply trickles in."""
    reads: list[int] = field(default_factory=list)
    """The size asked for by each read, in order."""
    _position: int = 0

    def getheaders(self) -> list[tuple[str, str]]:
        """Return the reply headers."""
        return list(self.headers)

    def read(self, amt: int | None = None) -> bytes:
        """Return at most `amt` of the body that has not been read yet."""
        end = len(self.body) if amt is None else self._position + amt
        return self._take(end)

    def read1(self, amt: int) -> bytes:
        """Return at most `amt` bytes, as one read of the socket would."""
        return self._take(self._position + amt)

    def _take(self, end: int) -> bytes:
        self.reads.append(end - self._position)
        if self.on_read is not None:
            self.on_read()
        chunk = self.body[self._position : end]
        self._position += len(chunk)
        return chunk


@dataclass
class FakeConnection:
    """The `http.client.HTTPSConnection` calls the transport makes."""

    response: FakeResponse
    requested: list[tuple[str, str, bytes | None, dict[str, str] | None]] = field(
        default_factory=list
    )
    closed: bool = False

    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Record one request."""
        self.requested.append((method, url, body, headers))

    def getresponse(self) -> FakeResponse:
        """Return the scripted reply."""
        return self.response

    def close(self) -> None:
        """Record the close."""
        self.closed = True


@dataclass
class FakeOpener:
    """Stands in for `open_https`: records its arguments and hands back a fake connection."""

    connection: FakeConnection | None = None
    error: BaseException | None = None
    opened: list[dict[str, Any]] = field(default_factory=list)

    def __call__(  # noqa: PLR0913 (it mirrors `open_https`, every setting explicit)
        self,
        host: str,
        port: int,
        *,
        connect_timeout_s: float,
        read_timeout_s: float,
        context: object,
        proxy: tuple[str, int] | None,
    ) -> FakeConnection:
        """Record the opening, then return the connection or raise the scripted error."""
        self.opened.append(
            {
                "host": host,
                "port": port,
                "connect_timeout_s": connect_timeout_s,
                "read_timeout_s": read_timeout_s,
                "context": context,
                "proxy": proxy,
            }
        )
        if self.error is not None:
            raise self.error
        assert self.connection is not None
        return self.connection


# -- the lowest seam: the real `open_https` on in-memory sockets ------------------------------

CONNECT_ESTABLISHED = b"HTTP/1.1 200 Connection established\r\n\r\n"
"""What a proxy says when it has opened the tunnel."""

CISCO_REPLY = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
"""What the fake Cisco says through the tunnel (or directly)."""


class FakeSocket:
    """A socket with scripted incoming bytes that records everything sent on it."""

    def __init__(self, incoming: bytes) -> None:
        """Hold the bytes the other end will say."""
        self._incoming = incoming
        self.sent = bytearray()
        self.closed = False

    def settimeout(self, value: float | None) -> None:
        """Accept a timeout."""

    def setsockopt(self, *args: object) -> None:
        """Accept an option."""

    def sendall(self, data: bytes) -> None:
        """Record what was sent."""
        self.sent += data

    def makefile(self, *_args: object, **_kwargs: object) -> io.BytesIO:
        """Hand out the scripted incoming bytes."""
        return io.BytesIO(self._incoming)

    def close(self) -> None:
        """Record the close."""
        self.closed = True


class FakeTlsContext:
    """A TLS context that records who the handshake is for, and wraps a socket in a fake one.

    It has the two settings `http.client` checks, so the real `HTTPSConnection` accepts it.
    """

    check_hostname = True
    verify_mode = ssl.CERT_REQUIRED

    def __init__(self, tls_reply: bytes) -> None:
        """Hold the bytes the far end says once the handshake is done."""
        self._tls_reply = tls_reply
        self.server_names: list[str | None] = []
        self.wrapped: list[FakeSocket] = []
        self.tls_sockets: list[FakeSocket] = []

    def wrap_socket(self, sock: FakeSocket, *, server_hostname: str | None = None) -> FakeSocket:
        """Record the name the certificate would be checked against."""
        self.server_names.append(server_hostname)
        self.wrapped.append(sock)
        wrapped = FakeSocket(self._tls_reply)
        self.tls_sockets.append(wrapped)
        return wrapped


@dataclass
class FakeNetwork:
    """`socket.create_connection` and the TLS context, on in-memory sockets.

    `connected` is every address the code under test tried to reach, so a test can say
    that nothing but the proxy was ever dialled.
    """

    proxy_says: bytes = CONNECT_ESTABLISHED
    cisco_says: bytes = CISCO_REPLY
    connected: list[tuple[str, int]] = field(default_factory=list)
    plain_sockets: list[FakeSocket] = field(default_factory=list)
    context: FakeTlsContext = field(init=False)

    def __post_init__(self) -> None:
        """Make the TLS context that answers as Cisco."""
        self.context = FakeTlsContext(self.cisco_says)

    def create_connection(
        self, address: tuple[str, int], _timeout: float | None = None, *_args: object
    ) -> FakeSocket:
        """Record the address, and give back a socket that speaks as a proxy would."""
        self.connected.append(address)
        sock = FakeSocket(self.proxy_says)
        self.plain_sockets.append(sock)
        return sock

    def sent_in_clear(self) -> bytes:
        """Everything written on the plain connections, before any TLS."""
        return b"".join(bytes(sock.sent) for sock in self.plain_sockets)

    def sent_over_tls(self) -> bytes:
        """Everything written after the handshake."""
        return b"".join(bytes(sock.sent) for sock in self.context.tls_sockets)
