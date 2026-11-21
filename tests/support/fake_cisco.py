"""A fake Cisco at the `advisories` transport seam, for tests with no network (#95).

`FakeCisco` is the `Transport` the module is handed: it answers the token, openVuln, EoX and
Software Suggestion paths from synthetic data, records every request, and is scriptable for a
redirect, a rate limit, a 5xx or an outage. It refuses a request that leaves the fence, carries
an undesired value, or lacks the token, so every test also proves the envelope held.

All data here is synthetic: made-up releases, PIDs, ids and text. No Cisco reply is committed.

`FakeOpener` stands in for `transport.open_https`, so the real transport's own checks (TLS
context, timeouts, tunnel, redirect refusal, size cap) are tested without a socket.
"""

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from network_analyser.advisories import (
    HttpRequest,
    HttpResponse,
    TransportFailed,
)
from network_analyser.advisories.fence import FENCED_HOSTS, HTTPS_PORT
from network_analyser.advisories.patterns import is_safe_pid, is_safe_release

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

    compatible_last_page: dict[str, int] = field(default_factory=dict)
    """The `paginationResponseRecord.lastIndex` one PID reports."""

    page_records: dict[tuple[str, int], list[dict[str, Any]]] = field(default_factory=dict)
    """Records for one EoX page, when a test needs paging instead of the maps above."""

    last_page: dict[str, int] = field(default_factory=dict)
    """The `LastIndex` one EoX lookup kind reports."""

    scripted: list[tuple[str, HttpResponse | TransportFailed]] = field(default_factory=list)
    """Replies for the next requests whose path starts with the given prefix."""

    token_status: int = 200
    token_error: str = ""
    token_headers: tuple[tuple[str, str], ...] = ()

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
                "expires_in": 3600,
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
        advisories = self.advisories.get((os_type, release, params.get("platformAlias")), [])
        return _json(200, {"advisories": advisories})

    def _eox(self, path: str) -> HttpResponse:
        rest = path.removeprefix(EOX_PREFIX)
        kind, _, tail = rest.partition("/")
        page_text, _, values_text = tail.partition("/")
        page = int(page_text)
        values = values_text.split(",")
        for value in values:
            if kind == "EOXByProductID" and not is_safe_pid(value):
                msg = f"PID left without its pattern: {value!r}"
                raise UnsafeValueSentError(msg)
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
                    "EOXInputValue": value,
                    "EOXInputType": input_type,
                    "ErrorCode": "SSA_ERR_026",
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
        values = path.removeprefix(SUGGESTION_PREFIX).split(",")
        entries: list[dict[str, Any]] = []
        for value in values:
            if not is_safe_pid(value):
                msg = f"PID left without its pattern: {value!r}"
                raise UnsafeValueSentError(msg)
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
                        "product": {"basePID": value},
                        "errorDetailsResponse": {"errorCode": "S3_INV_BASEPID"},
                    }
                )
        return _json(200, {"suggestions": entries})

    def _compatible(self, path: str) -> HttpResponse:
        rest = path.removeprefix(COMPATIBLE_PREFIX)
        product_id, _, query = rest.partition("?")
        if not is_safe_pid(product_id):
            msg = f"PID left without its pattern: {product_id!r}"
            raise UnsafeValueSentError(msg)
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


def _params(query: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for part in query.split("&"):
        if part:
            key, _, value = part.partition("=")
            params[key] = value
    return params


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

    def getheaders(self) -> list[tuple[str, str]]:
        """Return the reply headers."""
        return list(self.headers)

    def read(self, amt: int | None = None) -> bytes:
        """Return at most `amt` bytes of the body."""
        return self.body if amt is None else self.body[:amt]


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
        tunnel: tuple[str, int] | None,
    ) -> FakeConnection:
        """Record the opening, then return the connection or raise the scripted error."""
        self.opened.append(
            {
                "host": host,
                "port": port,
                "connect_timeout_s": connect_timeout_s,
                "read_timeout_s": read_timeout_s,
                "context": context,
                "tunnel": tunnel,
            }
        )
        if self.error is not None:
            raise self.error
        assert self.connection is not None
        return self.connection
