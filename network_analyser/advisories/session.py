"""One Run's conversation with Cisco: the token once, paced calls, one retry, counts.

The token is requested at most once per Session, and only when a call needs it. An auth
rejection from Cisco stops the Session: no further request is made, so a bad or revoked key is
never hammered (story 36). A key problem is only a 401 or a 400 `invalid_client` from the
token endpoint, or an auth-coded 403; any other 4xx from `apix.cisco.com` fails that one
call and the Session carries on (#131). Only a rate limit, a 5xx or a connection failure that
can pass is retried, and only once, after `Retry-After` when Cisco sends it and after the
pacing wait (story 19).

A 401 from `apix.cisco.com` comes after a token was issued, so it means the token expired, not
that the key is bad (#133). The spec allows one token a Run, so a second is never requested:
the Session stops, and says so in fixed text that never blames the key. It also stops by
itself shortly before the token's `expires_in` runs out, so a long Run does not reach the 401.

Everything kept for the Audit log is a count (`CiscoCallTally`); the client ID, the secret and
the token never leave this object except as the `Authorization` header of a request. All three
join the Run's secret scan the moment they exist (story 40; ADR 0008).
"""

import base64
import json
import re
from dataclasses import dataclass
from enum import Enum, unique
from typing import Final

from network_analyser.advisories.fence import API_HOST, TOKEN_HOST, TOKEN_PATH
from network_analyser.advisories.numbers import whole_number
from network_analyser.advisories.pacing import Pacer, retry_delay
from network_analyser.advisories.proxy import ProxyConfig
from network_analyser.advisories.transport import (
    DEFAULT_MAX_REPLY_BYTES,
    TOKEN_MAX_REPLY_BYTES,
    HttpRequest,
    HttpResponse,
    HttpsTransport,
    Transport,
    TransportFailed,
    header,
)
from network_analyser.credentials import Secret, SecretScan
from network_analyser.records.cisco import (
    CiscoCallTally,
    CiscoEndpoint,
    EndpointUse,
    TokenOutcome,
    TokenResult,
)

TOKEN_SCOPE: Final = "customscope"  # noqa: S105 (a scope name Cisco grants, not a secret)
"""The only scope Cisco's token service grants (confirmed on #87)."""

AUTH_ERROR_CODES: Final = frozenset({"ERR_403_NOT_AUTHORIZED", "ERR_403_DEVELOPER_INACTIVE"})
"""Cisco's 403 codes that mean the key is not usable, so the call is never retried."""

RATE_LIMIT_CODES: Final = frozenset({"ERR_403_DEVELOPER_OVER_QPS", "ERR_403_DEVELOPER_OVER_RATE"})
"""Cisco's 403 codes that mean a limit was reached, so the call is retried once."""

REJECTED: Final = "Cisco rejected the API key"
"""Fixed text for a refused key; the Run turns it into a Needs-attention line (story 36)."""

TOKEN_EXPIRED: Final = "Cisco's token expired"  # noqa: S105 (fixed text, not a secret)
"""Fixed text for a token that ran out mid-Run. It never says the key was rejected, because it
was not, and the Run never tells the operator to run `cisco-key set` for it (#133)."""

TOKEN_MARGIN_S: Final = 30.0
"""No call is sent in the last seconds of the token's life, so none is cut off by its expiry."""

_ERROR_CODE: Final = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
"""Cisco's error codes are letters, digits, `_`, `.` and `-`; nothing else is ever shown."""

_TOKEN_LIMIT: Final = 8192
"""A bearer token is a JWT of a few KB; anything larger is not a token."""

_TOKEN_VALUE: Final = re.compile(r"[A-Za-z0-9._~+/-]{16,8192}={0,2}")
"""A token's characters only: a reply cannot inject a header with it (story 117)."""

_INVALID_CLIENT: Final = "invalid_client"
"""The error code the token endpoint gives a client ID or secret it does not know."""

_HTTP_OK = 200
_HTTP_BAD_REQUEST = 400
_HTTP_UNAUTHORIZED = 401
_HTTP_FORBIDDEN = 403
_HTTP_TOO_MANY_REQUESTS = 429
_HTTP_SERVER_ERROR = 500


@unique
class CallOutcome(Enum):
    """What came of one logical call to an API endpoint."""

    OK = "ok"
    REJECTED = "rejected"
    TOKEN_EXPIRED = "token expired"  # noqa: S105 (an outcome name, never a secret)
    UNAVAILABLE = "unavailable"
    CALL_FAILED = "call failed"


@dataclass(frozen=True, slots=True)
class Call:
    """One logical call's outcome.

    Attributes:
        outcome: ok; rejected (the key is not usable, never retried, stops every call);
            token expired (a 401 after the token was issued, or no time left on it: nothing
            more is sent, and the key is not blamed); call failed (Cisco refused this one
            call, so the others carry on); or unavailable.
        response: the reply, when one came.
        reason: fixed text for an unavailable call.
        retryable: whether the single retry may be made (a limit, a 5xx or no connection).
    """

    outcome: CallOutcome
    response: HttpResponse | None = None
    reason: str = ""
    retryable: bool = False


class Session:
    """One Run's token, transport, pacing and counts."""

    def __init__(  # noqa: PLR0913 (one seam with every dependency explicit)
        self,
        client_id: Secret,
        client_secret: Secret,
        *,
        transport: Transport | None = None,
        proxy: ProxyConfig | None = None,
        pacer: Pacer | None = None,
        scan: SecretScan | None = None,
    ) -> None:
        """Hold the key as Secrets and use `transport`, or the real fenced one."""
        self._client_id = client_id
        self._client_secret = client_secret
        self._transport = (
            transport if transport is not None else HttpsTransport(proxy=proxy or ProxyConfig())
        )
        self._pacer = pacer if pacer is not None else Pacer()
        self._scan = scan
        self._token: Secret | None = None
        self._token_result: TokenResult | None = None
        self._token_reason = ""
        self._auth_rejected = False
        self._token_expired = False
        self._expires_at: float | None = None
        self._counts: dict[CiscoEndpoint, list[int]] = {
            endpoint: [0, 0, 0, 0] for endpoint in CiscoEndpoint
        }
        if scan is not None:
            scan.watch(client_id)
            scan.watch(client_secret)

    @property
    def token_reason(self) -> str:
        """Why the token is unusable, in fixed text; empty when it is fine."""
        return self._token_reason

    @property
    def auth_rejected(self) -> bool:
        """Whether Cisco refused the key, so nothing more may be sent."""
        return self._auth_rejected

    @property
    def token_expired(self) -> bool:
        """Whether the token ran out, so nothing more may be sent (#133)."""
        return self._token_expired

    @property
    def stop_reason(self) -> str | None:
        """Why no further call will be sent, in fixed text; None while calls may go on."""
        if self._auth_rejected:
            return REJECTED
        return TOKEN_EXPIRED if self._token_expired else None

    def token(self) -> TokenResult:
        """Return the token request's result, requesting the token at most once."""
        if self._token_result is None:
            self._token_result = self._request_token()
        return self._token_result

    def tally(self) -> CiscoCallTally:
        """Return the counts for the Audit log: counts only, never a value or a secret.

        It never asks for the token: a Session that stopped before the token was requested
        says `not requested`.
        """
        return CiscoCallTally(
            token=self._token_result or TokenResult(TokenOutcome.NOT_REQUESTED),
            endpoints=tuple(
                EndpointUse(
                    endpoint=endpoint,
                    calls=self._counts[endpoint][0],
                    values=self._counts[endpoint][1],
                    retries=self._counts[endpoint][2],
                    pages=self._counts[endpoint][3],
                )
                for endpoint in CiscoEndpoint
            ),
        )

    def get(self, endpoint: CiscoEndpoint, path: str, *, values: int, pages: int = 0) -> Call:
        """Ask an `apix.cisco.com` endpoint, with the token, paced and retried once.

        `values` counts the PIDs or releases this logical call carries, and `pages` the reply
        pages it reads; both count once per logical call, never once per retry.
        """
        return self._call(endpoint, API_HOST, path, values=values, pages=pages)

    # -- internals ---------------------------------------------------------------------------

    def _request_token(self) -> TokenResult:
        if self._auth_rejected:
            self._token_reason = REJECTED
            return TokenResult(TokenOutcome.REJECTED)
        body = f"grant_type=client_credentials&scope={TOKEN_SCOPE}".encode()
        basic = base64.b64encode(
            f"{self._client_id.reveal()}:{self._client_secret.reveal()}".encode()
        ).decode("ascii")
        request = HttpRequest(
            host=TOKEN_HOST,
            port=443,
            method="POST",
            path=TOKEN_PATH,
            headers=(
                ("Accept", "application/json"),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Authorization", f"Basic {basic}"),
            ),
            body=body,
            max_bytes=TOKEN_MAX_REPLY_BYTES,
        )
        reply = self._send(CiscoEndpoint.TOKEN, request)
        if reply.outcome is CallOutcome.REJECTED:
            self._auth_rejected = True
            self._token_reason = REJECTED
            return TokenResult(
                TokenOutcome.REJECTED,
                _status(reply.response),
                _error_code(reply.response),
            )
        if reply.outcome is CallOutcome.UNAVAILABLE or reply.response is None:
            self._token_reason = reply.reason or "Cisco did not give the tool a token"
            return TokenResult(
                TokenOutcome.UNAVAILABLE,
                _status(reply.response),
                _error_code(reply.response),
            )
        token = _access_token(reply.response)
        if token is None:
            self._token_reason = "Cisco's token reply was not understood"  # noqa: S105 (fixed text)
            return TokenResult(
                TokenOutcome.UNAVAILABLE,
                reply.response.status,
                _error_code(reply.response),
            )
        self._token = Secret(token)
        if self._scan is not None:
            self._scan.watch(self._token)
        lifetime = _expires_in(reply.response)
        if lifetime is not None:
            self._expires_at = self._pacer.now() + lifetime - TOKEN_MARGIN_S
        return TokenResult(TokenOutcome.OK, reply.response.status)

    def _call(
        self, endpoint: CiscoEndpoint, host: str, path: str, *, values: int, pages: int = 0
    ) -> Call:
        if self._auth_rejected:
            return Call(CallOutcome.REJECTED, reason=REJECTED)
        if self._token_expired:
            return Call(CallOutcome.TOKEN_EXPIRED, reason=TOKEN_EXPIRED)
        token = self.token()
        if self._token is None or token.outcome is not TokenOutcome.OK:
            return Call(CallOutcome.UNAVAILABLE, reason=self._token_reason)
        request = HttpRequest(
            host=host,
            port=443,
            method="GET",
            path=path,
            headers=(
                ("Accept", "application/json"),
                ("Authorization", f"Bearer {self._token.reveal()}"),
            ),
            max_bytes=DEFAULT_MAX_REPLY_BYTES,
        )
        reply = self._send(endpoint, request, values=values)
        if reply.outcome is CallOutcome.OK:
            self._counts[endpoint][3] += pages
        if reply.outcome is CallOutcome.REJECTED:
            self._auth_rejected = True
            self._token_reason = REJECTED
        if reply.outcome is CallOutcome.TOKEN_EXPIRED:
            self._token_expired = True
        return reply

    def _send(self, endpoint: CiscoEndpoint, request: HttpRequest, *, values: int = 0) -> Call:
        self._pacer.ready(endpoint)
        reply = self._attempt(endpoint, request, retry=False, values=values)
        if not _may_retry(reply):
            return reply
        delay = retry_delay(_retry_after(reply.response))
        if delay is None:
            return Call(CallOutcome.UNAVAILABLE, reply.response, "Cisco asked for a long wait")
        self._pacer.back_off(delay)
        self._pacer.ready(endpoint)
        return self._attempt(endpoint, request, retry=True, values=values)

    def _attempt(
        self, endpoint: CiscoEndpoint, request: HttpRequest, *, retry: bool, values: int
    ) -> Call:
        if self._token_has_run_out(endpoint):
            return Call(CallOutcome.TOKEN_EXPIRED, reason=TOKEN_EXPIRED)
        counts = self._counts[endpoint]
        counts[0] += 1
        if retry:
            counts[2] += 1
        else:
            counts[1] += values
        reply = self._transport(request)
        if isinstance(reply, TransportFailed):
            return Call(CallOutcome.UNAVAILABLE, None, reply.reason, retryable=reply.retryable)
        return _classified(endpoint, reply)

    def _token_has_run_out(self, endpoint: CiscoEndpoint) -> bool:
        """Whether the token has no safe time left, judged just before a request is sent."""
        if endpoint is CiscoEndpoint.TOKEN or self._expires_at is None:
            return False
        return self._pacer.now() >= self._expires_at


def _classified(endpoint: CiscoEndpoint, reply: HttpResponse) -> Call:
    """Say what one reply means: only a key problem is `REJECTED`, which stops every call.

    A 401 from the token endpoint, an auth-coded 403 and a 400 `invalid_client` there mean the
    key is not usable. A 401 from `apix.cisco.com` comes after a token was issued, so it is an
    expired token (#133). A rate limit and a 5xx may be tried once more. Any other client error
    is that one call's failure: `CALL_FAILED` from `apix.cisco.com`, never a rejected key (#131).
    """
    if reply.status == _HTTP_OK:
        return Call(CallOutcome.OK, reply)
    known = _key_or_limit(endpoint, reply)
    if known is not None:
        return known
    reason = f"Cisco returned HTTP {reply.status}"
    if reply.status >= _HTTP_SERVER_ERROR:
        return Call(CallOutcome.UNAVAILABLE, reply, reason, retryable=True)
    if endpoint is not CiscoEndpoint.TOKEN and reply.status >= _HTTP_BAD_REQUEST:
        return Call(CallOutcome.CALL_FAILED, reply, reason)
    return Call(CallOutcome.UNAVAILABLE, reply, reason)


def _key_or_limit(  # noqa: PLR0911 (one return per reply shape, each named)
    endpoint: CiscoEndpoint, reply: HttpResponse
) -> Call | None:
    """Return the call for a key problem or a rate limit, or None for any other status."""
    rejected = Call(CallOutcome.REJECTED, reply, REJECTED)
    limited = Call(CallOutcome.UNAVAILABLE, reply, "Cisco rate limited the calls", retryable=True)
    if reply.status == _HTTP_UNAUTHORIZED:
        if endpoint is CiscoEndpoint.TOKEN:
            return rejected
        return Call(CallOutcome.TOKEN_EXPIRED, reply, TOKEN_EXPIRED)
    if reply.status == _HTTP_TOO_MANY_REQUESTS:
        return limited
    if reply.status == _HTTP_FORBIDDEN:
        code = header(reply, "X-Mashery-Error-Code") or ""
        if code in AUTH_ERROR_CODES:
            return rejected
        return limited if code in RATE_LIMIT_CODES else None
    if reply.status == _HTTP_BAD_REQUEST and _is_invalid_client(endpoint, reply):
        return rejected
    return None


def _is_invalid_client(endpoint: CiscoEndpoint, reply: HttpResponse) -> bool:
    return endpoint is CiscoEndpoint.TOKEN and _error_code(reply) == _INVALID_CLIENT


def _may_retry(reply: Call) -> bool:
    """Say whether the call may be tried once more: a limit, a 5xx or no connection."""
    return reply.outcome is CallOutcome.UNAVAILABLE and reply.retryable


def _retry_after(response: HttpResponse | None) -> str | None:
    return None if response is None else header(response, "Retry-After")


def _expires_in(response: HttpResponse) -> int | None:
    """The seconds the token lives, when the reply says so as a plain whole number."""
    try:
        document = json.loads(response.body)
    except ValueError, RecursionError:
        return None
    return whole_number(document.get("expires_in")) if isinstance(document, dict) else None


def _status(response: HttpResponse | None) -> int | None:
    return None if response is None else response.status


def _error_code(response: HttpResponse | None) -> str | None:
    code = None if response is None else header(response, "X-Mashery-Error-Code")
    if code is None and response is not None:
        try:
            document = json.loads(response.body)
        except ValueError, RecursionError:
            return None
        value = document.get("error") if isinstance(document, dict) else None
        code = value if isinstance(value, str) else None
    return code if code is not None and _ERROR_CODE.fullmatch(code) else None


def _access_token(response: HttpResponse | None) -> str | None:
    if response is None:
        return None
    try:
        document = json.loads(response.body)
    except ValueError, RecursionError:
        return None
    value = document.get("access_token") if isinstance(document, dict) else None
    if not isinstance(value, str) or len(value) > _TOKEN_LIMIT:
        return None
    return value if _TOKEN_VALUE.fullmatch(value) else None
