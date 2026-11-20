"""The host fence: Cisco's two hosts, HTTPS on port 443, and nothing else (story 15).

`FENCED_HOSTS` is the exact list, not a suffix match and not a pattern. The token service and
the APIs are the only places the tool goes, so a DNS answer, a proxy or a reply cannot send it
anywhere else. The transport checks every request against this list again, so a mistake above
it still cannot open a socket.
"""

from typing import Final

TOKEN_HOST: Final = "id.cisco.com"  # noqa: S105 (a host name, never a secret)
"""The OAuth2 token service (ADR 0008)."""

API_HOST: Final = "apix.cisco.com"
"""openVuln, EoX and Software Suggestion (ADR 0007)."""

FENCED_HOSTS: Final = frozenset({TOKEN_HOST, API_HOST})

HTTPS_PORT: Final = 443
"""The only port the tool ever connects to."""

TOKEN_PATH: Final = "/oauth2/default/v1/token"  # noqa: S105 (a fixed path, never a secret)
"""The client-credentials grant's path on `id.cisco.com`."""


def is_fenced(host: str, port: int) -> bool:
    """Say whether `host` and `port` are inside the fence."""
    return port == HTTPS_PORT and host in FENCED_HOSTS
