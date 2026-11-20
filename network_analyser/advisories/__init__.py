"""The `advisories` module: the one place the tool goes online (ADR 0007; #95).

It is the only module that imports an HTTP client or opens an outbound connection, and the
only one besides `backup_store` that may reveal the Cisco API Key. It holds no device password,
no Backup Passphrase and no device record: it takes the lookup questions (de-duplicated PIDs
and OS type + release strings) and the key, and returns Cisco's answers with counts.

The safety envelope it owns:

- the host fence: exactly `id.cisco.com` and `apix.cisco.com`, HTTPS on port 443, Cisco's
  certificate checked against the Windows store through `truststore`, every redirect refused,
  size caps and timeouts (stories 15-16);
- the proxy: Windows' own setting or `--proxy host:port`, never an environment variable
  (story 17);
- the token: a client-credentials grant with scope `customscope`, requested once per Run;
- batching (20 EoX, 10 Suggestion), pacing (openVuln 30 a minute), `Retry-After`, Cisco's
  rate-limit codes and exactly one retry, while a rejected key is never retried (stories
  19, 36);
- strict patterns on every outbound value, so an odd string is refused rather than sent
  (story 13).

`ask_cisco` is the Run's call; `check_api_key` is the token-only check `cisco-key set` uses
(ticket #103). Tests fake Cisco at the `Transport` seam (`tests/support/fake_cisco.py`).
"""

from network_analyser.advisories.fence import API_HOST, FENCED_HOSTS, HTTPS_PORT, TOKEN_HOST
from network_analyser.advisories.lookup import ask_cisco, check_api_key
from network_analyser.advisories.pacing import Pacer
from network_analyser.advisories.patterns import (
    is_safe_pid,
    is_safe_platform_alias,
    is_safe_release,
)
from network_analyser.advisories.proxy import (
    ProxyConfig,
    ProxyMode,
    ProxyNotUsable,
    ProxyTarget,
    resolve_proxy,
)
from network_analyser.advisories.transport import (
    HttpRequest,
    HttpResponse,
    HttpsTransport,
    Transport,
    TransportFailed,
)

__all__ = [
    "API_HOST",
    "FENCED_HOSTS",
    "HTTPS_PORT",
    "TOKEN_HOST",
    "HttpRequest",
    "HttpResponse",
    "HttpsTransport",
    "Pacer",
    "ProxyConfig",
    "ProxyMode",
    "ProxyNotUsable",
    "ProxyTarget",
    "Transport",
    "TransportFailed",
    "ask_cisco",
    "check_api_key",
    "is_safe_pid",
    "is_safe_platform_alias",
    "is_safe_release",
    "resolve_proxy",
]
