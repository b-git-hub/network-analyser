# HTTP egress uses the standard library's `http.client`, with `truststore` for certificates

`advisories` is the one module that reaches Cisco ([ADR 0007](0007-cisco-lookups-at-run-end-after-secrets-wiped.md)), and it must do so on the operator's Python 3.14 build. The parent spec left the HTTP client to this build because the research could not verify `httpx` on 3.14. The client is now **`http.client.HTTPSConnection`** from the standard library, with **`truststore`** supplying the TLS context so certificates are checked against the Windows store.

Decided on [#95](https://github.com/b-git-hub/network-analyser/issues/95).

## Consequences

- **Nothing new to audit but one small package.** `http.client` is part of CPython 3.14, so there is no release cadence to follow and no library that might start following redirects for us. `truststore` (MIT, pure Python, `py.typed`) is the only new runtime dependency; it reads the Windows certificate stores through `ssl`/`ctypes` and works on 3.14.
- **Redirects are refused by construction.** `http.client` never follows a redirect: a 3xx is just a status. The transport treats every 3xx as a failure and never reads the `Location` header, so a reply cannot send the tool anywhere else (story 16).
- **The fence is checked twice.** The caller builds only `https://id.cisco.com:443` and `https://apix.cisco.com:443` requests, and the real transport refuses any other host or port before it opens a connection (story 15).
- **Proxy handling stays explicit.** `HTTPSConnection.set_tunnel` makes the proxy open a `CONNECT` to the exact Cisco host, and TLS is still negotiated with Cisco through the tunnel, so the certificate is still Cisco's. Only Windows' Internet Settings or an explicit `--proxy host:port` is used; no `HTTPS_PROXY`-style variable is ever read (story 17).
- **Size caps and timeouts are ours.** `http.client` reads exactly as many bytes as asked, so the transport caps each reply before it is parsed, and sets its own connect and read timeouts.
- **Only `advisories` imports it.** The import-rule test and security test 4 keep it that way, and the ruff banned-API list names the one file allowed.

## Considered Options

- **`httpx`:** pleasant API and a ready-made proxy and redirect policy, but its Python 3.14 support is unverified (the reason the spec left this open), and it brings `httpcore`, `h11`, `anyio`, `sniffio` and `certifi` into a tool that needs one GET per question.
- **`requests`:** mature, but it depends on `urllib3`/`certifi` and follows redirects unless told not to; on Windows its certificate handling is another layer to reason about.
- **`urllib.request`:** stdlib, but redirect following is in the opener's default handlers and turning it off means subclassing a redirect handler. It also brings a URL parser and a file/`data:` scheme handler that this module must never use.
- **`ssl.create_default_context()` alone (no `truststore`):** on Windows it loads the system stores, but the guarantee is CPython-implementation detail rather than a documented, testable seam, and it does not follow the operator's own enterprise trust configuration as directly as `truststore`.
- **Stdlib `ssl` with OpenSSL's bundled CA file (`certifi`):** ignores the Windows store the spec names, so it is out.
