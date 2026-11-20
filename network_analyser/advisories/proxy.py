"""The only two places the proxy may come from: Windows' setting, or `--proxy` (#95, story 17).

`HTTPS_PROXY` and every other environment variable are never read: a variable can be changed
behind the operator's back, and the proxy is part of where the tool's traffic goes. The caller
hands in a `ProxyConfig`; the default is Windows' own Internet Settings, read by `_winsys`.

A setting the tool cannot use (a SOCKS address, a `user:password@host` form, a bare hostname)
is refused rather than ignored, so a Run never quietly goes direct when the operator expected
a proxy. The fence itself is unaffected: whatever the proxy, it only ever learns the exact
Cisco host and port.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, unique

from network_analyser._winsys import system_proxy

# A host name or dotted address and a port, nothing else: no scheme, path or credentials.
_ADDRESS = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}):[0-9]{1,5}")
_MAX_PORT = 65535


@unique
class ProxyMode(Enum):
    """Where the proxy setting comes from."""

    WINDOWS = "windows"
    DIRECT = "direct"
    EXPLICIT = "explicit"


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    """How to reach Cisco: through Windows' proxy, directly, or through a given proxy.

    Attributes:
        mode: windows, direct, or an explicit proxy.
        address: `host:port` when the mode is explicit; None otherwise.
    """

    mode: ProxyMode = ProxyMode.WINDOWS
    address: str | None = None

    @classmethod
    def direct(cls) -> ProxyConfig:
        """Return the setting that makes no proxy at all (`HTTPS_PROXY` is still never read)."""
        return cls(mode=ProxyMode.DIRECT)

    @classmethod
    def explicit(cls, address: str) -> ProxyConfig:
        """Return the setting for `--proxy host:port`.

        Raises:
            ValueError: the text is not a host and port, so it is never used.
        """
        if _parse(address) is None:
            msg = "the proxy must be host:port, with no scheme or password"
            raise ValueError(msg)
        return cls(mode=ProxyMode.EXPLICIT, address=address)


@dataclass(frozen=True, slots=True)
class ProxyTarget:
    """The HTTP proxy the transport must tunnel through.

    Attributes:
        host: the proxy's host name or address.
        port: the proxy's port.
    """

    host: str
    port: int


@dataclass(frozen=True, slots=True)
class ProxyNotUsable:
    """The configured proxy cannot be used, so the Run must not go online.

    Attributes:
        reason: fixed text for the operator, such as
            `the Windows proxy setting is not a host and port`.
    """

    reason: str


def resolve_proxy(
    config: ProxyConfig, *, system: Callable[[], str | None] = system_proxy
) -> ProxyTarget | ProxyNotUsable | None:
    """Return the proxy to tunnel through, None for a direct connection, or why not.

    `system` is Windows' proxy setting; tests replace it so no registry is read.
    """
    if config.mode is ProxyMode.DIRECT:
        return None
    if config.mode is ProxyMode.EXPLICIT:
        return _parse(config.address or "") or ProxyNotUsable(
            "the proxy setting is not a host and port"
        )
    return _windows(system())


def _windows(raw: str | None) -> ProxyTarget | ProxyNotUsable | None:
    if raw is None:
        return None
    address = _chosen_address(raw)
    if address is None:
        return ProxyNotUsable("the Windows proxy setting names no HTTP proxy")
    if "@" in address:
        return ProxyNotUsable(
            "the Windows proxy setting holds a password, which the tool never reads"
        )
    return _parse(address) or ProxyNotUsable("the Windows proxy setting is not a host and port")


def _chosen_address(raw: str) -> str | None:
    """Pick the HTTPS (then HTTP, then bare) address from Windows' `ProxyServer` value."""
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    schemes: dict[str, str] = {}
    bare: str | None = None
    for part in parts:
        scheme, separator, address = part.partition("=")
        if separator:
            schemes[scheme.strip().lower()] = address.strip()
        else:
            bare = bare or part
    return schemes.get("https") or schemes.get("http") or bare


def _parse(address: str) -> ProxyTarget | None:
    if _ADDRESS.fullmatch(address) is None:
        return None
    host, _, port_text = address.rpartition(":")
    port = int(port_text)
    if not 0 < port <= _MAX_PORT:
        return None
    return ProxyTarget(host=host, port=port)
