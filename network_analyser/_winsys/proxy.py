"""Windows' own proxy setting, read for `advisories` (#95; story 17; #150).

Only the per-user Internet Settings key is read (`ProxyEnable`, `ProxyServer` and
`AutoConfigURL`), and only with `KEY_READ`: this module never writes one. What the values mean
is decided by its caller, `advisories.proxy`, so it can be tested with a fake on any OS.
Environment variables such as `HTTPS_PROXY` are never read, here or anywhere.

The bypass list and WPAD auto-detection are not read. Ignoring the bypass list can only route
more traffic through the proxy the operator configured, never around it; the auto-detect flag
lives in a binary connection-settings value this module does not parse, so a machine set up
with WPAD alone still reads as no proxy setting here (#150).

On a machine without the Windows registry the function says there is no proxy setting, which
leaves the caller with a direct connection.
"""

import sys
from dataclasses import dataclass

_INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


@dataclass(frozen=True, slots=True)
class WindowsProxy:
    """Windows' proxy setting, as much of it as the tool can use.

    Attributes:
        server: the `ProxyServer` text, which can be `host:port` or a semicolon-separated
            list such as `http=host:port;https=host:port`; None when no proxy server is set.
        script: the `AutoConfigURL` PAC script URL; None when none is set. The caller refuses
            it, because running a script is not something the tool does.
    """

    server: str | None = None
    script: str | None = None


if sys.platform == "win32":
    import winreg

    def _value(key: winreg.HKEYType, name: str) -> object:
        """Return one value, or None when Windows does not hold it."""
        try:
            value, _kind = winreg.QueryValueEx(key, name)
        except OSError:
            return None
        return value

    def system_proxy() -> WindowsProxy | None:
        """Return Windows' proxy setting, or None when none is set or it cannot be read.

        The values are returned as written; the caller validates and picks from them. A PAC
        script is reported rather than ignored, so a Run never quietly goes direct when the
        operator expected a proxy. An unreadable setting is None.
        """
        try:
            with winreg.OpenKeyEx(
                winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS, 0, winreg.KEY_READ
            ) as key:
                enabled = _value(key, "ProxyEnable")
                server = _value(key, "ProxyServer")
                script = _value(key, "AutoConfigURL")
        except OSError:
            return None
        return _setting(enabled, server, script)

else:

    def system_proxy() -> WindowsProxy | None:
        """Say there is no Windows proxy setting on this machine."""
        return None


def _setting(enabled: object, server: object, script: object) -> WindowsProxy | None:
    """Return the usable parts of Windows' values, or None when there are none."""
    server_text = server.strip() if enabled and isinstance(server, str) and server.strip() else None
    script_text = script.strip() if isinstance(script, str) and script.strip() else None
    if server_text is None and script_text is None:
        return None
    return WindowsProxy(server=server_text, script=script_text)
