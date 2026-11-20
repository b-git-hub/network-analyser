"""Windows' own proxy setting, read for `advisories` (#95; story 17).

Only the per-user Internet Settings value is read (`ProxyEnable` and `ProxyServer`), and only
with `KEY_READ`: this module never writes one. What the string means is decided by its caller,
`advisories.proxy`, so it can be tested with a fake on any OS. Environment variables such as
`HTTPS_PROXY` are never read, here or anywhere.

On a machine without the Windows registry the function says there is no proxy setting, which
leaves the caller with a direct connection.
"""

import sys

_INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

if sys.platform == "win32":
    import winreg

    def system_proxy() -> str | None:
        """Return Windows' proxy server setting, or None when no proxy is enabled.

        The value is Windows' own `ProxyServer` string, which can be `host:port` or a
        semicolon-separated list such as `http=host:port;https=host:port`. It is returned as
        written; the caller validates and picks from it. An unreadable setting is None.
        """
        try:
            with winreg.OpenKeyEx(
                winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS, 0, winreg.KEY_READ
            ) as key:
                enabled, _kind = winreg.QueryValueEx(key, "ProxyEnable")
                server, _kind = winreg.QueryValueEx(key, "ProxyServer")
        except OSError:
            return None
        if not enabled or not isinstance(server, str) or not server.strip():
            return None
        return server

else:

    def system_proxy() -> str | None:
        """Say there is no Windows proxy setting on this machine."""
        return None
