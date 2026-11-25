r"""Windows' own proxy setting, read for `advisories` (#95; story 17; #150).

Only the per-user Internet Settings key (`ProxyEnable`, `ProxyServer`, `AutoConfigURL`) and its
`Connections\DefaultConnectionSettings` binary value are read, only with `KEY_READ`. From the
binary value only the AutoDetect flag (0x8) and the auto-config URL (flag 0x4) are taken, by
`connection_settings`, a pure function tested with synthetic bytes (#192); a short or malformed
value counts as not set. Nothing is fetched: the caller refuses a PAC URL, and for WPAD alone
connects directly with a notice. The bypass list is not read: ignoring it can only route more
traffic through the proxy the operator configured, never around it; whether to honour it stays
an operator decision (#192).

On a machine without the Windows registry the function says there is no proxy setting, which
leaves the caller with a direct connection.
"""

import sys
from dataclasses import dataclass

_INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_CONNECTIONS = _INTERNET_SETTINGS + r"\Connections"
_CONNECTION_VALUE = "DefaultConnectionSettings"
_AUTO_PROXY_URL = 0x4
_AUTO_DETECT = 0x8
_FLAGS_END = 12
_MAX_BLOB = 65536
_LENGTH = 4


@dataclass(frozen=True, slots=True)
class WindowsProxy:
    """Windows' proxy setting, as much of it as the tool can use.

    Attributes:
        server: the `ProxyServer` text, which can be `host:port` or a semicolon-separated
            list such as `http=host:port;https=host:port`; None when no proxy server is set.
        script: the `AutoConfigURL` PAC script URL; None when none is set. The caller refuses
            it, because running a script is not something the tool does.
        auto_detect: Windows' "Automatically detect settings" (WPAD) is on. The tool does not
            use WPAD: it connects directly and the Run prints a notice (#192).
    """

    server: str | None = None
    script: str | None = None
    auto_detect: bool = False


@dataclass(frozen=True, slots=True)
class ConnectionSettings:
    """What the tool reads from WinINET's binary DefaultConnectionSettings (#192).

    Attributes:
        auto_detect: the PROXY_TYPE_AUTO_DETECT flag (0x8) is set.
        script: the auto-config URL when PROXY_TYPE_AUTO_PROXY_URL (0x4) is set; else None.
    """

    auto_detect: bool
    script: str | None


def connection_settings(blob: object) -> ConnectionSettings | None:
    """Read the AutoDetect flag and auto-config URL from the binary connection value.

    A value that is not bytes, too short for the flags, or larger than any real setting
    counts as no setting, so a missing or malformed value never breaks a Run.
    """
    if not isinstance(blob, bytes) or len(blob) < _FLAGS_END or len(blob) > _MAX_BLOB:
        return None
    flags = int.from_bytes(blob[8:12], "little")
    script = _auto_config_url(blob) if flags & _AUTO_PROXY_URL else None
    return ConnectionSettings(auto_detect=bool(flags & _AUTO_DETECT), script=script)


def _auto_config_url(blob: bytes) -> str | None:
    """Walk the three length-prefixed fields and return the auto-config URL, or None."""
    offset = _FLAGS_END
    field = b""
    for _ in range(3):
        if offset + _LENGTH > len(blob):
            return None
        size = int.from_bytes(blob[offset : offset + _LENGTH], "little")
        start = offset + _LENGTH
        end = start + size
        if end > len(blob):
            return None
        field = blob[start:end]
        offset = end
    try:
        text = field.decode("ascii")
    except UnicodeDecodeError:
        return None
    text = text.strip()
    return text if text and text.isprintable() else None


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
        try:
            with winreg.OpenKeyEx(
                winreg.HKEY_CURRENT_USER, _CONNECTIONS, 0, winreg.KEY_READ
            ) as connections_key:
                connections = _value(connections_key, _CONNECTION_VALUE)
        except OSError:
            connections = None
        return windows_proxy(enabled, server, script, connections)

else:

    def system_proxy() -> WindowsProxy | None:
        """Say there is no Windows proxy setting on this machine."""
        return None


def windows_proxy(
    enabled: object, server: object, script: object, connections: object
) -> WindowsProxy | None:
    """Return the usable parts of Windows' values, or None when there are none.

    Pure: tests call it with synthetic values.
    """
    server_text = server.strip() if enabled and isinstance(server, str) and server.strip() else None
    script_text = script.strip() if isinstance(script, str) and script.strip() else None
    parsed = connection_settings(connections)
    if script_text is None and parsed is not None:
        script_text = parsed.script
    auto_detect = parsed is not None and parsed.auto_detect
    if server_text is None and script_text is None and not auto_detect:
        return None
    return WindowsProxy(server=server_text, script=script_text, auto_detect=auto_detect)
