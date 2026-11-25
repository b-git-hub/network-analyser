"""WinINET's binary DefaultConnectionSettings, parsed from synthetic bytes (#192).

No registry is read.
"""

import pytest

from network_analyser._winsys.proxy import (
    ConnectionSettings,
    WindowsProxy,
    connection_settings,
    windows_proxy,
)

HEAD = "4600000005000000"  # version, counter
TAIL = bytes(32)
AUTO_DETECT_ONLY = bytes.fromhex(HEAD + "09000000000000000000000000000000") + TAIL
DIRECT_ONLY = bytes.fromhex(HEAD + "01000000000000000000000000000000") + TAIL
SCRIPT = (
    bytes.fromhex(HEAD + "0500000000000000000000001c000000")
    + b"http://wpad.example/wpad.dat"
    + TAIL
)
SCRIPT_FLAG_OFF = (
    bytes.fromhex(HEAD + "0100000000000000000000001c000000")
    + b"http://wpad.example/wpad.dat"
    + TAIL
)
PROXY_AND_DETECT = (
    bytes.fromhex(HEAD + "0b00000012000000")
    + b"proxy.example:8080"
    + bytes.fromhex("07000000")
    + b"<local>"
    + bytes.fromhex("00000000")
    + TAIL
)
TRUNCATED_URL = bytes.fromhex(HEAD + "0d0000000000000000000000ff000000") + b"http://wpad"


def test_auto_detect_alone_is_read() -> None:
    assert connection_settings(AUTO_DETECT_ONLY) == ConnectionSettings(
        auto_detect=True, script=None
    )


def test_a_direct_only_setting_has_no_auto_detect() -> None:
    assert connection_settings(DIRECT_ONLY) == ConnectionSettings(auto_detect=False, script=None)


def test_the_auto_config_url_is_read_when_its_flag_is_set() -> None:
    assert connection_settings(SCRIPT) == ConnectionSettings(
        auto_detect=False, script="http://wpad.example/wpad.dat"
    )


def test_an_auto_config_url_with_its_flag_off_is_ignored() -> None:
    assert connection_settings(SCRIPT_FLAG_OFF) == ConnectionSettings(
        auto_detect=False, script=None
    )


def test_auto_detect_beside_a_fixed_proxy_is_read() -> None:
    assert connection_settings(PROXY_AND_DETECT) == ConnectionSettings(
        auto_detect=True, script=None
    )


def test_a_truncated_url_keeps_the_flags_and_drops_the_url() -> None:
    assert connection_settings(TRUNCATED_URL) == ConnectionSettings(auto_detect=True, script=None)


@pytest.mark.parametrize(
    "blob",
    [
        None,
        "09",
        9,
        b"",
        bytes.fromhex("4600000005000000"),
        bytes.fromhex("460000000500000009"),
        bytes(65537),
    ],
    ids=["none", "text", "int", "empty", "8-bytes", "9-bytes", "oversized"],
)
def test_an_unusable_value_is_no_setting(blob: object) -> None:
    assert connection_settings(blob) is None


def test_a_non_ascii_url_is_dropped() -> None:
    blob = bytes.fromhex(HEAD + "05000000000000000000000004000000e9e9e9e9")

    assert connection_settings(blob) == ConnectionSettings(auto_detect=False, script=None)


def test_auto_detect_alone_makes_a_windows_setting() -> None:
    assert windows_proxy(0, None, None, AUTO_DETECT_ONLY) == WindowsProxy(
        server=None, script=None, auto_detect=True
    )


def test_the_blob_url_is_used_when_auto_config_url_is_missing() -> None:
    assert windows_proxy(0, None, None, SCRIPT) == WindowsProxy(
        script="http://wpad.example/wpad.dat"
    )


def test_the_auto_config_url_value_wins_over_the_blob_url() -> None:
    setting = windows_proxy(0, None, "http://pac.example/a.pac", SCRIPT)

    assert setting is not None
    assert setting.script == "http://pac.example/a.pac"


def test_no_proxy_and_no_auto_detect_is_none() -> None:
    assert windows_proxy(0, None, None, DIRECT_ONLY) is None
    assert windows_proxy(0, None, None, None) is None


def test_a_fixed_proxy_is_kept_beside_auto_detect() -> None:
    assert windows_proxy(1, "proxy.example:8080", None, PROXY_AND_DETECT) == WindowsProxy(
        server="proxy.example:8080", auto_detect=True
    )


def test_a_disabled_proxy_server_is_still_ignored() -> None:
    assert windows_proxy(0, "proxy.example:8080", None, None) is None
