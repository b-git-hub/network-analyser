"""Strict patterns for every value Analysis may hand the online step (stories 12-14).

A value that does not match is dropped, never sent. The pattern alone cannot tell a PID from
a hostname, so only fields that hold a model or a release are ever offered here: never a
hostname, address, serial or interface name.
"""

import re
from typing import Final

_PID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{2,63}(?:/[A-Za-z0-9-]{1,16})?")
_DIGIT: Final = re.compile(r"[0-9]")
_RELEASE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9.()_-]{0,31}")


def valid_pid(value: object) -> bool:
    """Return True when `value` is a Cisco PID shape safe to send (at least one digit)."""
    return (
        isinstance(value, str) and _PID.fullmatch(value) is not None and bool(_DIGIT.search(value))
    )


def valid_release(value: object) -> bool:
    """Return True when `value` is a release-string shape safe to send."""
    return isinstance(value, str) and _RELEASE.fullmatch(value) is not None
