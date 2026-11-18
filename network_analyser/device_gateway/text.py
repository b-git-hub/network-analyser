r"""Make device text safe before anything reads it (spec #37 "Redaction layers"; #28, #30).

A device is untrusted: its output may hold terminal escape codes that would rewrite the
operator's console, or be far larger than any real reply. Output is cut at `OUTPUT_CAP`
while it is read (in `ssh`), and here escape sequences and control characters are stripped
before any parser sees it. Short strings that go into a record, such as the SSH
identification string, are kept as printable ASCII with anything else shown as `\xNN`.
"""

import re
from typing import Final

OUTPUT_CAP: Final = 1_000_000
"""The most characters one command's reply may hold; reading stops beyond it."""

_ESCAPES: Final = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI: colours, cursor moves, screen clears
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC: window titles and the like
    r"|\x1b[@-_]?"  # any other escape
)
# Every C0 and C1 control but tab and line feed, and DEL.
_CONTROLS: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_FIRST_PRINTABLE: Final = 0x20
_LAST_PRINTABLE: Final = 0x7E
_BYTE: Final = 0xFF


def clean_output(text: str) -> str:
    """Return device output with escape sequences, carriage returns and controls removed."""
    return _CONTROLS.sub("", _ESCAPES.sub("", text))


def printable(text: str, limit: int) -> str:
    r"""Return `text` as printable ASCII, cut to `limit`, anything else shown as `\xNN`."""
    return "".join(_escape(ch) for ch in text[:limit])


def _escape(ch: str) -> str:
    code = ord(ch)
    if _FIRST_PRINTABLE <= code <= _LAST_PRINTABLE and ch != "\\":
        return ch
    return f"\\x{code:02x}" if code <= _BYTE else f"\\u{code:04x}"
