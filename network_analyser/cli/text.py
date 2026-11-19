r"""Make text the tool did not write safe to print (CODING_STANDARDS.md, "Output").

Operator entries echoed in a refusal, and later device text, may hold terminal escape codes.
They are shown as `\xNN` so they can never rewrite the console, and kept ASCII so they show
on any Windows console code page.
"""

_FIRST_PRINTABLE = 0x20
_LAST_PRINTABLE = 0x7E
_BYTE = 0xFF
_SHOWN_AT_MOST = 80


def escape_controls(text: str, limit: int | None = _SHOWN_AT_MOST) -> str:
    """Return `text` as printable ASCII, cut to `limit` characters with `...` if longer.

    A `limit` of None never cuts: `show-backup` prints a whole config line (#57).
    """
    cut = limit is not None and len(text) > limit
    shown = text[:limit] if cut else text
    escaped = "".join(_escape(ch) for ch in shown)
    return escaped + ("..." if cut else "")


def _escape(ch: str) -> str:
    code = ord(ch)
    if _FIRST_PRINTABLE <= code <= _LAST_PRINTABLE:
        return ch
    return f"\\x{code:02x}" if code <= _BYTE else f"\\u{code:04x}"
