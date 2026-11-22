"""Reading a number out of Cisco's reply without ever raising (#133).

`str.isdigit()` is true for `"²"` and for digits of other scripts, and `int()` refuses a digit
string of more than 4300 characters, so neither may judge text from the internet. A number is
a real JSON integer or one to four ASCII digits; anything else is simply not a number, and the
caller falls back to a safe default.
"""

import re
from typing import Final

_DIGITS: Final = re.compile(r"[0-9]{1,4}")


def whole_number(value: object) -> int | None:
    """Return `value` as a whole number of at least 0, or None when it is not one.

    A JSON integer is taken as it is (a boolean is not a number) and a string must be one to
    four ASCII digits, so a string of thousands of digits, a sign, a fraction, spaces or any
    other script's digits all come back as None.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and _DIGITS.fullmatch(value):
        return int(value)
    return None


def last_page(value: object, *, ceiling: int) -> int:
    """Return the last page a reply names, from 1 up to `ceiling`; 1 when it names none."""
    pages = whole_number(value)
    if pages is None or pages < 1:
        return 1
    return min(pages, ceiling)
