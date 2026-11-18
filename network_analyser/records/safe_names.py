"""The strict character allow-list for names the tool puts on disk (decision #26).

`--label` (in a Run folder name, at most 32 characters, #42) and Backup names (at most 64,
#51) share it: ASCII letters, digits, `-`, `.` and `_`. It lives in `records`, the leaf every
module may import, so both owners check names the same way.
"""

import re
from typing import Final

SAFE_NAME_CHARACTERS: Final = "letters, digits, - . _"
_SAFE_NAME: Final = re.compile(r"[A-Za-z0-9._-]+")


def safe_name_problem(text: str, max_length: int) -> str | None:
    """Return why `text` is not a safe name, or None when it is.

    The reason is fixed text and never quotes `text`. A name may not end with `.`, because
    Windows silently drops a trailing dot from a folder or file name.
    """
    if not text or len(text) > max_length:
        return f"must be 1 to {max_length} characters"
    if not _SAFE_NAME.fullmatch(text):
        return f"may hold only {SAFE_NAME_CHARACTERS}"
    if text.endswith("."):
        return "may not end with ."
    return None
