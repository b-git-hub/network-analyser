"""Stable ids for Analysis Findings, worked out the way `topology` works out its own.

A Finding's id comes from what it names, never from the order it was found (#52), so the same
network gives the same id in every Run and every surface can link to it.
"""

import hashlib
from typing import Final

_HEX_DIGITS: Final = 12


def finding_id(check_id: str, subject: str) -> str:
    """Return `finding-` and 12 hex digits from `check_id` and `subject`."""
    text = f"{check_id}\x1f{subject}"
    return f"finding-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:_HEX_DIGITS]}"
