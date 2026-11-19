"""Stable ids, worked out from what they name (`records.topology` explains the scheme)."""

import hashlib
import re
from collections.abc import Iterable
from ipaddress import IPv4Address
from typing import Final

from network_analyser.records.unknown import Unknown

_SAFE: Final = re.compile(r"[A-Za-z0-9._-]{1,64}")
_DIGITS: Final = 12


def hashed(prefix: str, parts: Iterable[str]) -> str:
    """Return `<prefix>-` and 12 hex digits from `parts`, taken in the order given."""
    text = "\x1f".join(parts)
    return f"{prefix}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:_DIGITS]}"


def device_id(serials: tuple[str, ...] | Unknown, management_ip: IPv4Address) -> str:
    """Return a Visited Device's id: its first serial, else the address logged into."""
    if not isinstance(serials, Unknown) and serials and _SAFE.fullmatch(serials[0]):
        return f"dev-{serials[0]}"
    return f"dev-ip-{management_ip}"


def unique(ids: Iterable[str]) -> list[str]:
    """Return `ids` with a repeat made unique by `-2`, `-3`... in the order given."""
    seen: dict[str, int] = {}
    out: list[str] = []
    for item in ids:
        count = seen.get(item, 0) + 1
        seen[item] = count
        out.append(item if count == 1 else f"{item}-{count}")
    return out
