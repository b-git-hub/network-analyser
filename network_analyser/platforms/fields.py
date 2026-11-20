"""Checks on single values read from device output, before they go into a record.

Device text is untrusted (#28, #30): a value goes into a record only when it looks like what
it claims to be, else it is unknown. That keeps terminal escapes, spaces and oversized text
out of the record, the report and the Topology.
"""

import re
from collections.abc import Iterable, Mapping
from ipaddress import IPv4Address
from typing import Final

from network_analyser.records.collected import ALL_VLANS
from network_analyser.records.device import Unknown

# One word of printable ASCII, no spaces: hostnames, models and versions.
_WORD: Final = re.compile(r"[!-~]{1,64}")
_SERIAL: Final = re.compile(r"[A-Za-z0-9]{1,40}")


def word(row: Mapping[str, object] | None, key: str, what: str) -> str | Unknown:
    """Return one printable word from a parsed row, or Unknown naming `what`."""
    value = _first(row, key)
    if value is None or not _WORD.fullmatch(value):
        return Unknown(f"{what} not found in show version")
    return value


def serials(rows: Iterable[str]) -> tuple[str, ...] | Unknown:
    """Return the distinct serials in order, or Unknown when none is well-formed."""
    found = tuple(dict.fromkeys(s.strip() for s in rows if _SERIAL.fullmatch(s.strip())))
    return found or Unknown("serial not found in show version")


def text_list(row: Mapping[str, object] | None, key: str) -> list[str]:
    """Return a parsed field as a list of strings, whether TextFSM gave a list or one value."""
    if row is None:
        return []
    value = row.get(key)
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


LABEL_LIMIT: Final = 255
"""The most characters kept of a free-text value, such as a description or a VLAN name."""
_MAC: Final = re.compile(r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|[0-9a-fA-F]{12}")
_VLAN_RANGE: Final = re.compile(r"(\d{1,4})(?:-(\d{1,4}))?")
_HIGHEST_VLAN: Final = 4094


def text(row: Mapping[str, object] | None, key: str) -> str:
    """Return a parsed field as one stripped string; empty when absent."""
    values = text_list(row, key)
    return values[0].strip() if values else ""


def label(value: str) -> str:
    """Return device text as one printable line: other characters become `?`, capped.

    For free text that goes into a record (descriptions, names). Never parsed further.
    """
    line = value.strip().splitlines()[0].strip() if value.strip() else ""
    return "".join(c if " " <= c <= "~" else "?" for c in line)[:LABEL_LIMIT]


def mac(value: str) -> str | None:
    """Return a MAC address as 12 lowercase hex digits (`records.collected`), or None."""
    found = value.strip()
    if not _MAC.fullmatch(found):
        return None
    return found.replace(".", "").lower()


def ipv4(value: str) -> IPv4Address | None:
    """Return an IPv4 address, or None when `value` is not exactly one."""
    try:
        return IPv4Address(value.strip())
    except ValueError:
        return None


def number(value: str, highest: int = _HIGHEST_VLAN) -> int | None:
    """Return a whole number from 0 to `highest`, or None."""
    found = value.strip()
    if not found.isascii() or not found.isdigit() or len(found) > len(str(highest)):
        return None
    return int(found) if int(found) <= highest else None


def vlan_set(values: Iterable[str]) -> frozenset[int] | None:
    """Return the VLANs in `10,20,30-32`-style lists, `ALL` or `none`; None if malformed."""
    pieces = [p.strip() for v in values for p in v.split(",") if p.strip()]
    if [p.lower() for p in pieces] == ["all"]:
        return ALL_VLANS
    if [p.lower() for p in pieces] in (["none"], []):
        return frozenset()
    found: set[int] = set()
    for piece in pieces:
        match = _VLAN_RANGE.fullmatch(piece)
        if match is None:
            return None
        first = int(match.group(1))
        last = int(match.group(2) or first)
        if not 1 <= first <= last <= _HIGHEST_VLAN:
            return None
        found.update(range(first, last + 1))
    return frozenset(found)


def _first(row: Mapping[str, object] | None, key: str) -> str | None:
    values = text_list(row, key)
    return values[0].strip() if values else None
