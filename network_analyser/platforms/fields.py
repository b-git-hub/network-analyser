"""Checks on single values read from device output, before they go into a record.

Device text is untrusted (#28, #30): a value goes into a record only when it looks like what
it claims to be, else it is unknown. That keeps terminal escapes, spaces and oversized text
out of the record, the report and the Topology.
"""

import re
from collections.abc import Iterable, Mapping
from typing import Final

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


def _first(row: Mapping[str, object] | None, key: str) -> str | None:
    values = text_list(row, key)
    return values[0].strip() if values else None
