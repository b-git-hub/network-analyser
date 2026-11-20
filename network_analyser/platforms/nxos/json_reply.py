"""Reading one NX-OS `| json` reply, and the checked values inside it (#60).

NX-OS shapes every table as `TABLE_<name>` holding `ROW_<name>`, where a lone row comes as a
bare object instead of a list (and a table can itself be a list of such objects), and gives
numbers sometimes as numbers and sometimes as text. An empty reply means the table is empty:
NX-OS sends nothing at all for a `| json` table with no rows.

Device text is untrusted (#28, #30). A reply that is an error message is classed as denied
or rejected without being quoted; a reply or value that does not have the expected shape
raises `NotUnderstood`, so the whole command's data is unknown, never guessed. Text kept
for display is made one printable line and capped.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address, IPv4Interface, NetmaskValueError
from typing import Final

from network_analyser.records.collected import ALL_VLANS
from network_analyser.records.interface_names import InterfaceName, interface_name

type Row = Mapping[str, object]

TEXT_LIMIT: Final = 255
"""The most characters kept of any one value."""

DENIED: Final = "denied"
REJECTED: Final = "rejected by the device"
NOT_UNDERSTOOD: Final = "not understood"

_DENIED: Final = re.compile(
    r"permission denied|authori[sz]ation failed|not authori[sz]ed", re.IGNORECASE
)
_ERROR: Final = re.compile(
    r"^\s*(?:%|\^|Syntax error|Invalid (?:command|input))", re.MULTILINE | re.IGNORECASE
)
_PORT: Final = re.compile(r"[A-Za-z][A-Za-z-]* ?\d+(?:/\d+)*(?:[.:]\d+)?")
_MAC_SEPARATORS: Final = re.compile(r"[.:-]")
_MAC: Final = re.compile(r"[0-9a-f]{12}")
_VLAN_RANGE: Final = re.compile(r"(\d{1,4})(?:-(\d{1,4}))?")
_MAX_VLAN: Final = 4094


class NotUnderstood(Exception):  # noqa: N818 (a parse outcome, not a programming error)
    """A reply or value does not have the expected shape. Never carries device text."""


@dataclass(frozen=True, slots=True)
class Refused:
    """The device answered with an error message instead of data.

    Attributes:
        reason: `denied` (the role or AAA refused it) or `rejected by the device`.
    """

    reason: str


def read(text: str) -> Row | Refused:
    """Return the reply's top-level JSON object; empty for an empty reply.

    Raises:
        NotUnderstood: the reply is neither an error message nor a JSON object.
    """
    stripped = text.strip()
    if not stripped:
        return {}
    if not stripped.startswith("{"):
        refused = refusal(stripped)
        if refused is not None:
            return refused
        raise NotUnderstood
    try:
        data: object = json.loads(stripped)
    except ValueError, RecursionError:  # nesting too deep to read is device text too
        raise NotUnderstood from None
    if not isinstance(data, dict):
        raise NotUnderstood
    return data


def refusal(text: str) -> Refused | None:
    """Return how a reply refused the command, or None when it may be data.

    A reply that is an error message is `denied` (the role or AAA refused it) or `rejected by
    the device`; anything else, including a JSON object, may be data. Never quotes the reply.
    """
    stripped = text.strip()
    if not stripped or stripped.startswith("{"):
        return None
    if _DENIED.search(stripped):
        return Refused(DENIED)
    if _ERROR.search(stripped):
        return Refused(REJECTED)
    return None


def rows(data: Row, name: str) -> list[Row]:
    """Return the `TABLE_<name>` / `ROW_<name>` rows of `data`; none when it has no table."""
    table = data.get(f"TABLE_{name}")
    if table is None:
        return []
    found: list[Row] = []
    for part in _as_list(table):
        if not isinstance(part, dict):
            raise NotUnderstood
        row = part.get(f"ROW_{name}")
        if row is None:
            continue
        for one in _as_list(row):
            if not isinstance(one, dict):
                raise NotUnderstood
            found.append(one)
    return found


def tables(data: Row, name: str) -> list[object]:
    """Return `TABLE_<name>` as a list, for tables NX-OS gives side by side."""
    table = data.get(f"TABLE_{name}")
    return [] if table is None else _as_list(table)


def _as_list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else [value]


# -- Values ------------------------------------------------------------------------------------


def text(row: Row, key: str) -> str | None:
    """Return a field as text (a number becomes its digits); None when absent or empty."""
    value = row.get(key)
    if isinstance(value, bool):
        raise NotUnderstood
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value if value.strip() else None
    if value is None:
        return None
    raise NotUnderstood


def required(row: Row, key: str) -> str:
    """Return a field that must be there."""
    value = text(row, key)
    if value is None:
        raise NotUnderstood
    return value


def number(value: str | None) -> int:
    """Return a whole number given as digits."""
    if value is None or not value.strip().isdigit():
        raise NotUnderstood
    return int(value.strip())


def label(value: str) -> str:
    """Return device text as one printable line: other characters become `?`, capped."""
    line = value.strip().splitlines()[0] if value.strip() else ""
    return "".join(c if " " <= c <= "~" else "?" for c in line.strip())[:TEXT_LIMIT]


def port(value: str) -> InterfaceName:
    """Return an interface name from the fixed table, keeping the name as reported."""
    shown = label(value)
    if not shown:
        raise NotUnderstood
    return interface_name(shown)


def is_port(value: str) -> bool:
    """Say whether `value` looks like a port name, not a pseudo-port such as `sup-eth1(R)`."""
    return _PORT.fullmatch(value.strip()) is not None


def ipv4(value: str | None) -> IPv4Address:
    """Return an IPv4 address."""
    if value is None:
        raise NotUnderstood
    try:
        return IPv4Address(value.strip())
    except AddressValueError:
        raise NotUnderstood from None


def ipv4_interface(address: str | None, length: str | None) -> IPv4Interface:
    """Return an address with its prefix length, such as `192.0.2.1/24`."""
    try:
        return IPv4Interface(f"{ipv4(address)}/{number(length)}")
    except AddressValueError, NetmaskValueError:
        raise NotUnderstood from None


def mac(value: str | None) -> str | None:
    """Return a MAC address as 12 lowercase hex digits; None when it is not one (INCOMPLETE)."""
    if value is None:
        return None
    digits = _MAC_SEPARATORS.sub("", value.strip()).lower()
    return digits if _MAC.fullmatch(digits) else None


def vlan_set(value: str | None) -> frozenset[int]:
    """Return the VLANs in a list such as `10,20,30-32`; `none` is the empty set."""
    if value is None:
        raise NotUnderstood
    spec = value.strip().lower()
    if spec in {"none", ""}:
        return frozenset()
    if spec == "all":
        return ALL_VLANS
    vlans: set[int] = set()
    for item in spec.replace(" ", "").split(","):
        match = _VLAN_RANGE.fullmatch(item)
        if match is None:
            raise NotUnderstood
        first = int(match.group(1))
        last = int(match.group(2) or first)
        if not 1 <= first <= last <= _MAX_VLAN:
            raise NotUnderstood
        vlans.update(range(first, last + 1))
    return frozenset(vlans)
