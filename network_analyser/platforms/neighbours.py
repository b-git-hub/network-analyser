"""Reading a device's CDP and LLDP tables into Neighbour records (ticket #50; stories 60-65).

IOS/IOS-XE text and NX-OS `| json` output are read here rather than by ntc-templates: those
templates keep only the first address of each Neighbour, and the crawl needs every
management address first, then the others (story 65). Only what the crawl and the Links need
is read: ports, addresses, the Platform and description text, capabilities and the LLDP
Chassis id. Device text is untrusted (#28, #30): each value is made printable and capped,
and an address that does not parse is dropped. A table the device refused, or that is not
understood, is unknown, never "no Neighbours"; the output itself is never kept.
"""

import json
import re
from collections.abc import Iterable, Iterator, Mapping
from enum import Enum, unique
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Final

from network_analyser.records.collected import Neighbour
from network_analyser.records.interface_names import interface_name
from network_analyser.records.unknown import Unknown

type Address = IPv4Address | IPv6Address
type Table = tuple[Neighbour, ...] | Unknown


@unique
class NeighbourProtocol(Enum):
    """The discovery protocol a table comes from: `Collected.cdp` or `Collected.lldp`."""

    CDP = "CDP"
    LLDP = "LLDP"


TEXT_LIMIT: Final = 255
"""The most characters kept of any one value (an RFC 4253 identification line's limit)."""

_NOT_ENABLED: Final = re.compile(r"^%.*\bnot enabled\b", re.MULTILINE | re.IGNORECASE)
_DEVICE_ERROR: Final = re.compile(r"^\s*%|Invalid input detected|Invalid command", re.MULTILINE)
_NOT_ADVERTISED: Final = "not advertised"
_NO_PORT: Final = "the Neighbour's port was not advertised"
_MAX_VLAN: Final = 4094
LOCAL_PORT_NOT_SHOWN: Final = "not-shown"
"""The local port name kept when a table entry did not show it (an unknown name)."""


def table_problem(protocol: NeighbourProtocol, text: str) -> Unknown | None:
    """Say why a table is unknown when the device refused the command; else None."""
    if _NOT_ENABLED.search(text):
        return Unknown(f"{protocol.value} is not enabled on the device")
    if _DEVICE_ERROR.search(text):
        return Unknown(f"the device refused the {protocol.value} neighbour command")
    return None


# -- IOS/IOS-XE text --------------------------------------------------------------------------

_CDP_START: Final = re.compile(r"^Device ID:", re.MULTILINE)
_CDP_DEVICE_ID: Final = re.compile(r"^Device ID:\s*(.*)$", re.MULTILINE)
_CDP_PLATFORM: Final = re.compile(
    r"^Platform\s*:\s*(.*?)\s*,\s*Capabilities\s*:\s*(.*)$", re.MULTILINE
)
_CDP_PORTS: Final = re.compile(
    r"^Interface\s*:\s*(.*?)\s*,\s*Port ID \(outgoing port\)\s*:\s*(.*)$", re.MULTILINE
)
_CDP_VERSION: Final = re.compile(r"^Version\s*:\s*\n\s*(\S.*)$", re.MULTILINE)
_CDP_NATIVE_VLAN: Final = re.compile(r"^Native VLAN\s*:\s*(\d{1,4})\s*$", re.MULTILINE)
_CDP_OTHER_HEADER: Final = re.compile(r"^(?:Entry|Interface) address\(es\)\s*:", re.IGNORECASE)
_CDP_MGMT_HEADER: Final = re.compile(r"^(?:Management|Mgmt) address\(es\)\s*:", re.IGNORECASE)
_CDP_ADDRESS: Final = re.compile(r"^\s+IP(?:v4|v6)? address\s*:\s*(\S+)", re.IGNORECASE)

_LLDP_START: Final = re.compile(r"^Local Intf:", re.MULTILINE)
_LLDP_LOCAL: Final = re.compile(r"^Local Intf:\s*(\S+)", re.MULTILINE)
_LLDP_CHASSIS: Final = re.compile(r"^Chassis id:\s*(\S+)", re.MULTILINE)
_LLDP_PORT: Final = re.compile(r"^Port id:\s*(.*)$", re.MULTILINE)
_LLDP_NAME: Final = re.compile(r"^System Name:\s*(.*)$", re.MULTILINE)
_LLDP_DESCRIPTION: Final = re.compile(r"^System Description:[ \t]*\n?[ \t]*(\S.*)$", re.MULTILINE)
_LLDP_MGMT_HEADER: Final = re.compile(r"^Management Addresses\s*:\s*$", re.IGNORECASE)
_LLDP_ADDRESS: Final = re.compile(r"^\s+IP(?:V6)?\s*:\s*(\S+)", re.IGNORECASE)


def read_ios_cdp(text: str) -> Table:
    """Read `show cdp neighbors detail`."""
    return table_problem(NeighbourProtocol.CDP, text) or tuple(
        _ios_cdp_entry(block) for block in _blocks(_CDP_START, text)
    )


def read_ios_lldp(text: str) -> Table:
    """Read `show lldp neighbors detail`."""
    return table_problem(NeighbourProtocol.LLDP, text) or tuple(
        _ios_lldp_entry(block) for block in _blocks(_LLDP_START, text)
    )


def _blocks(start: re.Pattern[str], text: str) -> Iterator[str]:
    """Yield each entry of a detail table: from one start line to the next."""
    starts = [m.start() for m in start.finditer(text)]
    for begin, end in zip(starts, [*starts[1:], len(text)], strict=False):
        yield text[begin:end]


def _ios_cdp_entry(block: str) -> Neighbour:
    platform = _CDP_PLATFORM.search(block)
    ports = _CDP_PORTS.search(block)
    version = _CDP_VERSION.search(block)
    native = _CDP_NATIVE_VLAN.search(block)
    return _neighbour(
        local=ports.group(1) if ports else None,
        remote=ports.group(2) if ports else None,
        addresses=(
            *_section_addresses(block, _CDP_MGMT_HEADER, _CDP_ADDRESS),
            *_section_addresses(block, _CDP_OTHER_HEADER, _CDP_ADDRESS),
        ),
        name=_one(_CDP_DEVICE_ID.search(block)),
        platform=(platform.group(1) if platform else None, version.group(1) if version else None),
        native_vlan=native.group(1) if native else None,
    )


def _ios_lldp_entry(block: str) -> Neighbour:
    return _neighbour(
        local=_one(_LLDP_LOCAL.search(block)),
        remote=_one(_LLDP_PORT.search(block)),
        addresses=_section_addresses(block, _LLDP_MGMT_HEADER, _LLDP_ADDRESS),
        name=_one(_LLDP_NAME.search(block)),
        platform=(_one(_LLDP_DESCRIPTION.search(block)),),
        chassis_id=_one(_LLDP_CHASSIS.search(block)),
    )


def _section_addresses(
    block: str, header: re.Pattern[str], address: re.Pattern[str]
) -> tuple[Address, ...]:
    """Return the addresses listed under each `header` line, up to the next unindented line."""
    found: list[Address] = []
    inside = False
    for line in block.splitlines():
        if header.match(line):
            inside = True
            continue
        if not inside:
            continue
        match = address.match(line)
        if match:
            found.extend(_addresses([match.group(1)]))
        elif line.strip() and not line[0].isspace():
            inside = False
    return tuple(dict.fromkeys(found))


# -- NX-OS JSON ----------------------------------------------------------------------------


def read_nxos_cdp(text: str) -> Table:
    """Read `show cdp neighbors detail | json` (keys provisional: lab check)."""
    rows = _json_rows(NeighbourProtocol.CDP, text, "cdp_neighbor_detail_info")
    if isinstance(rows, Unknown):
        return rows
    return tuple(_nxos_cdp_entry(row) for row in rows)


def read_nxos_lldp(text: str) -> Table:
    """Read `show lldp neighbors detail | json` (keys provisional: lab check)."""
    rows = _json_rows(NeighbourProtocol.LLDP, text, "nbor_detail")
    if isinstance(rows, Unknown):
        return rows
    return tuple(_nxos_lldp_entry(row) for row in rows)


def _json_rows(
    protocol: NeighbourProtocol, text: str, name: str
) -> list[Mapping[str, object]] | Unknown:
    """Return the `TABLE_<name>` / `ROW_<name>` rows; one row may come as a bare object."""
    if not text.strip():
        return []
    problem = table_problem(protocol, text)
    if problem is not None:
        return problem
    try:
        data: object = json.loads(text)
    except ValueError:
        data = None
    table = data.get(f"TABLE_{name}", {}) if isinstance(data, dict) else None
    rows = table.get(f"ROW_{name}", []) if isinstance(table, dict) else None
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        return Unknown(f"{protocol.value} neighbour output not understood")
    return rows


def _nxos_cdp_entry(row: Mapping[str, object]) -> Neighbour:
    return _neighbour(
        local=_first(row, "intf_id"),
        remote=_first(row, "port_id"),
        addresses=_addresses(
            [
                *_strings(row, "v4mgmtaddr"),
                *_strings(row, "v6mgmtaddr"),
                *_strings(row, "v4addr"),
                *_strings(row, "v6addr"),
            ]
        ),
        name=_label_or_none(_first(row, "device_id")),
        platform=(_first(row, "platform_id"), _first(row, "version")),
        native_vlan=_first(row, "nativevlan"),
    )


def _nxos_lldp_entry(row: Mapping[str, object]) -> Neighbour:
    return _neighbour(
        local=_first(row, "l_port_id"),
        remote=_first(row, "port_id"),
        addresses=_addresses([*_strings(row, "mgmt_addr"), *_strings(row, "mgmt_addr_ipv6")]),
        name=_label_or_none(_first(row, "sys_name")),
        platform=(_first(row, "sys_desc"),),
        chassis_id=_label_or_none(_first(row, "chassis_id")),
    )


def _neighbour(  # noqa: PLR0913 (one argument per advertised field)
    *,
    local: str | None,
    remote: str | None,
    addresses: Iterable[Address],
    name: str | None,
    platform: tuple[str | None, ...],
    chassis_id: str | None = None,
    native_vlan: str | None = None,
) -> Neighbour:
    """Build one entry: IPv4 addresses in the order advertised (management first), then IPv6."""
    ordered = tuple(dict.fromkeys(addresses))
    shown = [t for t in (_label_or_none(p) for p in platform) if t]
    local_port = _label_or_none(local)
    remote_port = _label_or_none(remote)
    vlan = int(native_vlan) if native_vlan and native_vlan.isdigit() else None
    return Neighbour(
        local_port=interface_name(local_port or LOCAL_PORT_NOT_SHOWN),
        name=name or Unknown("no name was advertised"),
        remote_port=interface_name(remote_port) if remote_port else Unknown(_NO_PORT),
        addresses=tuple(a for a in ordered if isinstance(a, IPv4Address)),
        platform="; ".join(shown) if shown else Unknown("no Platform string was advertised"),
        ipv6_addresses=tuple(a for a in ordered if isinstance(a, IPv6Address)),
        chassis_id=chassis_id,
        native_vlan=vlan if vlan is not None and 1 <= vlan <= _MAX_VLAN else None,
    )


def _strings(row: Mapping[str, object], key: str) -> list[str]:
    value = row.get(key)
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _first(row: Mapping[str, object], key: str) -> str | None:
    values = _strings(row, key)
    return values[0] if values else None


# -- Values ---------------------------------------------------------------------------------


def label(value: str) -> str:
    """Return device text as one printable line: other characters become `?`, capped."""
    line = value.strip().splitlines()[0] if value.strip() else ""
    return "".join(c if " " <= c <= "~" else "?" for c in line.strip())[:TEXT_LIMIT]


def _label_or_none(value: str | None) -> str | None:
    if value is None:
        return None
    text = label(value)
    return text if text and _NOT_ADVERTISED not in text.lower() else None


def _one(match: re.Match[str] | None) -> str | None:
    return _label_or_none(match.group(1)) if match else None


def _addresses(values: Iterable[str]) -> tuple[Address, ...]:
    found: list[Address] = []
    for value in values:
        try:
            found.append(ip_address(value.strip()))
        except ValueError:
            continue  # not an address: dropped, never guessed at
    return tuple(dict.fromkeys(found))
