"""`read_topology(text)`: `topology.json` read for drawing, and nothing else (#63, story 155).

The diagram is drawn from this file alone, so `render` can redraw an old Run without any
device. The rules (docs/topology-json.md):

- `format_version` must be an integer this version of the tool knows. A newer one is refused
  (`NewerFormatError`), because the file could be misread; an older one is read.
- Fields the diagram does not know are dropped, so a file from a later version that added
  optional fields still draws.
- `{"unknown": "<reason>"}` stays unknown wherever it is. A field the diagram knows but the
  file lacks (an optional field added after the file was written) reads as unknown, never as
  empty or absent.
- Every id must be a plain id (letters, digits, `.`, `-`, `_`), since the page uses ids to
  find what to draw and to open `#device=<id>`.

What is read is read-only: objects become read-only mappings and lists become tuples. A
refusal carries a fixed message and never quotes the file, which holds device text.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

KNOWN_FORMAT_VERSION: Final = 1
NOT_RECORDED: Final = "not recorded in this topology.json"

type Plain = str | int | float | bool | tuple[Plain, ...] | Mapping[str, Plain] | None
"""A value read from the file: JSON data made read-only."""

_ID = re.compile(r"[A-Za-z0-9._-]{1,200}")


class TopologyFileError(ValueError):
    """The text is not a `topology.json` this version of the tool can draw."""


class NewerFormatError(TopologyFileError):
    """The file was written by a newer version of the tool, so it is not read."""


@dataclass(frozen=True, slots=True)
class TopologyFile:
    """`topology.json` as read for drawing.

    Attributes:
        format_version: the file's format version, never newer than this tool knows.
        content: the fields the diagram knows, read-only, `format_version` left out.
    """

    format_version: int
    content: Mapping[str, Plain]


class _Leaf:
    """Any plain value: text, a number, true/false, null, unknown, or a list of these."""


class _Id:
    """A plain id: required, and only letters, digits, `.`, `-` and `_`."""


LEAF: Final = _Leaf()
ID: Final = _Id()

type _Schema = _Leaf | _Id | list[_Schema] | dict[str, _Schema]

_NAME: dict[str, _Schema] = {"short": LEAF, "reported": LEAF, "known": LEAF}
_EVIDENCE: dict[str, _Schema] = {"device": ID, "command": LEAF, "source": LEAF}
_PORT: dict[str, _Schema] = {"device": ID, "interface": _NAME}
_INTERFACE: dict[str, _Schema] = {
    "name": _NAME,
    "description": LEAF,
    "admin_up": LEAF,
    "line_up": LEAF,
    "speed": LEAF,
    "mode": LEAF,
    "access_vlan": LEAF,
    "native_vlan": LEAF,
    "allowed_vlans": LEAF,
    "ip": {"vrf": LEAF, "addresses": [LEAF], "unnumbered": LEAF},
    "bundle": LEAF,
    "stack_member": LEAF,
}
_VPC: dict[str, _Schema] = {
    "domain": LEAF,
    "peer_link": _NAME,
    "keepalive": {"source": LEAF, "destination": LEAF, "vrf": LEAF},
    "port_channels": [{"number": LEAF, "port_channel": _NAME}],
}
_DEVICE: dict[str, _Schema] = {
    "id": ID,
    "outcome": LEAF,
    "partial_reason": LEAF,
    "hostname": LEAF,
    "platform": LEAF,
    "model": LEAF,
    "software_version": LEAF,
    "serials": [LEAF],
    "stack_members": [{"number": LEAF, "serial": LEAF, "model": LEAF}],
    "management_ip": LEAF,
    "alias_ips": [LEAF],
    "interfaces": [_INTERFACE],
    "vlan_database": LEAF,
    "vpc": _VPC,
}
_UNVISITED: dict[str, _Schema] = {
    "id": ID,
    "reason": LEAF,
    "label": LEAF,
    "advertised_platform": LEAF,
    "advertised_ips": [LEAF],
    "advertised_ipv6": [LEAF],
    "chassis_id": LEAF,
    "reported_by": [{"device": ID, "interface": _NAME, "evidence": _EVIDENCE}],
}
_LINK: dict[str, _Schema] = {
    "id": ID,
    "ends": [_PORT],
    "status": LEAF,
    "evidence": [_EVIDENCE],
    "role": LEAF,
    "bundle": LEAF,
    "conflicts": [LEAF],
}
_SEGMENT: dict[str, _Schema] = {"id": ID, "ports": [_PORT], "evidence": [_EVIDENCE]}
_BUNDLE: dict[str, _Schema] = {
    "id": ID,
    "sides": [{"ends": [{"device": ID, "port_channel": LEAF}], "vpc": LEAF}],
    "links": [ID],
    "role": LEAF,
    "flagged": [ID],
}
_CHECK: dict[str, _Schema] = {"id": LEAF, "name": LEAF, "type": LEAF, "soft": LEAF}
_ADVISORY_DETAIL: dict[str, _Schema] = {
    "id": LEAF,
    "title": LEAF,
    "sir": LEAF,
    "cvss": LEAF,
    "cves": [LEAF],
    "published": LEAF,
    "updated": LEAF,
    "first_fixed": LEAF,
    "hardware_family_not_confirmed": LEAF,
}
_EOX_ITEM: dict[str, _Schema] = {
    "name": LEAF,
    "last_date_of_support": LEAF,
    "end_of_security_support": LEAF,
    "end_of_sw_maintenance": LEAF,
    "end_of_sale": LEAF,
    "replacement": LEAF,
}
_CISCO_DETAIL: dict[str, _Schema] = {
    **_ADVISORY_DETAIL,
    "items": [_EOX_ITEM],
}
_FINDING: dict[str, _Schema] = {
    "id": ID,
    "kind": LEAF,
    "summary": LEAF,
    "devices": [ID],
    "items": [ID],
    "evidence": [_EVIDENCE],
    "level": LEAF,
    "check": _CHECK,
    "what_was_found": LEAF,
    "what_to_do": LEAF,
    "source": LEAF,
    "cisco_detail": _CISCO_DETAIL,
    "also_flagged_by_cisco": LEAF,
}
_ADJACENCY: dict[str, _Schema] = {
    "id": ID,
    "ends": [{"device": ID, "interfaces": [_NAME]}],
    "vrf": LEAF,
    "kind": LEAF,
    "prefix": LEAF,
    "evidence": [_EVIDENCE],
    "conflicts": [LEAF],
}
_SUBNET: dict[str, _Schema] = {
    "id": ID,
    "vrf": LEAF,
    "prefix": LEAF,
    "attachments": [{"device": ID, "interface": _NAME, "address": LEAF}],
    "evidence": [_EVIDENCE],
    "conflicts": [LEAF],
}
_SKIPPED: dict[str, _Schema] = {"device": ID, "data": LEAF, "reason": LEAF}
_TOP: dict[str, _Schema] = {
    "devices": [_DEVICE],
    "unvisited": [_UNVISITED],
    "links": [_LINK],
    "segments": [_SEGMENT],
    "bundles": [_BUNDLE],
    "findings": [_FINDING],
    "adjacencies": [_ADJACENCY],
    "subnets": [_SUBNET],
    "skipped": [_SKIPPED],
}


def read_topology(text: str) -> TopologyFile:
    """Read `topology.json`'s text for drawing.

    Raises:
        NewerFormatError: a newer version of the tool wrote it.
        TopologyFileError: it is not a `topology.json` this tool can draw.
    """
    try:
        data: object = json.loads(text, parse_constant=_refuse_constant)
    except ValueError as error:  # JSONDecodeError, or NaN/Infinity
        msg = "topology.json is not valid JSON"
        raise TopologyFileError(msg) from error
    if not isinstance(data, dict):
        msg = "topology.json does not hold an object"
        raise TopologyFileError(msg)
    version = data.get("format_version")
    if type(version) is not int or version < 1:
        msg = "topology.json has no valid format version"
        raise TopologyFileError(msg)
    if version > KNOWN_FORMAT_VERSION:
        msg = "topology.json was written by a newer version of Network Analyser"
        raise NewerFormatError(msg)
    content = _record(data, _TOP)
    return TopologyFile(format_version=version, content=content)


def _refuse_constant(_name: str) -> object:
    msg = "not a JSON number"
    raise ValueError(msg)


def _read(value: object, schema: _Schema) -> Plain:
    if isinstance(schema, _Id):
        if isinstance(value, str) and _ID.fullmatch(value):
            return value
        msg = "topology.json holds an id that is not a plain id"
        raise TopologyFileError(msg)
    if value is None or _is_unknown(value):
        return _leaf(value)
    if isinstance(schema, _Leaf):
        return _leaf(value)
    if isinstance(schema, list):
        if not isinstance(value, list):
            msg = "topology.json holds a value where a list belongs"
            raise TopologyFileError(msg)
        return tuple(_read(item, schema[0]) for item in value)
    if not isinstance(value, dict):
        msg = "topology.json holds a value where a record belongs"
        raise TopologyFileError(msg)
    return _record(value, schema)


def _record(value: dict[object, object], schema: dict[str, _Schema]) -> Mapping[str, Plain]:
    read: dict[str, Plain] = {}
    for key, part in schema.items():
        if key in value:
            read[key] = _read(value[key], part)
        elif isinstance(part, _Id):
            msg = "topology.json holds a record with no id"
            raise TopologyFileError(msg)
        else:
            read[key] = MappingProxyType({"unknown": NOT_RECORDED})
    return MappingProxyType(read)


def _is_unknown(value: object) -> bool:
    return (
        isinstance(value, dict) and set(value) == {"unknown"} and isinstance(value["unknown"], str)
    )


def _leaf(value: object) -> Plain:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if _is_unknown(value):
        assert isinstance(value, dict)  # noqa: S101 (checked by _is_unknown)
        return MappingProxyType({"unknown": str(value["unknown"])})
    if isinstance(value, list):
        return tuple(_leaf(item) for item in value)
    msg = "topology.json holds a record where a plain value belongs"
    raise TopologyFileError(msg)
