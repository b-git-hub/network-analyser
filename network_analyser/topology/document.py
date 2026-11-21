"""`to_document(topology)`: the Topology as plain JSON data, the content of `topology.json`.

The rules (docs/topology-json.md):

- each record is an object with its field names as keys;
- an unknown value is `{"unknown": "<reason>"}`, never null, empty or left out (story 126);
- an enum is its value (`"IOS/IOS-XE"`, `"confirmed"`), an address its text
  (`"192.0.2.1"`, `"192.0.2.1/24"`), a tuple a list;
- a set of VLAN numbers is a list of `[first, last]` ranges, lowest first;
- the top level carries `format_version`, a single integer. It is bumped only when an older
  `render` would misread the file; an optional field is added without a bump.
"""

import dataclasses
from enum import Enum
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, IPv6Address
from typing import Final

from network_analyser.records.topology import DeviceAdvice, Topology
from network_analyser.records.unknown import Unknown

FORMAT_VERSION: Final = 3

type Json = str | int | bool | list[Json] | dict[str, Json] | None


def to_document(topology: Topology) -> dict[str, Json]:
    """Return `topology` as plain JSON data, `format_version` first."""
    body = _plain(topology)
    assert isinstance(body, dict)  # noqa: S101 (a record is always an object)
    _add_device_advice(body, () if topology.analysis is None else topology.analysis.advice)
    return {"format_version": FORMAT_VERSION, **body}


def _add_device_advice(body: dict[str, Json], advice: tuple[DeviceAdvice, ...]) -> None:
    """Give each Visited Device its own advice record (#124), beside the `analysis` list.

    The pages read a device's advice where it sits on the device, so the per-device record
    carries the outcome as text, the Upgrade Target, both Latest Releases with their lifecycle
    codes (#127), its Train and how many Advisories the target leaves open. The full
    `analysis.advice[]` record stays as it was.
    """
    devices = body.get("devices")
    if not isinstance(devices, list):
        return
    by_device = {record.device: record for record in advice}
    for device in devices:
        if not isinstance(device, dict):
            continue
        ident = device.get("id")
        if not isinstance(ident, str):
            continue
        record = by_device.get(ident)
        if record is not None:
            device["advice"] = _device_advice(record)


def _device_advice(advice: DeviceAdvice) -> dict[str, Json]:
    """One device's advice as the pages read it (#105, #107, #109, #124)."""
    return {
        "outcome": advice.advisory_outcome.text,
        "upgrade_target": advice.upgrade_target,
        "latest_release": advice.latest_release,
        "latest_in_train": advice.latest_release_in_train,
        "latest_release_lifecycle": advice.latest_release_lifecycle,
        "latest_in_train_lifecycle": advice.latest_in_train_lifecycle,
        "train": advice.train,
        "not_cleared": advice.not_cleared,
    }


def _plain(value: object) -> Json:  # noqa: PLR0911 (one return per kind of value)
    if isinstance(value, Unknown):
        return {"unknown": value.reason}
    if isinstance(value, Enum):
        return _plain(value.value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _plain(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, IPv4Address | IPv6Address | IPv4Interface | IPv4Network):
        return str(value)
    if isinstance(value, frozenset):
        return _ranges(value)
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if value is None or isinstance(value, str | int | bool):
        return value
    msg = f"no JSON form for {type(value).__name__}"
    raise TypeError(msg)


def _ranges(numbers: frozenset[object]) -> Json:
    """Return a set of VLAN numbers as `[first, last]` ranges, lowest first."""
    ordered = sorted(n for n in numbers if isinstance(n, int))
    ranges: list[Json] = []
    for number in ordered:
        last = ranges[-1] if ranges else None
        if isinstance(last, list) and last[1] == number - 1:
            last[1] = number
        else:
            ranges.append([number, number])
    return ranges
