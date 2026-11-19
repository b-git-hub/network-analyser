"""IOS/IOS-XE CDP and LLDP neighbour detail, read into `records.collected.Neighbour` (#59).

Read here, not by ntc-templates: those templates keep only one address per Neighbour, and the
Topology needs the management address first, then every other one (#50, story 65), plus the
native VLAN CDP advertises (story 135). Device text is untrusted (#28, #30): names and
descriptions are made printable and capped, an address that does not parse is dropped, and a
value the Neighbour did not advertise is `Unknown`, never guessed.
"""

import re
from collections.abc import Iterator
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Final

from network_analyser.platforms import fields
from network_analyser.records.collected import Neighbour
from network_analyser.records.interface_names import InterfaceName, interface_name
from network_analyser.records.unknown import Unknown

PARSER: Final = "Network Analyser IOS/IOS-XE neighbour reader"
NOT_ADVERTISED: Final = "not advertised"

_CDP_START: Final = re.compile(r"^Device ID:", re.MULTILINE)
_CDP_DEVICE_ID: Final = re.compile(r"^Device ID:\s*(.*)$", re.MULTILINE)
_CDP_PLATFORM: Final = re.compile(r"^Platform\s*:\s*(.*?)\s*,\s*Capabilities\s*:", re.MULTILINE)
_CDP_PORTS: Final = re.compile(
    r"^Interface\s*:\s*(.*?)\s*,\s*Port ID \(outgoing port\)\s*:\s*(.*?)\s*$", re.MULTILINE
)
_CDP_NATIVE_VLAN: Final = re.compile(r"^Native VLAN\s*:\s*(\d+)\s*$", re.MULTILINE)
_CDP_ENTRY_HEADER: Final = re.compile(r"^(?:Entry|Interface) address\(es\)\s*:", re.IGNORECASE)
_CDP_MGMT_HEADER: Final = re.compile(r"^(?:Management|Mgmt) address\(es\)\s*:", re.IGNORECASE)
_CDP_ADDRESS: Final = re.compile(r"^\s+IP(?:v6)? address\s*:\s*(\S+)", re.IGNORECASE)
_CDP_TOTAL: Final = re.compile(r"^Total cdp entries displayed\s*:\s*\d+", re.MULTILINE)

_LLDP_START: Final = re.compile(r"^Local Intf:", re.MULTILINE)
_LLDP_LOCAL: Final = re.compile(r"^Local Intf:\s*(\S+)", re.MULTILINE)
_LLDP_CHASSIS: Final = re.compile(r"^Chassis id:\s*(.*?)\s*$", re.MULTILINE)
_LLDP_PORT: Final = re.compile(r"^Port id:\s*(.*?)\s*$", re.MULTILINE)
_LLDP_NAME: Final = re.compile(r"^System Name:\s*(.*?)\s*$", re.MULTILINE)
_LLDP_DESCRIPTION: Final = re.compile(r"^System Description:[ \t]*\n?[ \t]*(\S.*)$", re.MULTILINE)
_LLDP_MGMT_HEADER: Final = re.compile(r"^Management Addresses\s*:\s*$", re.IGNORECASE)
_LLDP_ADDRESS: Final = re.compile(r"^\s+IP(?:V6)?\s*:\s*(\S+)", re.IGNORECASE)
_LLDP_TOTAL: Final = re.compile(r"^Total entries displayed\s*:\s*\d+", re.MULTILINE)

type Address = IPv4Address | IPv6Address


def cdp(text: str) -> tuple[Neighbour, ...] | None:
    """Read `show cdp neighbors detail`; None when it is not understood."""
    blocks = list(_blocks(_CDP_START, text))
    if not blocks and not _empty_table(text, _CDP_TOTAL):
        return None
    found: list[Neighbour] = []
    for block in blocks:
        ports = _CDP_PORTS.search(block)
        if ports is None:
            return None
        management = _addresses(block, _CDP_MGMT_HEADER, _CDP_ADDRESS)
        entry = _addresses(block, _CDP_ENTRY_HEADER, _CDP_ADDRESS)
        every = tuple(dict.fromkeys((*management, *entry)))
        platform = _CDP_PLATFORM.search(block)
        native = _CDP_NATIVE_VLAN.search(block)
        found.append(
            Neighbour(
                local_port=interface_name(fields.label(ports.group(1))),
                name=_advertised(_one(_CDP_DEVICE_ID, block)),
                remote_port=_remote_port(ports.group(2)),
                addresses=tuple(a for a in every if isinstance(a, IPv4Address)),
                platform=_advertised(platform.group(1) if platform else None),
                ipv6_addresses=tuple(a for a in every if isinstance(a, IPv6Address)),
                native_vlan=fields.number(native.group(1)) if native else None,
            )
        )
    return tuple(found)


def lldp(text: str) -> tuple[Neighbour, ...] | None:
    """Read `show lldp neighbors detail`; None when it is not understood."""
    blocks = list(_blocks(_LLDP_START, text))
    if not blocks and not _empty_table(text, _LLDP_TOTAL):
        return None
    found: list[Neighbour] = []
    for block in blocks:
        local = _one(_LLDP_LOCAL, block)
        if local is None:
            return None
        management = _addresses(block, _LLDP_MGMT_HEADER, _LLDP_ADDRESS)
        chassis = _one(_LLDP_CHASSIS, block)
        found.append(
            Neighbour(
                local_port=interface_name(fields.label(local)),
                name=_advertised(_one(_LLDP_NAME, block)),
                remote_port=_remote_port(_one(_LLDP_PORT, block)),
                addresses=tuple(a for a in management if isinstance(a, IPv4Address)),
                platform=_advertised(_one(_LLDP_DESCRIPTION, block)),
                ipv6_addresses=tuple(a for a in management if isinstance(a, IPv6Address)),
                chassis_id=_chassis(chassis),
            )
        )
    return tuple(found)


def _empty_table(text: str, total: re.Pattern[str]) -> bool:
    """A reply with no entries: blank, or only the closing total line."""
    return not text.strip() or total.search(text) is not None


def _blocks(start: re.Pattern[str], text: str) -> Iterator[str]:
    """Yield each entry of a detail table: from one start line to the next."""
    starts = [m.start() for m in start.finditer(text)]
    for begin, end in zip(starts, [*starts[1:], len(text)], strict=False):
        yield text[begin:end]


def _one(pattern: re.Pattern[str], block: str) -> str | None:
    match = pattern.search(block)
    return match.group(1) if match else None


def _advertised(value: str | None) -> str | Unknown:
    text = fields.label(value) if value is not None else ""
    if not text or NOT_ADVERTISED in text.lower():
        return Unknown(NOT_ADVERTISED)
    return text


def _chassis(value: str | None) -> str | None:
    text = _advertised(value)
    return None if isinstance(text, Unknown) else text


def _remote_port(port_id: str | None) -> InterfaceName | Unknown:
    """The Neighbour's port, as its port ID names it.

    An LLDP port ID that is not a port name (a server's MAC address) is kept exactly as
    sent, so it is matched only exactly and listed in the report (story 127). The free-text
    port description is never read as a port name: `eth0` would pass for `Eth0`.
    """
    port = _advertised(port_id)
    return port if isinstance(port, Unknown) else interface_name(port)


def _addresses(block: str, header: re.Pattern[str], address: re.Pattern[str]) -> list[Address]:
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
            try:
                found.append(ip_address(match.group(1)))
            except ValueError:
                continue  # not an address: dropped, never guessed at
        elif line.strip() and not line[0].isspace():
            inside = False
    return list(dict.fromkeys(found))
