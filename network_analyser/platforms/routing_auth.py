"""Routing-protocol authentication, read from a running config at capture time (#101, #142).

`routing_authentication_missing(lines)` names the protocols (`OSPF`, `EIGRP`, `BGP`) that are
configured with no authentication, as fixed keywords. No key, key-chain, neighbour address,
interface name or config line is kept.

OSPF and EIGRP authenticate per interface (or per area, or per EIGRP `af-interface`), so each is
judged on the interfaces that run it: it is missing authentication when any of them has none.
An interface runs the protocol when it is not shut down, not a loopback, not passive, and it is
named by the protocol's own interface command or matched by a `network` statement. When no
interface can be placed, the protocol falls back to "any authentication line anywhere", which is
what the config shows without an address map. BGP authenticates a neighbour or a template, so
a `password` line anywhere under `router bgp` counts.
"""

import re
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Interface
from typing import Final

type _Block = tuple[str, list[tuple[int, str]]]

_ROUTER: Final = re.compile(r"^router\s+(ospf|eigrp|bgp)(?:\s|$)", re.IGNORECASE)
_OSPF_NETWORK: Final = re.compile(r"^network\s+(\S+)\s+(\S+)\s+area\s+(\S+)", re.IGNORECASE)
_EIGRP_NETWORK: Final = re.compile(r"^network\s+(\S+)(?:\s+(\S+))?\s*$", re.IGNORECASE)
_IP_ADDRESS: Final = re.compile(r"^ip\s+address\s+(\S+)(?:\s+(\S+))?", re.IGNORECASE)
_OSPF_INTERFACE_AREA: Final = re.compile(
    r"^ip\s+(?:router\s+)?ospf\s+\S+\s+area\s+(\S+)", re.IGNORECASE
)
_CLASS_A_MAX: Final = 127
_CLASS_B_MAX: Final = 191


@dataclass(slots=True)
class _Interface:
    """What one interface block says about addressing and routing authentication."""

    name: str
    shutdown: bool = False
    addresses: list[IPv4Address] = field(default_factory=list)
    ospf_area: int | None = None
    ospf_authenticated: bool = False
    ospf_passive: bool = False
    eigrp_explicit: bool = False
    eigrp_authenticated: bool = False

    @property
    def loopback(self) -> bool:
        return self.name.startswith("loopback")


@dataclass(slots=True)
class _Process:
    """What the `router ospf` or `router eigrp` blocks say, merged."""

    networks: list[tuple[int, int, int | None]] = field(default_factory=list)
    authenticated_areas: set[int] = field(default_factory=set)
    authenticated_interfaces: set[str] = field(default_factory=set)
    passive: set[str] = field(default_factory=set)
    not_passive: set[str] = field(default_factory=set)
    passive_default: bool = False
    all_interfaces_authenticated: bool = False

    def is_passive(self, name: str) -> bool:
        return name in self.passive or (self.passive_default and name not in self.not_passive)

    def area_of(self, interface: _Interface) -> int | None:
        """The OSPF area that a `network` statement gives `interface`, else its own."""
        if interface.ospf_area is not None:
            return interface.ospf_area
        return next(
            (
                area
                for network, wildcard, area in self.networks
                if _matches(interface, network, wildcard)
            ),
            None,
        )

    def places(self, interface: _Interface) -> bool:
        """Whether a `network` statement covers one of the interface's addresses."""
        return any(_matches(interface, network, wildcard) for network, wildcard, _ in self.networks)


def routing_authentication_missing(lines: list[str]) -> tuple[str, ...]:
    """The routing protocols that are configured with no authentication, sorted."""
    blocks = _top_level_blocks(lines)
    configured = {
        match.group(1).upper()
        for header, _ in blocks
        if (match := _ROUTER.match(header)) is not None
    }
    interfaces = _interfaces(blocks)
    missing: list[str] = []
    if "OSPF" in configured and _ospf_missing(interfaces, _read_ospf(_bodies(blocks, "ospf"))):
        missing.append("OSPF")
    if "EIGRP" in configured and _eigrp_missing(interfaces, _read_eigrp(_bodies(blocks, "eigrp"))):
        missing.append("EIGRP")
    if "BGP" in configured and not _bgp_authenticated(_bodies(blocks, "bgp")):
        missing.append("BGP")
    return tuple(sorted(missing))


# -- Reading the config into blocks ------------------------------------------------------------


def _top_level_blocks(lines: list[str]) -> list[_Block]:
    """Every top-level command with its indented lines, as (header, [(indent, text)])."""
    blocks: list[_Block] = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        if not raw[:1].isspace():
            blocks.append((raw.strip(), []))
        elif blocks:
            blocks[-1][1].append((len(raw) - len(raw.lstrip()), raw.strip()))
    return blocks


def _bodies(blocks: list[_Block], protocol: str) -> list[tuple[int, str]]:
    """The indented lines of every `router <protocol>` block, joined in config order."""
    found: list[tuple[int, str]] = []
    for header, body in blocks:
        match = _ROUTER.match(header)
        if match is not None and match.group(1).lower() == protocol:
            found.extend(body)
    return found


def _interfaces(blocks: list[_Block]) -> list[_Interface]:
    return [
        _read_interface(header.split(None, 1)[1].lower(), body)
        for header, body in blocks
        if header.lower().startswith("interface ") and len(header.split(None, 1)) == 2  # noqa: PLR2004 (a name follows)
    ]


def _read_interface(name: str, body: list[tuple[int, str]]) -> _Interface:
    interface = _Interface(name)
    for _, text in body:
        tokens = text.lower().split()
        if tokens == ["shutdown"]:
            interface.shutdown = True
        _read_interface_address(interface, text)
        _read_interface_ospf(interface, text, tokens)
        if tokens[:3] == ["ip", "router", "eigrp"]:
            interface.eigrp_explicit = True
        if tokens[:2] == ["ip", "authentication"] and tokens[2:3] in (["mode"], ["key-chain"]):
            interface.eigrp_authenticated = True
    return interface


def _read_interface_address(interface: _Interface, text: str) -> None:
    match = _IP_ADDRESS.match(text)
    address = None if match is None else _address(match.group(1), match.group(2))
    if address is not None:
        interface.addresses.append(address)


def _read_interface_ospf(interface: _Interface, text: str, tokens: list[str]) -> None:
    area = _OSPF_INTERFACE_AREA.match(text)
    if area is not None:
        interface.ospf_area = _area(area.group(1))
    if tokens[:3] == ["ip", "ospf", "authentication"] and tokens[3:4] != ["null"]:
        interface.ospf_authenticated = True
    if tokens[:3] == ["ip", "ospf", "passive-interface"]:
        interface.ospf_passive = True


def _address(first: str, second: str | None) -> IPv4Address | None:
    """An interface's IPv4 address from `A.B.C.D M.M.M.M` or `A.B.C.D/L`, else None."""
    try:
        if "/" in first:
            return IPv4Interface(first).ip
        return None if second is None else IPv4Interface(f"{first}/{second}").ip
    except ValueError:
        return None


def _area(text: str) -> int | None:
    """An OSPF area id, written as a number or as a dotted quad."""
    try:
        return int(IPv4Address(text)) if "." in text else int(text)
    except ValueError:
        return None


def _matches(interface: _Interface, network: int, wildcard: int) -> bool:
    """Whether a `network` statement (address and wildcard bits) covers an interface address."""
    return any(int(address) | wildcard == network | wildcard for address in interface.addresses)


def _network(text: str, wildcard: str | None) -> tuple[int, int] | None:
    """A `network` statement's address and wildcard; no wildcard means the classful network."""
    try:
        address = IPv4Address(text)
        if wildcard is not None:
            return int(address), int(IPv4Address(wildcard))
    except ValueError:
        return None
    first = address.packed[0]
    host_bits = 24 if first <= _CLASS_A_MAX else 16 if first <= _CLASS_B_MAX else 8
    return int(address), (1 << host_bits) - 1


# -- OSPF --------------------------------------------------------------------------------------


def _read_ospf(body: list[tuple[int, str]]) -> _Process:
    process = _Process()
    for _, text in body:
        tokens = text.lower().split()
        network = _OSPF_NETWORK.match(text)
        if network is not None:
            read = _network(network.group(1), network.group(2))
            if read is not None:
                process.networks.append((*read, _area(network.group(3))))
        elif (
            tokens[:1] == ["area"]
            and tokens[2:3] == ["authentication"]
            and (tokens[3:4] != ["null"])
        ):
            area = _area(tokens[1])
            if area is not None:
                process.authenticated_areas.add(area)
        _read_passive(process, tokens)
    return process


def _read_passive(process: _Process, tokens: list[str]) -> None:
    """Note a `passive-interface` or `no passive-interface` line of a router block."""
    negated = tokens[:1] == ["no"]
    words = tokens[1:] if negated else tokens
    if words[:1] != ["passive-interface"] or len(words) < 2:  # noqa: PLR2004 (a name follows)
        return
    if words[1] == "default":
        process.passive_default = not negated
    elif negated:
        process.not_passive.add(words[1])
    else:
        process.passive.add(words[1])


def _ospf_missing(interfaces: list[_Interface], process: _Process) -> bool:
    running = [
        (interface, process.area_of(interface))
        for interface in interfaces
        if _runs(interface, process, passive=interface.ospf_passive)
        and process.area_of(interface) is not None
    ]
    if not running:
        return not (
            process.authenticated_areas
            or any(interface.ospf_authenticated for interface in interfaces)
        )
    return any(
        not (interface.ospf_authenticated or area in process.authenticated_areas)
        for interface, area in running
    )


def _runs(interface: _Interface, process: _Process, *, passive: bool) -> bool:
    """Whether an interface can form adjacencies: up, not a loopback, not passive."""
    return not (
        interface.shutdown or interface.loopback or passive or process.is_passive(interface.name)
    )


# -- EIGRP -------------------------------------------------------------------------------------


def _read_eigrp(body: list[tuple[int, str]]) -> _Process:
    process = _Process()
    scope: str | None = None
    scope_indent = -1
    for indent, text in body:
        tokens = text.lower().split()
        if scope is not None and indent <= scope_indent:
            scope = None
        if tokens[:1] == ["af-interface"] and len(tokens) > 1:
            scope, scope_indent = tokens[1], indent
            continue
        _read_eigrp_line(process, text, tokens, scope)
    return process


def _read_eigrp_line(process: _Process, text: str, tokens: list[str], scope: str | None) -> None:
    network = _EIGRP_NETWORK.match(text)
    if network is not None:
        read = _network(network.group(1), network.group(2))
        if read is not None:
            process.networks.append((*read, None))
    elif tokens[:1] == ["authentication"] and tokens[1:2] in (["mode"], ["key-chain"]):
        if scope is None or scope == "default":
            process.all_interfaces_authenticated = True
        else:
            process.authenticated_interfaces.add(scope)
    elif scope is not None and tokens == ["passive-interface"]:
        if scope == "default":
            process.passive_default = True
        else:
            process.passive.add(scope)
    else:
        _read_passive(process, tokens)


def _eigrp_missing(interfaces: list[_Interface], process: _Process) -> bool:
    running = [
        interface
        for interface in interfaces
        if _runs(interface, process, passive=False)
        and (interface.eigrp_explicit or process.places(interface))
    ]
    if not running:
        return not (
            process.all_interfaces_authenticated
            or process.authenticated_interfaces
            or any(interface.eigrp_authenticated for interface in interfaces)
        )
    return any(
        not (
            interface.eigrp_authenticated
            or process.all_interfaces_authenticated
            or interface.name in process.authenticated_interfaces
        )
        for interface in running
    )


# -- BGP ---------------------------------------------------------------------------------------


def _bgp_authenticated(body: list[tuple[int, str]]) -> bool:
    """Whether any neighbour or template under `router bgp` has a `password`."""
    for _, text in body:
        tokens = text.lower().split()
        if tokens[:1] == ["password"] or (tokens[:1] == ["neighbor"] and "password" in tokens[2:]):
            return True
    return False
