"""`place(topology)`: where each device sits on the Map (#63, stories 143, 144, 149; #13).

The Topology has no role field, so the rows are worked out from the Links:

1. The most central Visited Device (the smallest total hop count to every other device) and
   its vPC peer form the top row.
2. Every other Visited Device and Shared Segment sits in the row for its hop distance from
   them; a row wraps at 24 devices. Within a row, devices sit under the devices they link to.
3. Devices with no path to the top row sit in one more tier below the rest.
4. Unvisited Devices sit in their own area below, grouped by reason.

The positions depend only on what the file holds, never on the order it lists things, so
every view (and `diagram.drawio`) reuses them and a device stays where it was (story 144).
The vPC peer-keepalive is left out of the hop count: it is a management path, not the data
path.
"""

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from network_analyser.diagram.topology_file import Plain, TopologyFile

ROW_LIMIT: Final = 24
STEP_X: Final = 150.0
STEP_Y: Final = 150.0
TIER_GAP: Final = 24.0
UNVISITED_ROWS: Final = 6
UNVISITED_STEP_Y: Final = 54.0
PEER_LINK: Final = "vPC peer-link"
PEER_KEEPALIVE: Final = "vPC peer-keepalive"
NO_REASON: Final = "reason not recorded"
UNVISITED_HEADING: Final = (
    "Unvisited Devices (not logged into), grouped by reason. "
    "Select a device to see its lines to them."
)
_UNREACHED_COST: Final = 99


@dataclass(frozen=True, slots=True)
class Point:
    """A device's centre on the drawing."""

    x: float
    y: float


@dataclass(frozen=True, slots=True)
class AreaLabel:
    """A label in the Unvisited area: the heading, or one reason with its device count.

    Attributes:
        text: the label; a reason is fixed text from the file.
        x, y: where it starts.
        heading: True for the area's heading.
    """

    text: str
    x: float
    y: float
    heading: bool


@dataclass(frozen=True, slots=True)
class Layout:
    """Every device's place, by id, and the Unvisited area's labels."""

    positions: Mapping[str, Point]
    labels: tuple[AreaLabel, ...]


def place(topology: TopologyFile) -> Layout:
    """Return where each Visited, Unvisited Device and Shared Segment sits."""
    content = topology.content
    names = {d: _name(d, r) for d, r in _records(content, "devices")}
    for segment, _ in _records(content, "segments"):
        names[segment] = segment
    graph = _graph(content, set(names))
    roots = _roots(graph, sorted(_ids(content, "devices")), content)
    positions: dict[str, Point] = {}
    bottom = _place_tiers(graph, roots, names, positions)
    labels = _place_unvisited(content, positions, bottom)
    return Layout(positions=MappingProxyType(positions), labels=labels)


def _records(content: Mapping[str, Plain], key: str) -> Iterable[tuple[str, Mapping[str, Plain]]]:
    items = content.get(key)
    if not isinstance(items, tuple):
        return ()
    return [(r["id"], r) for r in items if isinstance(r, Mapping) and isinstance(r["id"], str)]


def _ids(content: Mapping[str, Plain], key: str) -> list[str]:
    return [ident for ident, _ in _records(content, key)]


def _name(ident: str, record: Mapping[str, Plain]) -> str:
    hostname = record.get("hostname")
    return hostname if isinstance(hostname, str) else ident


def _devices_of(record: Mapping[str, Plain], key: str) -> list[str]:
    parts = record.get(key)
    if not isinstance(parts, tuple):
        return []
    return [
        p["device"] for p in parts if isinstance(p, Mapping) and isinstance(p["device"], str)
    ]


def _graph(content: Mapping[str, Plain], nodes: set[str]) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {node: set() for node in nodes}

    def join(a: str, b: str) -> None:
        if a in graph and b in graph and a != b:
            graph[a].add(b)
            graph[b].add(a)

    for _, record in _records(content, "links"):
        ends = _devices_of(record, "ends")
        if len(ends) == 2 and record.get("role") != PEER_KEEPALIVE:  # noqa: PLR2004 (two ends)
            join(ends[0], ends[1])
    for segment, record in _records(content, "segments"):
        for device in _devices_of(record, "ports"):
            join(segment, device)
    return graph


def _hops(graph: Mapping[str, set[str]], sources: Iterable[str]) -> dict[str, int]:
    hops = dict.fromkeys(sources, 0)
    queue = deque(hops)
    while queue:
        node = queue.popleft()
        for neighbour in sorted(graph[node]):
            if neighbour not in hops:
                hops[neighbour] = hops[node] + 1
                queue.append(neighbour)
    return hops


def _roots(graph: Mapping[str, set[str]], visited: list[str], content: Mapping[str, Plain]) -> list[str]:
    best: str | None = None
    best_cost = 0
    for device in visited:
        hops = _hops(graph, [device])
        cost = sum(hops.values()) + (len(graph) - len(hops)) * _UNREACHED_COST
        if best is None or cost < best_cost:
            best, best_cost = device, cost
    if best is None:
        return []
    roots = {best}
    for _, record in _records(content, "links"):
        ends = _devices_of(record, "ends")
        if record.get("role") == PEER_LINK and best in ends:
            roots.update(e for e in ends if e in graph)
    for _, record in _records(content, "bundles"):
        sides = record.get("sides")
        if record.get("role") != PEER_LINK or not isinstance(sides, tuple):
            continue
        members = [d for side in sides if isinstance(side, Mapping) for d in _devices_of(side, "ends")]
        if best in members:
            roots.update(m for m in members if m in graph)
    return sorted(roots)


def _place_tiers(
    graph: Mapping[str, set[str]],
    roots: list[str],
    names: Mapping[str, str],
    positions: dict[str, Point],
) -> float:
    """Place the tiers from the top; return the y just below the last row."""
    hops = _hops(graph, roots)
    beyond = max(hops.values(), default=-1) + 1
    tiers: dict[int, list[str]] = {}
    for node in graph:
        tiers.setdefault(hops.get(node, beyond), []).append(node)
    y = 0.0
    for depth in sorted(tiers):

        def pull(node: str) -> float:
            above = [positions[n].x for n in graph[node] if n in positions]
            return sum(above) / len(above) if above else float("inf")

        tier = sorted(tiers[depth], key=lambda n: (names[n], n))
        if depth > 0:
            tier.sort(key=pull)  # stable: equal pulls keep name order
        for start in range(0, len(tier), ROW_LIMIT):
            row = tier[start : start + ROW_LIMIT]
            middle = (len(row) - 1) / 2
            for index, node in enumerate(row):
                positions[node] = Point((index - middle) * STEP_X, y)
            y += STEP_Y
        y += TIER_GAP
    return y


def _place_unvisited(
    content: Mapping[str, Plain], positions: dict[str, Point], top: float
) -> tuple[AreaLabel, ...]:
    groups: dict[str, list[tuple[str, str]]] = {}
    for ident, record in _records(content, "unvisited"):
        reason = record.get("reason")
        label = record.get("label")
        shown = label if isinstance(label, str) else ident
        groups.setdefault(reason if isinstance(reason, str) else NO_REASON, []).append(
            (shown, ident)
        )
    if not groups:
        return ()
    min_x = min((p.x for p in positions.values()), default=0.0)
    left = min_x - 60
    right = max(-min_x, 700.0) + 60
    y = top + 30
    labels = [AreaLabel(UNVISITED_HEADING, left, y, heading=True)]
    y += 40
    x, band = left, 0.0
    for reason in sorted(groups):
        members = sorted(groups[reason])
        text = f"{reason} ({len(members)})"
        columns = -(-len(members) // UNVISITED_ROWS)
        width = max(columns * STEP_X, len(text) * 6.4 + 16)
        if x > left and x + width > right:
            x, y, band = left, y + band + 34, 0.0
        labels.append(AreaLabel(text, x, y, heading=False))
        for index, (_, ident) in enumerate(members):
            positions[ident] = Point(
                x + 64 + (index // UNVISITED_ROWS) * STEP_X,
                y + 36 + (index % UNVISITED_ROWS) * UNVISITED_STEP_Y,
            )
        band = max(band, 22 + min(len(members), UNVISITED_ROWS) * UNVISITED_STEP_Y)
        x += width + 36
    return tuple(labels)
