r"""`draw_drawio(topology, redact)`: the self-contained `diagram.drawio` (#65, story 154).

A draw.io (diagrams.net) file the operator opens in draw.io Desktop to rearrange, annotate
or export to Visio. It is plain, uncompressed XML with two pages:

- **Physical**: every Visited Device, Unvisited Device and Shared Segment at the position
  `place` gives `diagram.html`, with the same line styles (confirmed solid, one-sided dashed,
  inferred dotted, a Bundle one double line labelled with its port-channels and member count).
  Lines to Unvisited Devices sit on a layer that starts hidden, as the HTML shows them only
  for the device picked.
- **Routing**: the Visited Devices at the same positions, each with its interface addresses in
  its shape data. `topology.json` format version 1 holds no routing adjacency, so no routing
  lines are drawn, and a note on the page says so (decision in
  docs/wiki/spec-37-implementation-calls.md).

Device details (hostname, Platform, model, version, management IP, serial) are in each
shape's data. There is no username: the Topology holds none (story 141).

The file loads nothing and points nowhere: no `xmlns`, no `link` property, no doctype, no
entity. Device text is untrusted, and reaches the file only as the value of an XML attribute:

- every string first passes through `redact` (the Run's secret scan), so a secret is caught
  before escaping could hide it;
- control characters, format characters (such as a right-to-left override), lone surrogates
  and unassigned code points, which XML 1.0 cannot hold, are shown as `\xNN`, `\uNNNN` or
  `\UNNNNNNNN` text, so nothing is silently dropped or hidden;
- every character other than letters, digits, space and `_ . , - /` is then written as a
  numeric character reference (`&#x3c;`), and so is the second of two slashes in a row. The
  file therefore holds no `<`, `&`, quote, colon, parenthesis, `=` or `//` from a device, and
  no tag, comment, URL or style can be formed from it;
- device text is never put in a style, a cell or edge id, or a link; shapes are labelled as
  plain text (`html=0`) and never use placeholders, so draw.io shows the text and nothing more.

The file is the same for the same `topology.json` and secrets (no timestamp).
"""

import unicodedata
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from math import hypot
from typing import Final

from network_analyser.diagram.layout import Layout, Point, place
from network_analyser.diagram.topology_file import Plain, TopologyFile

PHYSICAL: Final = "Physical"
ROUTING: Final = "Routing"
NODE_WIDTH: Final = 128.0
NODE_HEIGHT: Final = 40.0
SEGMENT_SIZE: Final = 30.0
LABEL_LIFT: Final = 16.0
PARALLEL_STEP: Final = 32.0
NO_VALUE: Final = "\u2014"
NO_ROUTING_NOTE: Final = (
    "Routing page: this version of Network Analyser draws no routing lines, because "
    "topology.json format version 1 holds no routing adjacency. Each device's interface "
    "addresses are in its shape data (l3_interfaces)."
)
HIDDEN_LAYER: Final = "Links to Unvisited Devices (hidden until you show this layer)"
MAIN_LAYER: Final = "Devices and links"

_PLAIN: Final = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _.,-/")
_NEWLINE: Final = "&#xa;"
_ONE_BYTE: Final = 0x100
_ONE_UNIT: Final = 0x10000

_EDGE_BASE: Final = (
    "html=0;endArrow=none;startArrow=none;fontSize=10;fontFamily=Consolas;"
    "labelBackgroundColor=#fbfcfd;"
)
_LINE_COLOUR: Final = "strokeColor=#3b4757;"
_GREY: Final = "strokeColor=#8792a2;"
_STATUS_STYLES: Final[Mapping[str, str]] = {
    "confirmed": f"{_LINE_COLOUR}strokeWidth=1.6;dashed=0;",
    "one-sided": f"{_LINE_COLOUR}strokeWidth=1.6;dashed=1;dashPattern=7 5;",
    "inferred": f"{_LINE_COLOUR}strokeWidth=2.2;dashed=1;dashPattern=1.5 4.5;",
}
_UNKNOWN_STATUS: Final = f"{_GREY}strokeWidth=1.6;dashed=1;dashPattern=5 3;"
_KEEPALIVE: Final = "strokeColor=#5a6676;strokeWidth=1.2;dashed=1;dashPattern=1 3;"
_SEGMENT_LINE: Final = f"{_GREY}strokeWidth=1.6;dashed=1;dashPattern=3 3;"
_BUNDLE: Final = "shape=link;width=6;"
_NODE_BASE: Final = (
    "rounded=1;arcSize=15;whiteSpace=wrap;html=0;overflow=hidden;fontSize=11;"
    "fillColor=#ffffff;fontColor=#18212c;strokeWidth=1.2;"
)
_PLATFORM_COLOURS: Final[Mapping[str, str]] = {
    "NX-OS": "strokeColor=#0b6e99;",
    "IOS/IOS-XE": "strokeColor=#2c7a4b;",
}
_DEFAULT_COLOUR: Final = "strokeColor=#2d3a4a;"
_PARTIAL: Final = "dashed=1;dashPattern=6 3;"
_UNVISITED_NODE: Final = (
    "rounded=1;arcSize=15;whiteSpace=wrap;html=0;overflow=hidden;fontSize=11;"
    "fillColor=#eceff3;fontColor=#5a6676;strokeColor=#8792a2;strokeWidth=1.2;"
    "dashed=1;dashPattern=4 3;"
)
_SEGMENT_NODE: Final = (
    "ellipse;whiteSpace=wrap;html=0;fontSize=11;fillColor=#eceff3;fontColor=#5a6676;"
    "strokeColor=#8792a2;strokeWidth=1.2;dashed=1;dashPattern=3 3;"
)
_END_LABEL: Final = (
    "edgeLabel;html=0;align=center;verticalAlign=middle;resizable=0;points=[];fontSize=10;"
    "fontFamily=Consolas;labelBackgroundColor=#fbfcfd;"
)
_AREA_HEADING: Final = (
    "text;html=0;whiteSpace=nowrap;align=left;verticalAlign=top;fontStyle=1;fontSize=12;"
    "fontColor=#18212c;"
)
_AREA_REASON: Final = (
    "text;html=0;whiteSpace=nowrap;align=left;verticalAlign=top;fontStyle=1;fontSize=11;"
    "fontColor=#5a6676;"
)
_NOTE: Final = (
    "text;html=0;whiteSpace=wrap;align=left;verticalAlign=top;fontStyle=2;fontSize=11;"
    "fontColor=#5a6676;"
)

type _Data = tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class _Box:
    x: float
    y: float
    width: float
    height: float


@dataclass(frozen=True, slots=True)
class _Edge:
    """One line on the Physical page, its text already scanned."""

    seed: str
    a: str
    b: str
    label: str
    a_label: str
    b_label: str
    style: str
    data: _Data


def draw_drawio(topology: TopologyFile, redact: Callable[[str], str]) -> str:
    """Return `diagram.drawio` for `topology`, every string passed through `redact` first."""
    sheet = _Sheet(topology.content, place(topology), redact)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<mxfile host="Network Analyser" type="device" compressed="false">\n'
        f"{sheet.physical()}{sheet.routing()}</mxfile>\n"
    )


def _text(text: str) -> str:
    """Return `text` as XML attribute text: nothing but plain characters and references."""
    shown = "".join(_visible(character) for character in text)
    out: list[str] = []
    previous = ""
    for character in shown:
        slash_after_slash = character == "/" and previous == "/"
        if character in _PLAIN and not slash_after_slash:
            out.append(character)
        else:
            out.append(f"&#x{ord(character):x};")
        previous = character
    return "".join(out)


def _visible(character: str) -> str:
    """Return `character`, or its hex-escape text if XML cannot hold it or it would hide."""
    category = unicodedata.category(character)
    if category[0] != "C" and category not in {"Zl", "Zp"}:
        return character
    code = ord(character)
    if code < _ONE_BYTE:
        return f"\\x{code:02x}"
    if code < _ONE_UNIT:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def _lines(*lines: str) -> str:
    return _NEWLINE.join(_text(line) for line in lines)


def _number(value: float) -> str:
    text = f"{value:.1f}".rstrip("0").rstrip(".")
    return "0" if text in {"-0", ""} else text


def _geometry(box: _Box) -> str:
    return (
        f'<mxGeometry x="{_number(box.x)}" y="{_number(box.y)}" '
        f'width="{_number(box.width)}" height="{_number(box.height)}" as="geometry"/>'
    )


def _properties(data: _Data) -> str:
    return "".join(f' {key}="{_text(value)}"' for key, value in data)


class _Ids:
    """Cell ids on one page: each used once, whatever the file holds."""

    def __init__(self) -> None:
        self._used = {"0", "1", "2"}

    def take(self, wanted: str) -> str:
        """Return `wanted`, or `wanted` with a number added if it was taken."""
        ident, number = wanted, 1
        while ident in self._used:
            number += 1
            ident = f"{wanted}-{number}"
        self._used.add(ident)
        return ident


def _vertex(ident: str, label: str, style: str, box: _Box, *, data: _Data = ()) -> str:
    if not data:
        return (
            f'<mxCell id="{ident}" value="{label}" style="{style}" vertex="1" '
            f'parent="1">{_geometry(box)}</mxCell>\n'
        )
    return (
        f'<object label="{label}" id="{ident}"{_properties(data)}>'
        f'<mxCell style="{style}" vertex="1" parent="1">{_geometry(box)}</mxCell>'
        "</object>\n"
    )


def _edge_cell(ident: str, edge: _Edge, parent: str, bend: Point | None) -> str:
    points = (
        f'<Array as="points"><mxPoint x="{_number(bend.x)}" y="{_number(bend.y)}"/></Array>'
        if bend
        else ""
    )
    style = edge.style + ("curved=1;" if bend else "")
    return (
        f'<object label="{_text(edge.label)}" id="{ident}"{_properties(edge.data)}>'
        f'<mxCell style="{style}" edge="1" parent="{parent}" source="n-{_text(edge.a)}" '
        f'target="n-{_text(edge.b)}"><mxGeometry relative="1" as="geometry">{points}'
        "</mxGeometry></mxCell></object>\n"
    )


def _end_label(ident: str, text: str, position: str, edge: str) -> str:
    return (
        f'<mxCell id="{ident}" value="{_text(text)}" style="{_END_LABEL}" vertex="1" '
        f'connectable="0" parent="{edge}"><mxGeometry x="{position}" relative="1" '
        'as="geometry"><mxPoint as="offset"/></mxGeometry></mxCell>\n'
    )


def _records(content: Mapping[str, Plain], key: str) -> list[Mapping[str, Plain]]:
    items = content.get(key)
    if not isinstance(items, tuple):
        return []
    return [r for r in items if isinstance(r, Mapping) and isinstance(r.get("id"), str)]


def _id(record: Mapping[str, Plain]) -> str:
    ident = record["id"]
    assert isinstance(ident, str)  # noqa: S101 (checked by `_records`)
    return ident


def _tuple(value: Plain) -> tuple[Plain, ...]:
    return value if isinstance(value, tuple) else ()


class _Sheet:
    """What both pages draw from: the Topology, where things sit, and the secret scan."""

    def __init__(
        self, content: Mapping[str, Plain], layout: Layout, redact: Callable[[str], str]
    ) -> None:
        self._content = content
        self._layout = layout
        self._redact = redact
        self._devices = _records(content, "devices")
        self._unvisited = _records(content, "unvisited")
        self._segments = _records(content, "segments")
        self._by_id = {
            _id(r): r for group in (self._devices, self._unvisited, self._segments) for r in group
        }
        self._segment_ids = {_id(r) for r in self._segments}
        self._unvisited_ids = {_id(r) for r in self._unvisited}
        self._bundles = {_id(r): r for r in _records(content, "bundles")}

    # ---------- text, scanned ----------

    def _scan(self, text: str) -> str:
        return self._redact(text)

    def _txt(self, value: Plain) -> str:
        if value is None:
            return NO_VALUE
        if isinstance(value, Mapping):
            reason = value.get("unknown")
            return f"unknown ({self._scan(reason)})" if isinstance(reason, str) else NO_VALUE
        if isinstance(value, tuple):
            return ", ".join(self._txt(v) for v in value) if value else "none"
        if isinstance(value, bool):
            return "yes" if value else "no"
        return self._scan(value) if isinstance(value, str) else str(value)

    def _string(self, value: Plain) -> str | None:
        return self._scan(value) if isinstance(value, str) and value else None

    def _ifn(self, name: Plain) -> str:
        if isinstance(name, Mapping):
            short = name.get("short")
            if isinstance(short, str):
                return self._scan(short)
        return "?"

    def _name(self, ident: str) -> str:
        record = self._by_id.get(ident)
        if record is None:
            return ident
        if ident in self._segment_ids:
            return "Shared Segment"
        if ident in self._unvisited_ids:
            addresses = _tuple(record.get("advertised_ips"))
            return (
                self._string(record.get("label"))
                or self._string(addresses[0] if addresses else None)
                or ident
            )
        return (
            self._string(record.get("hostname"))
            or self._string(record.get("management_ip"))
            or ident
        )

    # ---------- shape data ----------

    def _l3(self, record: Mapping[str, Plain]) -> str:
        interfaces = record.get("interfaces")
        if not isinstance(interfaces, tuple):
            return self._txt(interfaces)
        found: list[str] = []
        for interface in interfaces:
            ip = interface.get("ip") if isinstance(interface, Mapping) else None
            addresses = ip.get("addresses") if isinstance(ip, Mapping) else None
            if not isinstance(ip, Mapping) or not isinstance(addresses, tuple) or not addresses:
                continue
            assert isinstance(interface, Mapping)  # noqa: S101 (checked above)
            found.append(
                f"{self._ifn(interface.get('name'))} {self._txt(addresses)} "
                f"(VRF {self._txt(ip.get('vrf'))})"
            )
        return "; ".join(found) if found else "none"

    def _stack(self, record: Mapping[str, Plain]) -> str:
        members = _tuple(record.get("stack_members"))
        shown = [
            f"{self._txt(m.get('number'))}: {self._txt(m.get('model'))} "
            f"{self._txt(m.get('serial'))}"
            for m in members
            if isinstance(m, Mapping)
        ]
        return "; ".join(shown) if shown else "none"

    def _device_data(self, record: Mapping[str, Plain]) -> _Data:
        data: list[tuple[str, str]] = [
            ("hostname", self._txt(record.get("hostname"))),
            ("platform", self._txt(record.get("platform"))),
            ("model", self._txt(record.get("model"))),
            ("software_version", self._txt(record.get("software_version"))),
            ("management_ip", self._txt(record.get("management_ip"))),
            ("serial", self._txt(record.get("serials"))),
            ("stack_members", self._stack(record)),
            ("alias_ips", self._txt(record.get("alias_ips"))),
            ("outcome", self._txt(record.get("outcome"))),
        ]
        if record.get("outcome") == "partial":
            data.append(("partial_reason", self._txt(record.get("partial_reason"))))
        data += [("l3_interfaces", self._l3(record)), ("topology_id", _id(record))]
        return tuple(data)

    def _unvisited_data(self, record: Mapping[str, Plain]) -> _Data:
        return (
            ("reason", self._txt(record.get("reason"))),
            ("advertised_name", self._txt(record.get("label"))),
            ("advertised_platform", self._txt(record.get("advertised_platform"))),
            ("advertised_ips", self._txt(record.get("advertised_ips"))),
            ("advertised_ipv6", self._txt(record.get("advertised_ipv6"))),
            ("chassis_id", self._txt(record.get("chassis_id"))),
            ("topology_id", _id(record)),
        )

    def _segment_data(self, record: Mapping[str, Plain]) -> _Data:
        ports = [
            f"{self._name(str(p['device']))} {self._ifn(p.get('interface'))}"
            for p in _tuple(record.get("ports"))
            if isinstance(p, Mapping) and isinstance(p.get("device"), str)
        ]
        return (("ports", "; ".join(ports) if ports else "none"), ("topology_id", _id(record)))

    # ---------- shapes ----------

    def _box(self, ident: str, width: float, height: float) -> _Box:
        point = self._layout.positions[ident]
        return _Box(point.x - width / 2, point.y - height / 2, width, height)

    def _device_shape(self, ids: _Ids, record: Mapping[str, Plain]) -> str:
        ident = _id(record)
        platform = record.get("platform")
        style = _NODE_BASE + _PLATFORM_COLOURS.get(
            platform if isinstance(platform, str) else "", _DEFAULT_COLOUR
        )
        if record.get("outcome") == "partial":
            style += _PARTIAL
        model = self._string(record.get("model")) or ""
        label = _lines(self._name(ident), model) if model else _lines(self._name(ident))
        return _vertex(
            ids.take(f"n-{ident}"),
            label,
            style,
            self._box(ident, NODE_WIDTH, NODE_HEIGHT),
            data=self._device_data(record),
        )

    def _unvisited_shape(self, ids: _Ids, record: Mapping[str, Plain]) -> str:
        ident = _id(record)
        reason = self._string(record.get("reason")) or "reason not recorded"
        return _vertex(
            ids.take(f"n-{ident}"),
            _lines(self._name(ident), reason),
            _UNVISITED_NODE,
            self._box(ident, NODE_WIDTH, NODE_HEIGHT),
            data=self._unvisited_data(record),
        )

    def _segment_shape(self, ids: _Ids, record: Mapping[str, Plain]) -> str:
        ident = _id(record)
        return _vertex(
            ids.take(f"n-{ident}"),
            _lines("?"),
            _SEGMENT_NODE,
            self._box(ident, SEGMENT_SIZE, SEGMENT_SIZE),
            data=self._segment_data(record),
        )

    def _area_labels(self, ids: _Ids) -> str:
        out: list[str] = []
        for index, label in enumerate(self._layout.labels):
            box = _Box(label.x, label.y - LABEL_LIFT, 620.0 if label.heading else 260.0, 22.0)
            style = _AREA_HEADING if label.heading else _AREA_REASON
            out.append(
                _vertex(ids.take(f"area-{index}"), _lines(self._scan(label.text)), style, box)
            )
        return "".join(out)

    # ---------- lines ----------

    def _status_style(self, status: str | None) -> str:
        return _STATUS_STYLES.get(status or "", _UNKNOWN_STATUS)

    def _ends(self, record: Mapping[str, Plain]) -> list[Mapping[str, Plain]]:
        return [
            e
            for e in _tuple(record.get("ends"))
            if isinstance(e, Mapping) and isinstance(e.get("device"), str)
        ]

    def _evidence(self, items: tuple[Plain, ...]) -> str:
        shown = [
            f"{self._txt(e.get('source'))} on {self._name(str(e['device']))}: "
            f"{self._txt(e.get('command'))}"
            for e in items
            if isinstance(e, Mapping) and isinstance(e.get("device"), str)
        ]
        return "; ".join(shown) if shown else "none"

    def _link_edge(self, record: Mapping[str, Plain], ends: list[Mapping[str, Plain]]) -> _Edge:
        a, b = str(ends[0]["device"]), str(ends[1]["device"])
        status = record.get("status")
        role = record.get("role")
        style, label = self._status_style(status if isinstance(status, str) else None), ""
        if role == "vPC peer-keepalive":
            style, label = _KEEPALIVE, "vPC keepalive"
        elif role == "vPC peer-link":
            label = "vPC peer-link"
        ai, bi = self._ifn(ends[0].get("interface")), self._ifn(ends[1].get("interface"))
        data = (
            ("status", self._txt(status)),
            ("role", self._txt(role)),
            ("ends", f"{self._name(a)} {ai} - {self._name(b)} {bi}"),
            ("evidence", self._evidence(_tuple(record.get("evidence")))),
            ("topology_id", _id(record)),
        )
        return _Edge(f"e-{_id(record)}", a, b, label, ai, bi, _EDGE_BASE + style, data)

    def _port_channel(self, bundle: Mapping[str, Plain], device: str) -> str:
        for side in _tuple(bundle.get("sides")):
            for end in _tuple(side.get("ends")) if isinstance(side, Mapping) else ():
                if isinstance(end, Mapping) and end.get("device") == device:
                    channel = end.get("port_channel")
                    return "no port-channel" if channel is None else self._txt(channel)
        return "?"

    def _bundle_edge(
        self,
        bundle: Mapping[str, Plain],
        a: str,
        b: str,
        links: list[Mapping[str, Plain]],
        seed: str,
    ) -> _Edge:
        na, nb = self._port_channel(bundle, a), self._port_channel(bundle, b)
        statuses = {s for s in (r.get("status") for r in links) if isinstance(s, str)}
        status = next(iter(statuses)) if len(statuses) == 1 else None
        if len(statuses) > 1 and "one-sided" in statuses:
            status = "one-sided"
        label = (na if na == nb else f"{na} / {nb}") + f" \u00d7{len(links)}"
        vpc = any(
            isinstance(s, Mapping) and isinstance(s.get("vpc"), int)
            for s in _tuple(bundle.get("sides"))
        )
        if vpc:
            label += " vPC"
        if bundle.get("role") == "vPC peer-link":
            label += " peer-link"
        data = (
            ("status", self._txt(status) if status else "mixed"),
            ("role", self._txt(bundle.get("role"))),
            ("members", str(len(links))),
            ("flagged_members", self._txt(bundle.get("flagged"))),
            (
                "evidence",
                self._evidence(tuple(e for r in links for e in _tuple(r.get("evidence")))),
            ),
            ("topology_id", _id(bundle)),
        )
        style = _EDGE_BASE + _BUNDLE + self._status_style(status)
        return _Edge(seed, a, b, label, na, nb, style, data)

    def _physical_edges(self) -> list[_Edge]:
        edges: list[_Edge] = []
        groups: dict[str, tuple[Mapping[str, Plain], str, str, list[Mapping[str, Plain]]]] = {}
        for record in _records(self._content, "links"):
            ends = self._ends(record)
            if len(ends) != 2:  # noqa: PLR2004 (two ends)
                continue
            a, b = str(ends[0]["device"]), str(ends[1]["device"])
            bundle_id = record.get("bundle")
            bundle = self._bundles.get(bundle_id) if isinstance(bundle_id, str) else None
            if bundle is None:
                edges.append(self._link_edge(record, ends))
                continue
            key = f"{bundle_id}|{'|'.join(sorted((a, b)))}"
            groups.setdefault(key, (bundle, a, b, []))[3].append(record)
        for number, (bundle, a, b, links) in enumerate(groups.values()):
            edges.append(self._bundle_edge(bundle, a, b, links, f"e-{_id(bundle)}-{number}"))
        for segment in self._segments:
            for index, port in enumerate(_tuple(segment.get("ports"))):
                if not isinstance(port, Mapping) or not isinstance(port.get("device"), str):
                    continue
                ident, device = _id(segment), str(port["device"])
                data = (
                    ("status", "Shared Segment"),
                    (
                        "ends",
                        f"Shared Segment - {self._name(device)} {self._ifn(port.get('interface'))}",
                    ),
                    ("evidence", self._evidence(_tuple(segment.get("evidence")))),
                    ("topology_id", ident),
                )
                edges.append(
                    _Edge(
                        f"e-{ident}-{index}",
                        ident,
                        device,
                        "",
                        "",
                        self._ifn(port.get("interface")),
                        _EDGE_BASE + _SEGMENT_LINE,
                        data,
                    )
                )
        return edges

    def _bends(self, edges: list[_Edge]) -> dict[int, Point]:
        """Where parallel lines between one pair of shapes bow out, so none hides another."""
        key = [tuple(sorted((e.a, e.b))) for e in edges]
        total = Counter(key)
        seen: Counter[tuple[str, ...]] = Counter()
        bends: dict[int, Point] = {}
        for index, pair in enumerate(key):
            count, position = total[pair], seen[pair]
            seen[pair] += 1
            first, second = self._layout.positions[pair[0]], self._layout.positions[pair[1]]
            length = hypot(second.x - first.x, second.y - first.y)
            offset = (position - (count - 1) / 2) * PARALLEL_STEP
            if count > 1 and length > 0:
                dx, dy = second.x - first.x, second.y - first.y
                bends[index] = Point(
                    (first.x + second.x) / 2 - dy / length * offset,
                    (first.y + second.y) / 2 + dx / length * offset,
                )
        return bends

    # ---------- pages ----------

    def physical(self) -> str:
        """Return the Physical page."""
        ids = _Ids()
        unvisited = self._unvisited_ids
        shapes: list[str] = []
        drawn: set[str] = set()
        for group, make in (
            (self._devices, self._device_shape),
            (self._unvisited, self._unvisited_shape),
            (self._segments, self._segment_shape),
        ):
            for record in group:
                ident = _id(record)
                if ident in drawn or ident not in self._layout.positions:
                    continue
                drawn.add(ident)
                shapes.append(make(ids, record))
        edges = [e for e in self._physical_edges() if e.a != e.b and e.a in drawn and e.b in drawn]
        bends = self._bends(edges)
        lines: list[str] = []
        for index, edge in enumerate(edges):
            parent = "2" if edge.a in unvisited or edge.b in unvisited else "1"
            ident = ids.take(edge.seed)
            lines.append(_edge_cell(ident, edge, parent, bends.get(index)))
            for suffix, text, position in (("a", edge.a_label, "-0.7"), ("b", edge.b_label, "0.7")):
                if text:
                    lines.append(_end_label(ids.take(f"{ident}-{suffix}"), text, position, ident))
        body = "".join(shapes) + self._area_labels(ids) + "".join(lines)
        return _page("physical", PHYSICAL, body, hidden_layer=True)

    def routing(self) -> str:
        """Return the Routing page."""
        ids = _Ids()
        shapes: list[str] = []
        drawn: set[str] = set()
        for record in self._devices:
            ident = _id(record)
            if ident in drawn or ident not in self._layout.positions:
                continue
            drawn.add(ident)
            shapes.append(self._device_shape(ids, record))
        points = [self._layout.positions[i] for i in drawn]
        left = min((p.x for p in points), default=0.0) - NODE_WIDTH / 2
        top = min((p.y for p in points), default=0.0) - NODE_HEIGHT / 2 - 70
        note = _vertex(
            ids.take("note"), _lines(NO_ROUTING_NOTE), _NOTE, _Box(left, top, 640.0, 48.0)
        )
        return _page("routing", ROUTING, note + "".join(shapes), hidden_layer=False)


def _page(ident: str, title: str, body: str, *, hidden_layer: bool) -> str:
    layers = f'<mxCell id="1" value="{_text(MAIN_LAYER)}" parent="0"/>\n'
    if hidden_layer:
        layers += f'<mxCell id="2" value="{_text(HIDDEN_LAYER)}" parent="0" visible="0"/>\n'
    return (
        f'<diagram id="{ident}" name="{title}">\n'
        '<mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1" tooltips="1" '
        'connect="1" arrows="1" fold="1" page="0" pageScale="1" pageWidth="827" '
        'pageHeight="1169" math="0" shadow="0">\n<root>\n<mxCell id="0"/>\n'
        f"{layers}{body}</root>\n</mxGraphModel>\n</diagram>\n"
    )
