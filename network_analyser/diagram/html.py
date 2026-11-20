r"""`draw_html(topology, redact)`: the self-contained `diagram.html` (#63, #64, stories 142-153).

Two tabs: the Map (Physical, Routing and VLAN views, each device in the same place, with a
Finding count badge and an Upgrade Target tag on every box) (#109) and Findings (grouped by
level, then by Check; picking a Check lights only the devices and Links it hit and dims
everything else) (#108).

The page is one file that works offline. It loads nothing: no CDN, web font, telemetry or
third-party JavaScript, only our own plain JavaScript and CSS from `assets/`, inlined. A
Content-Security-Policy `<meta>` tag allows only those two inline blocks (by their SHA-256)
and no network at all, so even a string that slipped past the escaping could neither run
nor reach anything.

Device text reaches the page only inside one JSON data block, which the script reads and
escapes again wherever it draws it:

- every string, keys included, first passes through `redact` (the Run's secret scan), so a
  secret is caught before escaping could hide it;
- every character other than letters, digits, space and `_ . , -` is then written as a
  `\uXXXX` escape, so the block can hold no `<`, `&`, quote, slash or colon, and so no tag,
  no `</script>`, no URL and no call.

The page is the same for the same `topology.json` and secrets.
"""

import base64
import hashlib
import json
import math
from collections.abc import Callable, Mapping
from dataclasses import asdict
from importlib import resources
from typing import Final

from network_analyser.diagram.findings import findings_tab
from network_analyser.diagram.layout import Layout, place
from network_analyser.diagram.markers import map_markers
from network_analyser.diagram.topology_file import Plain, TopologyFile

TITLE: Final = "Network diagram"
_PLAIN_CHARACTERS: Final = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _.,-"
)

type _Data = Plain | list[_Data] | dict[str, _Data]


def draw_html(topology: TopologyFile, redact: Callable[[str], str]) -> str:
    """Return `diagram.html` for `topology`, every string passed through `redact` first."""
    layout = place(topology)
    data: dict[str, _Data] = {
        "topology": topology.content,
        "layout": _layout_data(layout),
        "findings": asdict(findings_tab(topology)),
        "markers": asdict(map_markers(topology)),
    }
    payload = _encode(data, redact)
    style = _asset("diagram.css")
    script = _asset("diagram.js")
    policy = (
        f"default-src 'none'; script-src 'sha256-{_digest(script)}'; "
        f"style-src 'sha256-{_digest(style)}'; base-uri 'none'; form-action 'none'"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{policy}">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="referrer" content="no-referrer">\n'
        f"<title>{TITLE}</title>\n"
        f"<style>{style}</style>\n</head>\n<body>\n"
        '<div class="app" id="app"><p class="hint">This diagram needs JavaScript.</p></div>\n'
        f'<script type="application/json" id="topology-data">{payload}</script>\n'
        f"<script>{script}</script>\n</body>\n</html>\n"
    )


def _layout_data(layout: Layout) -> dict[str, _Data]:
    positions: list[_Data] = [
        [ident, round(point.x, 1), round(point.y, 1)]
        for ident, point in sorted(layout.positions.items())
    ]
    labels: list[_Data] = [
        {
            "text": label.text,
            "x": round(label.x, 1),
            "y": round(label.y, 1),
            "heading": label.heading,
        }
        for label in layout.labels
    ]
    subnets: list[_Data] = [
        [ident, round(point.x, 1), round(point.y, 1)]
        for ident, point in sorted(layout.subnets.items())
    ]
    return {"positions": positions, "labels": labels, "subnets": subnets}


def _encode(value: object, redact: Callable[[str], str]) -> str:
    """Return `value` as JSON whose strings hold only plain characters and escapes."""
    if isinstance(value, str):
        return f'"{_escape(redact(value))}"'
    if value is None or isinstance(value, bool | int | float):
        finite = not isinstance(value, float) or math.isfinite(value)
        return json.dumps(value) if finite else "null"  # JSON has no infinity
    if isinstance(value, Mapping):
        items = (f"{_encode(str(k), redact)}:{_encode(v, redact)}" for k, v in value.items())
        return "{" + ",".join(items) + "}"
    if isinstance(value, tuple | list):
        return "[" + ",".join(_encode(item, redact) for item in value) + "]"
    msg = f"no JSON form for {type(value).__name__}"
    raise TypeError(msg)


def _escape(text: str) -> str:
    out: list[str] = []
    for character in text:
        if character in _PLAIN_CHARACTERS:
            out.append(character)
            continue
        units = character.encode("utf-16-be", "surrogatepass")
        out.extend(f"\\u{units[i]:02x}{units[i + 1]:02x}" for i in range(0, len(units), 2))
    return "".join(out)


def _asset(name: str) -> str:
    return (
        resources.files("network_analyser.diagram")
        .joinpath("assets", name)
        .read_text(encoding="utf-8")
    )


def _digest(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")
