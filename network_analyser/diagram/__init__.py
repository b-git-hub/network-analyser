"""The `diagram` module: draws `diagram.html` and `diagram.drawio` from the Topology file.

Reads only `topology.json`, so `render` can redraw a diagram without any device. Neither
file loads anything from the network (security test 4).
"""

from network_analyser.diagram.drawio import draw_drawio
from network_analyser.diagram.html import draw_html
from network_analyser.diagram.layout import AreaLabel, Layout, Point, place
from network_analyser.diagram.topology_file import (
    KNOWN_FORMAT_VERSION,
    CiscoLookups,
    NewerFormatError,
    Plain,
    TopologyFile,
    TopologyFileError,
    cisco_lookups,
    read_topology,
)

__all__ = [
    "KNOWN_FORMAT_VERSION",
    "AreaLabel",
    "CiscoLookups",
    "Layout",
    "NewerFormatError",
    "Plain",
    "Point",
    "TopologyFile",
    "TopologyFileError",
    "cisco_lookups",
    "draw_drawio",
    "draw_html",
    "place",
    "read_topology",
]
