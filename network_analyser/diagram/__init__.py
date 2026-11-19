"""The `diagram` module: draws `diagram.html` and `diagram.drawio` from the Topology file.

Reads only `topology.json`, so `render` can redraw a diagram without any device. Its
pages load nothing from the network (security test 4).
"""

from network_analyser.diagram.html import draw_html
from network_analyser.diagram.layout import AreaLabel, Layout, Point, place
from network_analyser.diagram.topology_file import (
    KNOWN_FORMAT_VERSION,
    NewerFormatError,
    Plain,
    TopologyFile,
    TopologyFileError,
    read_topology,
)

__all__ = [
    "KNOWN_FORMAT_VERSION",
    "AreaLabel",
    "Layout",
    "NewerFormatError",
    "Plain",
    "Point",
    "TopologyFile",
    "TopologyFileError",
    "draw_html",
    "place",
    "read_topology",
]
