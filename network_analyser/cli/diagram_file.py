"""`diagram.html` and `diagram.drawio`, drawn from a Run folder's `topology.json` (#63, #65).

Both are drawn from that file alone (stories 142, 154, 155). They are made at the end of
every started Run (Ctrl+C included) and by `render RUN_FOLDER`. They are drawn from the file,
never from the Run's memory, so a Run and a later `render` draw the same thing. Every string
is passed through the secret scan before the page or the draw.io file escapes it, then the
whole text again as it is written (story 164); each file is written temp-then-rename beside
`topology.json`.
"""

import sys
from pathlib import Path
from typing import Final

from network_analyser import diagram, run_output
from network_analyser.credentials import SecretScan

TOPOLOGY_FILE: Final = "topology.json"
DIAGRAM_FILE: Final = "diagram.html"
DRAWIO_FILE: Final = "diagram.drawio"
NOT_WRITTEN: Final = (
    "Warning: diagram.html or diagram.drawio could not be drawn in the Run folder. Run "
    "`network-analyser render` on\nthe Run folder later to draw them from topology.json."
)


def write_diagram(folder: run_output.RunFolder, scan: SecretScan) -> int:
    """Draw `diagram.html` and `diagram.drawio` from `topology.json` in `folder`.

    Both are drawn before either is written, so a file this version cannot draw leaves the
    folder as it was. Returns the scan's hits.

    Raises:
        OSError: `topology.json` could not be read, or a diagram written.
        UnicodeDecodeError: `topology.json` is not UTF-8 text.
        diagram.TopologyFileError: it is not a `topology.json` this version can draw
            (`diagram.NewerFormatError` when a newer version wrote it).
    """
    text = (Path(folder.io_path) / TOPOLOGY_FILE).read_text(encoding="utf-8")
    topology = diagram.read_topology(text)
    hits = 0

    def redact(value: str) -> str:
        nonlocal hits
        redacted, found = scan.contains_secret(value)
        hits += found
        return redacted

    page = diagram.draw_html(topology, redact)
    drawing = diagram.draw_drawio(topology, redact)
    hits += run_output.write_scanned_text(folder, DIAGRAM_FILE, page, scan)
    return hits + run_output.write_scanned_text(folder, DRAWIO_FILE, drawing, scan)


def save_diagram(folder: run_output.RunFolder, scan: SecretScan) -> bool:
    """Draw both diagrams at the end of a Run; False, after a fixed warning, if one failed."""
    try:
        write_diagram(folder, scan)
    except OSError, ValueError:  # an unreadable file, or one this version cannot draw
        print(NOT_WRITTEN, file=sys.stderr)
        return False
    print(f"Diagrams written: {DIAGRAM_FILE} and {DRAWIO_FILE} in the Run folder.")
    return True
