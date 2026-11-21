"""`findings.html`, drawn from a Run folder's `topology.json` (#107, stories 103-111).

The page is drawn from that file alone (story 112), and the Run time from the folder's name,
which is the Run's UTC start, so a Run and a later `render` draw the same page. It is made at
the end of every started Run, beside the diagrams, and by `render RUN_FOLDER`.

Every string is passed through the secret scan before the page escapes it, then the whole
text again as it is written (story 116); the file is written temp-then-rename through
`run_output`'s one scanned writer.
"""

import re
import sys
from pathlib import Path
from typing import Final

from network_analyser import diagram, run_output
from network_analyser.credentials import SecretScan

TOPOLOGY_FILE: Final = "topology.json"
FINDINGS_FILE: Final = "findings.html"
NOT_WRITTEN: Final = (
    "Warning: findings.html could not be drawn in the Run folder. Run "
    "`network-analyser render` on\nthe Run folder later to draw it from topology.json."
)
_NOT_RECORDED: Final = "not recorded"
_STAMP: Final = re.compile(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z")


def write_findings(
    folder: run_output.RunFolder, scan: SecretScan, *, run_time: str | None = None
) -> int:
    """Draw `findings.html` from `topology.json` in `folder`; return the scan's hits.

    `run_time` is the Run's UTC start as fixed text. When it is None it is read from the Run
    folder's name, so `render` redraws the page a Run wrote.

    Raises:
        OSError: `topology.json` could not be read, or the page written.
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

    when = run_time if run_time is not None else _run_time(folder)
    page = diagram.draw_findings_report(topology, redact, run_time=when)
    return hits + run_output.write_scanned_text(folder, FINDINGS_FILE, page, scan)


def save_findings(folder: run_output.RunFolder, scan: SecretScan) -> bool:
    """Draw the Findings report at the end of a Run; False, after a fixed warning, if it failed."""
    try:
        write_findings(folder, scan)
    except OSError, ValueError:  # an unreadable file, or one this version cannot draw
        print(NOT_WRITTEN, file=sys.stderr)
        return False
    print(f"Findings report written: {FINDINGS_FILE} in the Run folder.")
    return True


def _run_time(folder: run_output.RunFolder) -> str:
    """The Run's UTC start, as fixed text, from a Run folder name; else `not recorded`."""
    match = _STAMP.match(folder.path.name)
    if match is None:
        return _NOT_RECORDED
    year, month, day, hour, minute, second = match.groups()
    return f"{year}-{month}-{day} {hour}:{minute}:{second}Z"
