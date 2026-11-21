"""`render RUN_FOLDER`: redraw a Run's pages in place, with no device (#63, #107, story 155).

Reads `topology.json` in the Run folder and writes `diagram.html`, `diagram.drawio` (#65)
and `findings.html` (#107) beside it. Files from an
older version of the tool are drawn; one from a newer version is refused, because it could
be misread. The Run report is never touched: it stays the fixed record of its Run (story
160). No secret is typed, so the secret scan has nothing to look for, but the pages go
through the same scanned writer as at the end of a Run.

Exit codes: 0 drawn; 1 the diagram could not be written; 2 refused (no such Run folder, no
`topology.json`, or one this version cannot draw).
"""

import argparse
import sys
from pathlib import Path

from network_analyser import _winsys, diagram, run_output
from network_analyser.cli.diagram_file import (
    DIAGRAM_FILE,
    DRAWIO_FILE,
    TOPOLOGY_FILE,
    write_diagram,
)
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.findings_file import FINDINGS_FILE, write_findings
from network_analyser.cli.run_folder import console_text, refuse
from network_analyser.credentials import SecretScan

NOT_A_FOLDER = "RUN_FOLDER is not a folder."
NO_TOPOLOGY = "there is no topology.json in RUN_FOLDER, so there is nothing to draw."
NEWER = (
    "topology.json was written by a newer version of Network Analyser. "
    "Draw it with that version or later."
)
NOT_A_TOPOLOGY = "topology.json in RUN_FOLDER is not a topology this version can draw."
NOT_WRITTEN = (
    "Warning: diagram.html, diagram.drawio or findings.html could not be written (or "
    "topology.json read) in\nthe Run folder. Check the disk and its permissions."
)


def render(args: argparse.Namespace) -> ExitCode:
    """Redraw the diagrams and the Findings report from `topology.json` in the Run folder."""
    path = Path(args.run_folder).absolute()
    folder = run_output.RunFolder(path=path, io_path=_winsys.os_path(path))
    if not Path(folder.io_path).is_dir():
        refuse(args.command, NOT_A_FOLDER)
        return ExitCode.REFUSED
    if not (Path(folder.io_path) / TOPOLOGY_FILE).is_file():
        refuse(args.command, NO_TOPOLOGY)
        return ExitCode.REFUSED
    try:
        scan = SecretScan()
        write_diagram(folder, scan)
        write_findings(folder, scan)
    except diagram.NewerFormatError:
        refuse(args.command, NEWER)
        return ExitCode.REFUSED
    except diagram.TopologyFileError, UnicodeDecodeError:
        refuse(args.command, NOT_A_TOPOLOGY)
        return ExitCode.REFUSED
    except OSError:
        print(NOT_WRITTEN, file=sys.stderr)
        return ExitCode.NEEDS_ATTENTION
    print(f"Diagram written: {console_text(str(path / DIAGRAM_FILE))}")
    print(f"Diagram written: {console_text(str(path / DRAWIO_FILE))}")
    print(f"Findings report written: {console_text(str(path / FINDINGS_FILE))}")
    return ExitCode.CLEAN
