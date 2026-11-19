"""`topology.json` and `diagram.html`: written at the end of every started Run, Ctrl+C included.

`topology.json` is #52's; the diagram is then drawn from that file alone (#63).

`Collector` keeps each device record as the crawl hands it back, so a Run stopped part way
still has the records gathered so far. At the end, `save_topology` builds the Topology and
writes it through `run_output`'s scanned writer, so a typed secret is never written (story
164). The topology module never sees the scan or a file: it turns records into plain data.
"""

import dataclasses
import sys
import threading
from collections.abc import Callable
from typing import Final

from network_analyser import run_output, topology
from network_analyser.cli import diagram_file
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.credentials import SecretScan
from network_analyser.records.device import DeviceRecord
from network_analyser.records.identity import Alias

TOPOLOGY_FILE: Final = diagram_file.TOPOLOGY_FILE
NOT_WRITTEN: Final = (
    "Warning: topology.json could not be written in the Run folder, so the diagram cannot be "
    "drawn\nfrom this Run. Check the disk or share the Run folder is on."
)


class Collector:
    """The device records of a Run, kept as the crawl hands them back. Thread-safe.

    An `Alias` (another IP of a device already examined, #50) is kept too, and folded into
    that device's `aliases` when the records are read.
    """

    def __init__(self) -> None:
        """Start with no records."""
        self._records: list[DeviceRecord] = []
        self._aliases: list[Alias] = []
        self._lock = threading.Lock()

    def add[R: (DeviceRecord, Alias, DeviceRecord | Alias)](self, record: R) -> R:
        """Keep `record`, and return it."""
        with self._lock:
            if isinstance(record, Alias):
                self._aliases.append(record)
            else:
                self._records.append(record)
        return record

    def records(self) -> tuple[DeviceRecord, ...]:
        """Every record kept so far, in the order they came, with its aliases folded in."""
        with self._lock:
            records, aliases = tuple(self._records), tuple(self._aliases)
        return tuple(_with_aliases(r, aliases) for r in records)


def _with_aliases(record: DeviceRecord, aliases: tuple[Alias, ...]) -> DeviceRecord:
    found = tuple(a.ip for a in aliases if a.same_as == record.ip and a.ip not in record.aliases)
    return dataclasses.replace(record, aliases=(*record.aliases, *found)) if found else record


def then_save(
    folder: run_output.RunFolder,
    collector: Collector,
    scan: SecretScan,
    run: Callable[[], ExitCode],
) -> ExitCode:
    """Run the Run, then write `topology.json` and draw the diagram from it, Ctrl+C included.

    A Topology or diagram that could not be written makes the Run need attention (exit 1
    at least).

    Raises:
        KeyboardInterrupt: Ctrl+C during the Run, once the files are written.
    """
    try:
        code = run()
    except KeyboardInterrupt:  # write what was found so far, then stop (exit 3)
        _save(folder, collector, scan)
        raise
    if not _save(folder, collector, scan):
        return max(code, ExitCode.NEEDS_ATTENTION)
    return code


def _save(folder: run_output.RunFolder, collector: Collector, scan: SecretScan) -> bool:
    """Write `topology.json`, then `diagram.html` from it; False if either failed."""
    return save_topology(folder, collector.records(), scan) and diagram_file.save_diagram(
        folder, scan
    )


def save_topology(
    folder: run_output.RunFolder, records: tuple[DeviceRecord, ...], scan: SecretScan
) -> bool:
    """Build the Topology from `records` and write `topology.json` through the scan.

    Returns False, after a fixed warning, if the file could not be written.
    """
    document = topology.to_document(topology.build(records))
    try:
        run_output.write_scanned_json(folder, TOPOLOGY_FILE, document, scan)
    except OSError:
        print(NOT_WRITTEN, file=sys.stderr)
        return False
    print(f"Topology written: {TOPOLOGY_FILE} in the Run folder.")
    return True
