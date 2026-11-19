"""`topology.json`: written at the end of every started Run, Ctrl+C included (#52).

`Collector` keeps each device record as the crawl hands it back, so a Run stopped part way
still has the records gathered so far. At the end, `save_topology` builds the Topology and
writes it through `run_output`'s scanned writer, so a typed secret is never written (story
164). The topology module never sees the scan or a file: it turns records into plain data.
"""

import sys
import threading
from collections.abc import Callable
from typing import Final

from network_analyser import run_output, topology
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.credentials import SecretScan
from network_analyser.records.device import DeviceRecord

TOPOLOGY_FILE: Final = "topology.json"
NOT_WRITTEN: Final = (
    "Warning: topology.json could not be written in the Run folder, so the diagram cannot be "
    "drawn\nfrom this Run. Check the disk or share the Run folder is on."
)


class Collector:
    """The device records of a Run, kept as the crawl hands them back. Thread-safe."""

    def __init__(self) -> None:
        """Start with no records."""
        self._records: list[DeviceRecord] = []
        self._lock = threading.Lock()

    def add(self, record: DeviceRecord) -> DeviceRecord:
        """Keep `record`, and return it."""
        with self._lock:
            self._records.append(record)
        return record

    def records(self) -> tuple[DeviceRecord, ...]:
        """Every record kept so far, in the order they came."""
        with self._lock:
            return tuple(self._records)


def then_save(
    folder: run_output.RunFolder,
    collector: Collector,
    scan: SecretScan,
    run: Callable[[], ExitCode],
) -> ExitCode:
    """Run the Run, then write `topology.json` from what `collector` kept, Ctrl+C included.

    A Topology that could not be written makes the Run need attention (exit 1 at least).

    Raises:
        KeyboardInterrupt: Ctrl+C during the Run, once `topology.json` is written.
    """
    try:
        code = run()
    except KeyboardInterrupt:  # write what was found so far, then stop (exit 3)
        save_topology(folder, collector.records(), scan)
        raise
    if not save_topology(folder, collector.records(), scan):
        return max(code, ExitCode.NEEDS_ATTENTION)
    return code


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
