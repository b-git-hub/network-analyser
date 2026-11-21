"""`topology.json`, `diagram.html` and `findings.html`: written at the end of a Run.

Written for every started Run, Ctrl+C included. `topology.json` is #52's; the diagram and the
Findings report are then drawn from that file alone (#63, #107).

`Collector` keeps each device record as the crawl hands it back, so a Run stopped part way
still has the records gathered so far. At the end, `save_topology` builds the Topology, runs
Analysis on it (#94), and writes it through `run_output`'s scanned writer, so a typed secret
is never written (story 164). The topology module never sees the scan or a file: it turns
records into plain data. Analysis takes the plain Topology and returns plain results.

Analysis runs here, after the crawl and after Backups are locked, on Visited Devices only.
`run_analysis.answers_for` is the offline placeholder for the Cisco step (#104).
"""

import dataclasses
import sys
import threading
from collections.abc import Callable
from typing import Final

from network_analyser import run_output, topology
from network_analyser.cli import diagram_file, findings_file, run_analysis
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.credentials import SecretScan
from network_analyser.records.device import DeviceRecord
from network_analyser.records.identity import Alias
from network_analyser.records.scope import ScopeRecord

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
    *,
    scope: ScopeRecord | None = None,
) -> ExitCode:
    """Run the Run, then write `topology.json` and draw the diagram from it, Ctrl+C included.

    `scope` is the Run's Scope, passed into the Topology so in-Scope routing neighbours are
    recorded (#62). A Topology or diagram that could not be written makes the Run need
    attention (exit 1 at least).

    Raises:
        KeyboardInterrupt: Ctrl+C during the Run, once the files are written.
    """
    try:
        code = run()
    except KeyboardInterrupt:  # write what was found so far, then stop (exit 3)
        _save(folder, collector, scan, scope)
        raise
    if not _save(folder, collector, scan, scope):
        return max(code, ExitCode.NEEDS_ATTENTION)
    return code


def _save(
    folder: run_output.RunFolder,
    collector: Collector,
    scan: SecretScan,
    scope: ScopeRecord | None,
) -> bool:
    """Write `topology.json`, then draw the diagram and the Findings report from it.

    False if any of the three failed.
    """
    return (
        save_topology(folder, collector.records(), scan, scope=scope)
        and diagram_file.save_diagram(folder, scan)
        and findings_file.save_findings(folder, scan)
    )


def save_topology(
    folder: run_output.RunFolder,
    records: tuple[DeviceRecord, ...],
    scan: SecretScan,
    *,
    scope: ScopeRecord | None = None,
) -> bool:
    """Build the Topology from `records` and write `topology.json` through the scan.

    `scope` is the Run's Scope, so in-Scope routing neighbours CDP never advertised are
    recorded (#62). Analysis runs on the built Topology (#94), so its Findings and advice
    ride the same file. Returns False, after a fixed warning, if the file could not be written.
    """
    built = topology.build(records, scope=scope)
    results = run_analysis.analysed(built)
    built = dataclasses.replace(
        built,
        findings=results.findings,
        analysis=results.summary,
    )
    document = topology.to_document(built)
    try:
        run_output.write_scanned_json(folder, TOPOLOGY_FILE, document, scan)
    except OSError:
        print(NOT_WRITTEN, file=sys.stderr)
        return False
    print(f"Topology written: {TOPOLOGY_FILE} in the Run folder.")
    return True
