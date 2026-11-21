"""`topology.json`, `diagram.html` and `findings.html`: written at the end of a Run.

Written for every started Run, Ctrl+C included. `topology.json` is #52's; the diagram and the
Findings report are then drawn from that file alone (#63, #107).

`Collector` keeps each device record as the crawl hands it back, so a Run stopped part way
still has the records gathered so far. At the end, `save_topology` builds the Topology, runs
Analysis on it (#94), and writes it through `run_output`'s scanned writer, so a typed secret
is never written (story 164). The topology module never sees the scan or a file: it turns
records into plain data. Analysis takes the plain Topology and returns plain results.

Analysis runs here, after the crawl and after Backups are locked, on Visited Devices only.
The Run-end's own results, Cisco's answers included, are written by `save_all` (#104); the
offline `save_topology` is the path a stopped Run takes.
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
from network_analyser.records.topology import AnalysisResults, CiscoLookups, Topology

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
    run: Callable[[], Conclusion],
    *,
    scope: ScopeRecord | None = None,
) -> ExitCode:
    """Run the Run, then write what is not written yet, Ctrl+C included.

    The Run-end writes its own outputs inside the audit trail (#104), so `run` says whether
    they are already written. A stopped Run never got that far: its records are written here
    with Cisco's sources unavailable. `scope` is the Run's Scope, passed into the Topology so
    in-Scope routing neighbours are recorded (#62). A Topology or diagram that could not be
    written makes the Run need attention (exit 1 at least).

    Raises:
        KeyboardInterrupt: Ctrl+C during the Run, once the files are written.
    """
    try:
        conclusion = run()
    except KeyboardInterrupt:  # write what was found so far, then stop (exit 3)
        _save(folder, collector, scan, scope)
        raise
    if conclusion.attempted:
        return (
            conclusion.code
            if conclusion.written
            else max(conclusion.code, ExitCode.NEEDS_ATTENTION)
        )
    if not _save(folder, collector, scan, scope):
        return max(conclusion.code, ExitCode.NEEDS_ATTENTION)
    return conclusion.code


@dataclasses.dataclass(frozen=True, slots=True)
class Conclusion:
    """How a Run ended once its outputs were accounted for.

    Attributes:
        code: the exit code the Run's own summary gives.
        written: whether every output is on disk.
        attempted: whether the Run-end tried to write them; when it did, a failed write is
            not retried here, so a partial failure never replaces Cisco's results with an
            offline copy.
    """

    code: ExitCode
    written: bool = False
    attempted: bool = False


def _save(
    folder: run_output.RunFolder,
    collector: Collector,
    scan: SecretScan,
    scope: ScopeRecord | None,
) -> bool:
    """Write `topology.json`, then draw the diagram and the Findings report from it.

    False if any of the three failed. A stopped Run takes this path: no key is unlocked and
    every Cisco source is unavailable, so only offline Checks contribute Findings.
    """
    return save_all(folder, collector.records(), scan, scope=scope)


def save_all(  # noqa: PLR0913 (the Run-end's outputs, every dependency explicit)
    folder: run_output.RunFolder,
    records: tuple[DeviceRecord, ...],
    scan: SecretScan,
    *,
    scope: ScopeRecord | None = None,
    results: AnalysisResults | None = None,
    lookups: CiscoLookups | None = None,
) -> bool:
    """Write `topology.json`, then draw the diagram and Findings report from it.

    `results` and `lookups` are the Run-end's own (#104); without them Analysis runs offline
    and the file records that Cisco was not asked. False if any of the three failed.
    """
    return (
        save_topology(folder, records, scan, scope=scope, results=results, lookups=lookups)
        and diagram_file.save_diagram(folder, scan)
        and findings_file.save_findings(folder, scan)
    )


def build_topology(records: tuple[DeviceRecord, ...], scope: ScopeRecord | None = None) -> Topology:
    """Build the Topology from `records`; `scope` records in-Scope routing neighbours (#62)."""
    return topology.build(records, scope=scope)


def save_topology(  # noqa: PLR0913 (the file's inputs, every dependency explicit)
    folder: run_output.RunFolder,
    records: tuple[DeviceRecord, ...],
    scan: SecretScan,
    *,
    scope: ScopeRecord | None = None,
    results: AnalysisResults | None = None,
    lookups: CiscoLookups | None = None,
) -> bool:
    """Build the Topology from `records` and write `topology.json` through the scan.

    `results` are the Run-end's Analysis results, Cisco's answers included (#104); without
    them Analysis runs offline. `lookups` is the top-level `cisco_lookups` record; None
    records that Cisco was not asked. Returns False, after a fixed warning, if the file could
    not be written.
    """
    built = build_topology(records, scope)
    if results is None:
        results = run_analysis.analysed(built)
    built = dataclasses.replace(
        built,
        findings=results.findings,
        analysis=results.summary,
        cisco_lookups=lookups or CiscoLookups(ran=False),
    )
    document = topology.to_document(built)
    try:
        run_output.write_scanned_json(folder, TOPOLOGY_FILE, document, scan)
    except OSError:
        print(NOT_WRITTEN, file=sys.stderr)
        return False
    print(f"Topology written: {TOPOLOGY_FILE} in the Run folder.")
    return True
