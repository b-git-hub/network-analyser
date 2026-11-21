"""Write `run-report.html` once a Run folder exists, including after Ctrl+C or a crash (#66).

The crawl keeps whatever it has on the draft. At the end, or when the Run is stopping, the
report is written best-effort: a failure to write it does not change how the Run ended, and
it never prints an exception's text.
"""

import dataclasses
import sys
from dataclasses import dataclass
from datetime import UTC, datetime

from network_analyser import _winsys, analysis, run_output, topology
from network_analyser._version import __version__
from network_analyser.cli import run_analysis, summary
from network_analyser.credentials import CredentialSets, SecretScan
from network_analyser.discovery import STOPPED_BY_CTRL_C
from network_analyser.records.analysis import AnalysisInput
from network_analyser.records.backup import BackupResults
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.device import DeviceRecord
from network_analyser.records.events import RunEnding
from network_analyser.records.platform import CredentialSetResult
from network_analyser.records.run_request import RunRequest
from network_analyser.records.run_summary import RunReport, RunReportFacts
from network_analyser.records.sweep import SweepResult

NOT_WRITTEN = (
    "Warning: run-report.html could not be written in the Run folder. The rest of this Run's "
    "outputs are unchanged."
)
_CRASHED = (
    "The Run ended in an internal error. Its details are not shown, in case they hold a "
    "secret or device output."
)
_EMPTY_BACKUPS = BackupResults((), 0.0, None, None)


@dataclass(frozen=True, slots=True)
class Captured:
    """What the crawl had when it stopped. None of it is a secret."""

    records: tuple[DeviceRecord, ...]
    backups: BackupResults | None
    credential_sets: tuple[CredentialSetResult, ...]
    sweep: SweepResult | None
    stopped: str | None


@dataclass
class Draft:
    """The report's inputs, filled in as the Run goes and read once at the end.

    Attributes:
        folder: the Run folder the report is written into.
        scan: the Run's secret scan.
        started_at: the Run folder's timestamp, UTC.
        request: the Scope, Seeds and flags. No secret.
        strict_host_keys: whether strict host-key checking was on.
        notices: location, permissions and Trust Store warnings.
        ending: completed once the crawl returns; stopped on Ctrl+C; crashed until then.
        ctrl_c: True when Ctrl+C raised out of the crawl, so the reason is that press.
        captured: what the crawl kept. None when it never started.
    """

    folder: run_output.RunFolder
    scan: SecretScan
    started_at: datetime
    request: RunRequest
    strict_host_keys: bool
    notices: tuple[str, ...]
    ending: RunEnding = RunEnding.CRASHED
    ctrl_c: bool = False
    captured: Captured | None = None

    def capture(self, captured: Captured) -> None:
        """Keep what the crawl had. Called from the crawl's own finally."""
        self.captured = captured


def publish(draft: Draft) -> None:
    """Write the report. A failure is a fixed warning and nothing else.

    Best-effort on purpose: this runs while a Run is already ending, including after a
    crash, and must not replace that ending with its own error.
    """
    try:
        run_output.write_run_report(draft.folder, _report(draft), draft.scan)
    except Exception:  # noqa: BLE001 (best-effort; the Run's own ending still stands)
        print(NOT_WRITTEN, file=sys.stderr)


def _report(draft: Draft) -> RunReport:
    """Assemble the plain report from the draft."""
    captured = draft.captured
    records = () if captured is None else captured.records
    backups = _EMPTY_BACKUPS if captured is None or captured.backups is None else captured.backups
    credential_sets = () if captured is None else captured.credential_sets
    sweep = None if captured is None else captured.sweep
    stopped = None if captured is None else captured.stopped
    if draft.ending is RunEnding.STOPPED and stopped is None and draft.ctrl_c:
        stopped = STOPPED_BY_CTRL_C
    built = topology.build(records, scope=draft.request.scope.value)
    # #94: the report shows Analysis Findings too. It does not use the online step's answers;
    # the Run-end results in topology.json are the ones #104 and #110 will share.
    results = analysis.analyse(
        AnalysisInput(topology=built, collected=run_analysis.collected_from(records))
    )
    built = dataclasses.replace(built, findings=results.findings, analysis=results.summary)
    crawl = CrawlResult(
        devices=records,
        stopped=stopped,
        credential_sets=credential_sets,
        sweep=sweep,
    )
    attention = tuple(summary.attention_items(crawl, backups))
    if draft.ending is RunEnding.CRASHED:
        attention = (*attention, _CRASHED)
    return RunReport(
        facts=_facts(draft, stopped),
        devices=records,
        backups=backups,
        topology=built,
        credential_sets=credential_sets,
        sweep=sweep,
        attention=attention,
    )


def _facts(draft: Draft, stopped: str | None) -> RunReportFacts:
    """The Run's own facts. The account and PC are read now, for a crash as well."""
    request = draft.request
    scope = request.scope.value
    return RunReportFacts(
        started_at=draft.started_at,
        ended_at=datetime.now(UTC),
        ending=draft.ending,
        stop_reason=stopped,
        tool_version=__version__,
        windows_account=_winsys.windows_account(),
        pc_name=_winsys.pc_name(),
        folder=str(draft.folder.path),
        scope=tuple(str(item) for item in scope.ranges),
        exclusions=tuple(str(item) for item in scope.exclusions),
        seeds=tuple(str(ip) for ip in request.seeds.value),
        flags=_flags(request, strict_host_keys=draft.strict_host_keys),
        notices=draft.notices,
        secret_scan_hits=draft.scan.hits,
    )


def _flags(request: RunRequest, *, strict_host_keys: bool) -> tuple[str, ...]:
    """Each flag as one line, with where it came from. No device text."""
    timeouts = request.timeouts
    label = "none" if request.label.value is None else request.label.value
    sweep = "yes" if request.sweep.value else "no"
    strict = "yes" if strict_host_keys else "no"
    return (
        f"label: {label} ({request.label.source.value})",
        f"parallel: {request.parallel.value} ({request.parallel.source.value})",
        f"failure budget: {request.failure_budget.value} ({request.failure_budget.source.value})",
        f"sweep: {sweep} ({request.sweep.source.value})",
        f"sweep in flight: {request.sweep_inflight.value} ({request.sweep_inflight.source.value})",
        f"strict host keys: {strict}",
        (
            "timeouts (seconds): "
            f"connect {_num(timeouts.connect)}, login {_num(timeouts.login)}, "
            f"command {_num(timeouts.command)}, backup {_num(timeouts.backup)}, "
            f"device {_num(timeouts.device)}"
        ),
    )


def _num(value: float) -> str:
    """A timeout without a trailing decimal when it is a whole number of seconds."""
    return format(value, "g")


def captured_from(
    records: tuple[DeviceRecord, ...],
    backups: BackupResults | None,
    sets: CredentialSets,
    sweep: SweepResult | None,
    stopped: str | None,
) -> Captured:
    """What the crawl's finally hands the draft. The sets' results never hold a password."""
    return Captured(records, backups, sets.results(), sweep, stopped)
