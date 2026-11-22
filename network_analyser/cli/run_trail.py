"""The started Run's audit trail and the secret-scan warning (ticket #48; stories 86, 161-164).

Once the Run folder is created and registered, `audit.log` is opened in it and the Run-start
event written before anything else happens; the Run-end event is the last line, however the
Run ends. If `audit.log` cannot be created or written, the Run stops as if Ctrl+C had been
pressed (story 86): no login ever happens without an audit trail.
"""

import contextlib
import sys
import time
from collections.abc import Callable

from network_analyser import _winsys, run_output
from network_analyser._version import __version__
from network_analyser.cli import backup_summary, summary
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.run_end import EndOutcome
from network_analyser.cli.run_topology import Conclusion
from network_analyser.credentials import CredentialSets, SecretScan
from network_analyser.records import RunRequest
from network_analyser.records.backup import BackupResults
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.events import (
    AuditEvent,
    CtrlCPressed,
    DeviceOutcome,
    RunEnded,
    RunEnding,
    RunStarted,
)

AUDIT_STOP = (
    "Stopped: audit.log could not be written in the Run folder, so the Run stops as if "
    "Ctrl+C had been pressed:\nno login happens without an audit trail. Check the disk or "
    "share the Run folder is on."
)

type Crawl = Callable[[run_output.AuditLog], tuple[CrawlResult, BackupResults]]
type EndStep = Callable[[run_output.AuditLog, CrawlResult], EndOutcome]


def run_with_audit_trail(  # noqa: PLR0913, PLR0917 (the Run's trail, every dependency explicit)
    request: RunRequest,
    sets: CredentialSets,
    folder: run_output.RunFolder,
    scan: SecretScan,
    crawl: Crawl,
    end: EndStep,
) -> Conclusion:
    """Open `audit.log`, record the Run's start, run `crawl`, then `end`, then its end.

    `end` is the Run's end (#104): it unlocks the key, asks Cisco, runs Analysis and writes
    the outputs, inside the trail, so its `analysis` event lands before the Run-end event.

    Raises:
        KeyboardInterrupt: Ctrl+C during the Run; it is recorded first.
    """
    try:
        audit = run_output.open_audit_log(folder, scan)
    except run_output.AuditLogError:
        return _audit_stop()
    started = time.monotonic()
    result: CrawlResult | None = None
    backups: BackupResults | None = None
    outcome: EndOutcome | None = None
    try:
        audit.record(_run_started(request, sets, folder))
        result, backups = crawl(audit)
        outcome = end(audit, result)
        ending = RunEnding.STOPPED if result.stopped or outcome.stopped else RunEnding.COMPLETED
        audit.record(RunEnded(ending, *_counts(result, backups), scan.hits))
    except run_output.AuditLogError:
        return _audit_stop()
    except KeyboardInterrupt:
        _record_last(audit, CtrlCPressed(press=1, sessions_running=0))
        _record_last(audit, RunEnded(RunEnding.STOPPED, *_counts(result, backups), scan.hits))
        raise
    except Exception:
        _record_last(audit, RunEnded(RunEnding.CRASHED, *_counts(result, backups), scan.hits))
        raise
    finally:
        audit.close()
    assert result is not None  # noqa: S101 (every other path returned or raised)
    assert backups is not None  # noqa: S101 (every other path returned or raised)
    assert outcome is not None  # noqa: S101 (every other path returned or raised)
    print(
        summary.final_summary(
            result,
            backups,
            elapsed_s=time.monotonic() - started,
            extra_attention=outcome.attention,
            stopped_by_operator=outcome.stopped,
        )
    )
    return Conclusion(
        ExitCode.STOPPED
        if outcome.stopped
        else summary.exit_code(
            result,
            backups,
            scan_hits=scan.hits,
            extra_attention=outcome.attention,
        ),
        written=outcome.written,
        attempted=True,
    )


def _counts(result: CrawlResult | None, backups: BackupResults | None) -> tuple[int, int, int]:
    """Visited, Unvisited and Backups-written counts, or zeros before the crawl returned."""
    if result is None or backups is None:
        return (0, 0, 0)
    visited = sum(1 for r in result.devices if r.outcome is not DeviceOutcome.UNVISITED)
    unvisited = len(result.devices) - visited + len(result.unvisited)
    return (visited, unvisited, backup_summary.written(backups))


def _run_started(
    request: RunRequest, sets: CredentialSets, folder: run_output.RunFolder
) -> RunStarted:
    fence = request.scope.value
    return RunStarted(
        tool_version=__version__,
        windows_account=_winsys.windows_account(),
        pc_name=_winsys.pc_name(),
        run_folder=str(folder.path),
        scope=tuple(str(r) for r in fence.ranges),
        exclusions=tuple(str(r) for r in fence.exclusions),
        seeds=request.seeds.value,
        label=request.label.value,
        parallel=request.parallel.value,
        failure_budget=request.failure_budget.value,
        sweep=request.sweep.value,
        credential_sets=tuple(view.username for view in sets.views()),
    )


def _record_last(audit: run_output.AuditLog, event: AuditEvent) -> None:
    """Record how a Run ended, if `audit.log` still takes lines."""
    with contextlib.suppress(run_output.AuditLogError):  # the stop is under way already
        audit.record(event)


def _audit_stop() -> Conclusion:
    print(f"{AUDIT_STOP} No device was contacted.", file=sys.stderr)
    return Conclusion(ExitCode.STOPPED)


def warn_of_scan_hits(scan: SecretScan) -> None:
    """Show one warning with the Run's hit count, if the secret scan blocked anything.

    It never says which Credential Set, or the passphrase, matched (story 164).
    """
    hits = scan.hits
    if not hits:
        return
    pieces = "1 piece" if hits == 1 else f"{hits} pieces"
    print(
        f"Warning: the secret scan replaced {pieces} of this Run's output with [blocked], "
        "because they matched\na password or the Backup Passphrase typed for this Run. "
        "Either the tool has a bug, or a\nCredential Set password is common text (such as a "
        "word that appears in names or paths)\nand should be changed.",
        file=sys.stderr,
    )
