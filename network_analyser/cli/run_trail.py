"""The started Run's audit trail and the secret-scan warning (ticket #48; stories 86, 161-164).

Once the Run folder is created and registered, `audit.log` is opened in it and the Run-start
event written before anything else happens; the Run-end event is the last line, however the
Run ends. If `audit.log` cannot be created or written, the Run stops as if Ctrl+C had been
pressed (story 86): no login ever happens without an audit trail.
"""

import contextlib
import sys
from collections.abc import Callable

from network_analyser import _winsys, run_output
from network_analyser._version import __version__
from network_analyser.cli import backup_summary, run_summary
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.credentials import CredentialSets, SecretScan
from network_analyser.records import RunRequest
from network_analyser.records.backup import BackupResults
from network_analyser.records.device import DeviceRecord
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

type Crawl = Callable[[run_output.AuditLog], tuple[tuple[DeviceRecord, ...], BackupResults]]


def run_with_audit_trail(
    request: RunRequest,
    sets: CredentialSets,
    folder: run_output.RunFolder,
    scan: SecretScan,
    crawl: Crawl,
) -> ExitCode:
    """Open `audit.log`, record the Run's start, run `crawl`, and record how the Run ended.

    Raises:
        KeyboardInterrupt: Ctrl+C during the Run; it is recorded first.
    """
    try:
        audit = run_output.open_audit_log(folder, scan)
    except run_output.AuditLogError:
        return _audit_stop()
    try:
        audit.record(_run_started(request, sets, folder))
        records, backups = crawl(audit)
        visited = sum(1 for r in records if r.outcome is not DeviceOutcome.UNVISITED)
        unvisited = len(records) - visited
        written = backup_summary.written(backups)
        audit.record(RunEnded(RunEnding.COMPLETED, visited, unvisited, written, scan.hits))
    except run_output.AuditLogError:
        return _audit_stop()
    except KeyboardInterrupt:
        _record_last(audit, CtrlCPressed(press=1, sessions_running=0))
        _record_last(audit, RunEnded(RunEnding.STOPPED, 0, 0, 0, scan.hits))
        raise
    except Exception:
        _record_last(audit, RunEnded(RunEnding.CRASHED, 0, 0, 0, scan.hits))
        raise
    finally:
        audit.close()
    print(run_summary.summary(records))
    print(backup_summary.summary(backups))
    attention = run_summary.needs_attention(records) or backup_summary.needs_attention(backups)
    if attention or scan.hits:
        return ExitCode.NEEDS_ATTENTION
    return ExitCode.CLEAN


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


def _audit_stop() -> ExitCode:
    print(f"{AUDIT_STOP} No device was contacted.", file=sys.stderr)
    return ExitCode.STOPPED


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
