"""The final summary at the end of a Run, and its exit code (ticket #56; stories 87-90).

Printed once the crawl and the Backups are done, Ctrl+C included:

- the outcome line;
- Visited counts (Backups locked, partial, Backup not taken);
- Unvisited counts by reason, the reasons that need attention marked `!!` and listed first;
- each Credential Set's results, and how many host keys were trusted on first use;
- the Backups' lines (`backup_summary`);
- "Needs your attention": each item marked `!!`, with its next step: the exact
  `trust-key` line, `role-snippet ios-xe` (or `nx-os`) for a Backup not taken, checking
  the password and the AAA lockout counter for a Retired Credential Set (story 88).

`output_paths` gives the full paths of the Run folder, `diagram.html` and
`run-report.html`, printed last of all, once those files are written (story 89). The exit
code is 0 when clean, 1 when something needs attention, 3 when the Run stopped (story 90).
Device text is escaped before it is shown (story 81). The per-device detail lives in the
Topology and, later, the Run report (#66); `run_summary` keeps the per-device lines.
"""

from collections import Counter
from typing import Final

from network_analyser import device_gateway, discovery, run_output
from network_analyser.cli import backup_summary, run_summary
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import PROG
from network_analyser.cli.run_folder import console_text
from network_analyser.records import HostKeyVerdict, Platform
from network_analyser.records.backup import BackupResults
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.events import DeviceOutcome

DIAGRAM_FILE: Final = "diagram.html"
REPORT_FILE: Final = "run-report.html"
NOT_ATTENTION: Final = frozenset(
    {
        UnvisitedReason.OUTSIDE_SCOPE,
        UnvisitedReason.EXCLUDED,
        UnvisitedReason.IPV6_ONLY,
        UnvisitedReason.UNSUPPORTED_ADVERTISED,
        UnvisitedReason.RUN_STOPPED,
        UnvisitedReason.ROUTING_OR_ARP_ONLY,
    }
)
"""Unvisited reasons that need nothing from the operator: the fence, or their own stop."""
_SNIPPET: Final = {Platform.IOS_XE: "ios-xe", Platform.NX_OS: "nx-os"}
_CONTINUED: Final = "      "


def final_summary(result: CrawlResult, backups: BackupResults) -> str:
    """Return the final summary block of one Run."""
    attention = _attention(result, backups)
    lines = [_outcome(result, attention=bool(attention)), *_visited(result, backups)]
    lines.extend(_unvisited(result))
    if result.credential_sets:
        lines.append("Credential Sets:")
        lines.extend(f"  {run_summary.set_line(s)}" for s in result.credential_sets)
    new_keys = sum(
        1
        for r in result.devices
        if r.host_key is not None and r.host_key.verdict is HostKeyVerdict.NEW
    )
    if new_keys:
        lines.append(
            f"New host keys trusted on first use: {new_keys}. Check each fingerprint on the "
            "device console."
        )
    lines.append(backup_summary.summary(backups))
    if attention:
        lines.append("Needs your attention:")
        lines.extend(_marked(item) for item in attention)
    return "\n".join(lines)


def exit_code(result: CrawlResult, backups: BackupResults, *, scan_hits: int) -> ExitCode:
    """0 when clean, 1 when something needs attention, 3 when the Run stopped (story 90)."""
    if result.stopped:
        return ExitCode.STOPPED
    if _attention(result, backups) or backup_summary.needs_attention(backups) or scan_hits:
        return ExitCode.NEEDS_ATTENTION
    return ExitCode.CLEAN


def output_paths(folder: run_output.RunFolder) -> str:
    """The full paths of the Run folder and its two pages, as far as they exist (story 89)."""
    lines = [f"Run folder:      {console_text(str(folder.path))}"]
    for name in (DIAGRAM_FILE, REPORT_FILE):
        label = f"{name}:".ljust(16)
        if (folder.io_path / name).is_file():
            lines.append(f"{label} {console_text(str(folder.path / name))}")
        else:
            lines.append(f"{label} not written")
    return "\n".join(lines)


def _outcome(result: CrawlResult, *, attention: bool) -> str:
    if result.stopped == discovery.STOPPED_BY_CTRL_C:
        return "Run stopped by the operator (Ctrl+C)."
    if result.stopped:
        return f"Run stopped early: {result.stopped}."
    if attention:
        return "Run finished: some things need your attention (below)."
    return "Run finished: nothing needs your attention."


def _visited(result: CrawlResult, backups: BackupResults) -> list[str]:
    reached = [r for r in result.devices if r.outcome is not DeviceOutcome.UNVISITED]
    partial = sum(1 for r in reached if r.outcome is DeviceOutcome.PARTIAL)
    locked = backup_summary.written(backups)
    not_taken = len(_not_backed_up(result, backups))
    line = f"Visited: {len(reached)} (Backups locked: {locked}, partial: {partial}, "
    return [f"{line}Backup not taken: {not_taken})"]


def _unvisited(result: CrawlResult) -> list[str]:
    reasons = Counter(
        r.unvisited_reason
        for r in (*result.devices, *result.unvisited)
        if r.outcome is DeviceOutcome.UNVISITED and r.unvisited_reason is not None
    )
    if not reasons:
        return []
    flagged = [r for r in UnvisitedReason if r in reasons and r not in NOT_ATTENTION]
    others = [r for r in UnvisitedReason if r in reasons and r in NOT_ATTENTION]
    return [
        f"Unvisited: {sum(reasons.values())}",
        *(f"  !! {r.value}: {reasons[r]}" for r in flagged),
        *(f"  {r.value}: {reasons[r]}" for r in others),
    ]


def _not_backed_up(result: CrawlResult, backups: BackupResults) -> list[DeviceRecord]:
    """Devices logged into and identified whose config never reached the locker."""
    taken = {b.ip for b in backups.backups}
    return [
        r
        for r in result.devices
        if r.outcome is not DeviceOutcome.UNVISITED
        and r.platform is not None
        and r.ip not in taken
        and r.partial_reason != device_gateway.CLOSED_BY_OPERATOR
    ]


def _attention(result: CrawlResult, backups: BackupResults) -> list[str]:
    items = run_summary.attention_items(result)
    items.extend(_backup_step(r) for r in _not_backed_up(result, backups))
    return items


def _backup_step(record: DeviceRecord) -> str:
    """The next step for a Backup not taken (story 88)."""
    snippet = _SNIPPET[record.platform] if record.platform else "ios-xe"
    return (
        f"{record.ip}: Backup not taken. If the device refused the backup command, give "
        f"the account its Device Role:\n{PROG} role-snippet {snippet}"
    )


def _marked(item: str) -> str:
    """`  !! ` before an item's first line; its other lines (the next step) indented."""
    first, *rest = item.split("\n")
    return "\n".join([f"  !! {first}", *(f"{_CONTINUED}{line.strip()}" for line in rest)])
