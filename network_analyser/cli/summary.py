"""The final summary at the end of a Run, and its exit code (ticket #56; stories 87-90).

The block printed once the crawl and the Backups are finished:

- the outcome line: finished clean, finished needing attention, or stopped (and why);
- Visited counts (Backups locked, partial, Backup not taken), then Unvisited counts by
  reason, the reasons that need attention marked `!!` and listed first;
- each Credential Set's results (#54) and the count of host keys trusted for the first
  time;
- the Backups line (#51);
- "Needs your attention": one item per thing to fix, each with its next step (story 88):
  the exact `trust-key` line, `role-snippet ios-xe` (or `nx-os`) for a Backup not taken,
  and checking the password and AAA lockout counter for a Retired Credential Set.

`where_to_look` gives the full paths of the Run folder, `diagram.html` and
`run-report.html`, printed last, once those files are written (story 89). `exit_code` is
0 when clean, 1 when something needs attention, 3 when the Run stopped (story 90).

Counts only, never a percentage (story 78). Usernames and device text are escaped (story
81); reasons are the tool's own fixed text. No device output is ever shown.
"""

from collections import Counter
from collections.abc import Iterable
from typing import Final

from network_analyser.cli import backup_summary
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import PROG
from network_analyser.cli.run_folder import console_text
from network_analyser.cli.text import escape_controls
from network_analyser.device_gateway import CLOSED_BY_OPERATOR
from network_analyser.discovery import ALL_SETS_RETIRED, STOPPED_BY_CTRL_C
from network_analyser.records import CredentialSetResult, HostKeyVerdict, Platform
from network_analyser.records.backup import BackupResults
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.device import DeviceRecord, LandingPrivilege, UnvisitedReason
from network_analyser.records.events import CredentialSetRetired, DeviceOutcome
from network_analyser.run_output import RunFolder

ATTENTION_REASONS: Final = frozenset(
    {
        UnvisitedReason.UNREACHABLE,
        UnvisitedReason.ALGORITHMS_TOO_OLD,
        UnvisitedReason.HOST_KEY_CHANGED,
        UnvisitedReason.HOST_KEY_NOT_TRUSTED,
        UnvisitedReason.AUTHENTICATION_FAILED,
        UnvisitedReason.SETS_RETIRED,
    }
)
"""The Unvisited reasons the operator can act on: marked `!!` and listed first (story 87)."""
DIAGRAM_FILE: Final = "diagram.html"
RUN_REPORT_FILE: Final = "run-report.html"
_ROLE_SNIPPET: Final = {Platform.IOS_XE: "ios-xe", Platform.NX_OS: "nx-os"}
_NEXT_STEP: Final = {
    UnvisitedReason.UNREACHABLE: (
        "no SSH connection could be made. Check the device is up and that SSH (TCP 22) is "
        "open to it from this PC."
    ),
    UnvisitedReason.ALGORITHMS_TOO_OLD: (
        "it offers only SSH algorithms the tool refuses. Enable modern SSH key exchange, "
        "ciphers and host keys on the device (vendor hardening guide)."
    ),
    UnvisitedReason.AUTHENTICATION_FAILED: (
        "authentication failed with every eligible Credential Set. Check the passwords and "
        "the device's AAA lockout counter."
    ),
    UnvisitedReason.SETS_RETIRED: (
        "not attempted: every Credential Set that fits it was retired. Fix the set, then run again."
    ),
}


def final_summary(result: CrawlResult, backups: BackupResults, *, elapsed_s: float) -> str:
    """Return the final summary block (story 87)."""
    attention = attention_items(result, backups)
    lines = [
        _outcome(result, len(attention), elapsed_s),
        _visited_line(result, backups),
        *_unvisited_lines(result),
    ]
    if result.credential_sets:
        lines.append("Credential Sets")
        lines.extend(f"   {_set_line(s)}" for s in result.credential_sets)
    lines.append(f"Host keys trusted for the first time: {_new_keys(result)}.")
    lines.append(backup_summary.headline(backups))
    if attention:
        lines.append("Needs your attention")
        lines.extend(f"  {item}" for item in attention)
    return "\n".join(lines)


def attention_items(result: CrawlResult, backups: BackupResults) -> list[str]:
    """Each thing the operator should fix, with its next step (story 88)."""
    locked = {b.ip for b in backups.backups if b.path is not None}
    items = [item for r in result.devices for item in _attention(r, locked)]
    items.extend(_retired_step(s) for s in result.credential_sets if s.retired)
    items.extend(backup_summary.attention(backups))
    if result.stopped == ALL_SETS_RETIRED:
        items.append(f"The Run stopped early: {result.stopped}. No further login was started.")
    elif result.stopped and result.stopped != STOPPED_BY_CTRL_C:
        items.append(
            f"The Run stopped early: {result.stopped}. No further login was started. Check "
            "the disk holding the per-user data folder, then run again."
        )
    return items


def needs_attention(result: CrawlResult, backups: BackupResults) -> bool:
    """Say whether anything in the Run needs the operator."""
    return bool(attention_items(result, backups))


def exit_code(result: CrawlResult, backups: BackupResults, *, scan_hits: int) -> ExitCode:
    """0 clean, 1 needs attention (a secret-scan hit included), 3 stopped (story 90)."""
    if result.stopped:
        return ExitCode.STOPPED
    if scan_hits or needs_attention(result, backups):
        return ExitCode.NEEDS_ATTENTION
    return ExitCode.CLEAN


def where_to_look(folder: RunFolder) -> str:
    """The full paths of the Run folder and of the diagram and Run report, if written."""
    lines = [f"Run folder  {console_text(str(folder.path))}"]
    for label, name in (("Diagram    ", DIAGRAM_FILE), ("Run report ", RUN_REPORT_FILE)):
        if (folder.io_path / name).is_file():
            lines.append(f"{label} {console_text(str(folder.path / name))}")
    return "\n".join(lines)


def retirement_notice(event: CredentialSetRetired) -> str:
    """The line shown the moment a set is retired: its number, username and the usual cause."""
    return (
        f"Credential Set {event.credential_set} ({_username(event.username)}) "
        f"is retired after {_logins(event.failures)} and will not be tried again this Run. "
        "A mistyped password is the usual cause."
    )


# -- Lines ---------------------------------------------------------------------------------


def _outcome(result: CrawlResult, attention: int, elapsed_s: float) -> str:
    took = _clock(elapsed_s)
    if result.stopped == STOPPED_BY_CTRL_C:
        return f"Run STOPPED by Ctrl+C after {took}. Outputs cover what was found before the stop."
    if result.stopped:
        return f"Run STOPPED after {took}: {result.stopped}."
    if attention:
        return f"Run finished in {took}, with {_count(attention, 'item')} that need your attention."
    return f"Run finished in {took}. Nothing needs your attention."


def _visited_line(result: CrawlResult, backups: BackupResults) -> str:
    visited = [r for r in result.devices if r.outcome is not DeviceOutcome.UNVISITED]
    partial = sum(1 for r in visited if r.outcome is DeviceOutcome.PARTIAL)
    locked = {b.ip for b in backups.backups if b.path is not None}
    not_taken = sum(1 for r in visited if r.platform is not None and r.ip not in locked)
    line = f"Visited    {len(visited):>3}   Backups locked {backup_summary.written(backups)}"
    if partial:
        line += f", partial {partial}"
    if not_taken:
        line += f", Backup not taken {not_taken}"
    return line


def _unvisited_lines(result: CrawlResult) -> list[str]:
    reasons = Counter(
        r.unvisited_reason
        for r in (*result.devices, *result.unvisited)
        if r.unvisited_reason is not None
    )
    lines = [f"Unvisited  {sum(reasons.values()):>3}"]
    marked = sorted(reasons.items(), key=lambda pair: (pair[0] not in ATTENTION_REASONS, -pair[1]))
    for reason, count in marked:
        mark = "!!" if reason in ATTENTION_REASONS else "  "
        lines.append(f"   {mark} {count:>3}  {reason.value}")
    return lines


def _set_line(result: CredentialSetResult) -> str:
    view = result.view
    limit = f", {view.platform_limit.value} only" if view.platform_limit else ""
    retired = ", retired" if result.retired else ""
    return (
        f"Set {view.number} ({_username(view.username)}{limit}): "
        f"{result.successes} worked, {result.failures} failed{retired}"
    )


def _new_keys(result: CrawlResult) -> int:
    return sum(
        1
        for r in result.devices
        if r.host_key is not None and r.host_key.verdict is HostKeyVerdict.NEW
    )


# -- Attention items -----------------------------------------------------------------------


def _attention(record: DeviceRecord, locked: Iterable[object]) -> list[str]:
    """What needs the operator about one device, each with its next step."""
    ip = str(record.ip)
    reason = record.unvisited_reason
    if reason in {UnvisitedReason.HOST_KEY_CHANGED, UnvisitedReason.HOST_KEY_NOT_TRUSTED}:
        return [_host_key_step(record)]
    if reason is not None:
        step = _NEXT_STEP.get(reason)
        return [f"{ip}: {step}"] if step is not None else []
    items: list[str] = []
    if record.outcome is DeviceOutcome.PARTIAL and record.partial_reason != CLOSED_BY_OPERATOR:
        items.append(f"{ip}: partial: {record.partial_reason}.")
    if (
        record.platform is not None
        and record.ip not in locked
        and record.partial_reason != CLOSED_BY_OPERATOR
    ):
        items.append(
            f"{ip}: Backup not taken. If the account lacks the rights, give it its Device "
            f'Role ("{PROG} role-snippet {_ROLE_SNIPPET[record.platform]}").'
        )
    privilege = record.landing_privilege
    if isinstance(privilege, LandingPrivilege) and privilege.too_low:
        items.append(
            f"{ip}: the login landed at privilege {escape_controls(privilege.shown, limit=64)}, "
            f"too low for the tool's commands. Give the account its Device Role (\"{PROG} "
            'role-snippet").'
        )
    return items


def _host_key_step(record: DeviceRecord) -> str:
    """The exact `trust-key` line for a changed or untrusted host key (story 88)."""
    ip = str(record.ip)
    check = record.host_key
    new = check.fingerprint if check is not None else None
    step = f"{PROG} trust-key {ip} --fingerprint {new or '<the fingerprint the console shows>'}"
    if record.unvisited_reason is UnvisitedReason.HOST_KEY_NOT_TRUSTED:
        what = "host key not yet trusted (strict mode)"
    else:
        old = ", ".join(check.trusted_fingerprints) if check is not None else ""
        what = f"host key changed (trusted: {old or 'unknown'}; now: {new or 'not read'})"
    return (
        f"{ip}: {what}. No password was sent. Check the key on the device console; if it is "
        f"right, run:\n    {step}"
    )


def _retired_step(result: CredentialSetResult) -> str:
    """The next step for a Retired Credential Set (story 88)."""
    view = result.view
    return (
        f"Credential Set {view.number} ({_username(view.username)}) was retired "
        f"after {_logins(result.failures)}. A mistyped password is the usual cause: check the "
        "password and each device's AAA lockout counter, then run again."
    )


# -- Helpers -------------------------------------------------------------------------------


def _username(username: str) -> str:
    return escape_controls(username, limit=64)


def _logins(failures: int) -> str:
    return _count(failures, "failed login")


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def _clock(seconds: float) -> str:
    whole = int(seconds)
    return f"{whole // 3600}:{whole // 60 % 60:02d}:{whole % 60:02d}"
