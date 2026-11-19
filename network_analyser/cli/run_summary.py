"""The basic end-of-Run summary: each device's outcome, and what needs attention (#49, #50).

The full summary and the Run report come later (#56, #66). This one lists every device the
Run tried (with the other IPs it was found at), every device it only heard of, then a
"Needs your attention" list with a next step for each item (story 88): the exact
`trust-key` line for a changed host key, a note for a landing privilege too low for the
tool's commands, a check for each Retired Credential Set, and why the Run stopped early, if
it did. Each Credential Set's results are listed too (#54). Device text and usernames are
escaped before they are printed (story 81); no device output is ever shown.
"""

from network_analyser.cli.parser import PROG
from network_analyser.cli.text import escape_controls
from network_analyser.discovery import ALL_SETS_RETIRED
from network_analyser.records import CredentialSetResult, HostKeyVerdict
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.device import DeviceRecord, LandingPrivilege, UnvisitedReason
from network_analyser.records.events import CredentialSetRetired, DeviceOutcome


def summary(result: CrawlResult) -> str:
    """Return the summary block for the devices of one Run."""
    records = result.devices
    counts = {o: sum(1 for r in records if r.outcome is o) for o in DeviceOutcome}
    lines = [
        (
            f"Run summary: {len(records)} device{'' if len(records) == 1 else 's'} tried: "
            f"{counts[DeviceOutcome.VISITED]} visited, {counts[DeviceOutcome.PARTIAL]} partial, "
            f"{counts[DeviceOutcome.UNVISITED]} unvisited."
        ),
        *(line for r in records for line in _lines(r)),
    ]
    if result.unvisited:
        lines.append(f"Known but never logged into: {len(result.unvisited)}.")
        lines.extend(f"  {_unvisited_line(u)}" for u in result.unvisited)
    new_keys = sum(
        1 for r in records if r.host_key is not None and r.host_key.verdict is HostKeyVerdict.NEW
    )
    if new_keys:
        lines.append(
            f"New host keys trusted on first use: {new_keys}. Check each fingerprint on the "
            "device console."
        )
    if result.credential_sets:
        lines.append("Credential Sets:")
        lines.extend(f"  {_set_line(s)}" for s in result.credential_sets)
    attention = _all_attention(result)
    if attention:
        lines.append("Needs your attention:")
        lines.extend(f"  {item}" for item in attention)
    return "\n".join(lines)


def needs_attention(result: CrawlResult) -> bool:
    """Say whether anything in the Run needs the operator (exit code 1, story 90)."""
    return bool(_all_attention(result))


def retirement_notice(event: CredentialSetRetired) -> str:
    """The line shown the moment a set is retired: its number, username and the usual cause."""
    return (
        f"Credential Set {event.credential_set} ({escape_controls(event.username, limit=64)}) "
        f"is retired after {_logins(event.failures)} and will not be tried again this Run. "
        "A mistyped password is the usual cause."
    )


def _all_attention(result: CrawlResult) -> list[str]:
    items = [item for r in result.devices for item in _attention(r)]
    items.extend(_retired_step(s) for s in result.credential_sets if s.retired)
    if result.stopped == ALL_SETS_RETIRED:
        items.append(f"The Run stopped early: {result.stopped}. No further login was started.")
    elif result.stopped:
        items.append(
            f"The Run stopped early: {result.stopped}. No further login was started. Check "
            "the disk holding the per-user data folder, then run again."
        )
    return items


def _set_line(result: CredentialSetResult) -> str:
    view = result.view
    limit = f", {view.platform_limit.value} only" if view.platform_limit else ""
    retired = ", retired" if result.retired else ""
    return (
        f"Set {view.number} ({escape_controls(view.username, limit=64)}{limit}): "
        f"{result.successes} worked, {result.failures} failed{retired}"
    )


def _retired_step(result: CredentialSetResult) -> str:
    """The next step for a Retired Credential Set (story 88)."""
    view = result.view
    return (
        f"Credential Set {view.number} ({escape_controls(view.username, limit=64)}) was retired "
        f"after {_logins(result.failures)}. A mistyped password is the usual cause: check the "
        "password and each device's AAA lockout counter, then run again."
    )


def _logins(failures: int) -> str:
    return f"{failures} failed login{'' if failures == 1 else 's'}"


def _lines(record: DeviceRecord) -> list[str]:
    """The device's line, then one line per other IP it was found at (story 73)."""
    return [
        f"  {_line(record)}",
        *(f"  {'':<15}  also at {alias}" for alias in record.aliases),
    ]


def _unvisited_line(record: DeviceRecord) -> str:
    reason = record.unvisited_reason.value if record.unvisited_reason else "no reason recorded"
    return f"{record.ip!s:<15}  unvisited  {reason}"


def _line(record: DeviceRecord) -> str:
    head = f"{record.ip!s:<15}  {record.outcome.value:<9}"
    if record.outcome is DeviceOutcome.UNVISITED and record.unvisited_reason is not None:
        return f"{head}  {record.unvisited_reason.value}"
    parts = [record.platform.value if record.platform else "Platform unknown"]
    if record.version is not None and isinstance(record.version.hostname, str):
        parts.append(escape_controls(record.version.hostname, limit=64))
    if isinstance(record.landing_privilege, LandingPrivilege):
        parts.append(f"privilege {escape_controls(record.landing_privilege.shown, limit=64)}")
    if record.credential_set is not None:
        parts.append(f"as {escape_controls(record.credential_set.username, limit=64)}")
    if record.partial_reason is not None:
        parts.append(f"({record.partial_reason})")
    return f"{head}  {'  '.join(parts)}"


def _attention(record: DeviceRecord) -> list[str]:
    """Return what needs the operator about one device, each with its next step."""
    ip = str(record.ip)
    reason = record.unvisited_reason
    if reason in {UnvisitedReason.HOST_KEY_CHANGED, UnvisitedReason.HOST_KEY_NOT_TRUSTED}:
        return [_host_key_step(record)]
    if reason is UnvisitedReason.AUTHENTICATION_FAILED:
        return [
            (
                f"{ip}: authentication failed with every eligible Credential Set. Check the "
                "passwords and the device's AAA lockout counter."
            )
        ]
    if reason is not None:
        return [f"{ip}: {reason.value}."]
    if record.outcome is DeviceOutcome.PARTIAL:
        return [f"{ip}: partial: {record.partial_reason}."]
    privilege = record.landing_privilege
    if isinstance(privilege, LandingPrivilege) and privilege.too_low:
        return [
            (
                f"{ip}: the login landed at privilege "
                f"{escape_controls(privilege.shown, limit=64)}, too low for the tool's "
                f'commands. Give the account its Device Role ("{PROG} role-snippet").'
            )
        ]
    return []


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
