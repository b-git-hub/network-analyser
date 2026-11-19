"""`audit.log`: what the tool did, in order, as it went (spec #37 stories 86, 161-166; #30).

JSON Lines in the Run folder: one object per event, appended and on disk as soon as it is
recorded, so it survives a crash. Every line holds `time` (UTC, milliseconds), `event` and
`severity`, then the event's fixed fields, in order. The writer refuses an event type that
is not in `AUDIT_SCHEMA`, a record whose fields differ from its list, and any value that is
not plain data, so nothing but the decided fields can ever reach the file: no device
output, and never a `Secret`.

Every text value, and then the whole line, passes through the Run's secret scan on the way
out, so a typed secret that slipped into an event is written as `[blocked]`. Lines are
plain ASCII: JSON escapes every control and non-ASCII character, so a device's terminal
escape codes never reach the file raw.

If a line cannot be written (a full disk, a lost share), `record` raises `AuditLogError`
then and for every later event: the caller stops the Run as if Ctrl+C had been pressed, so
no login happens without an audit trail (story 86).
"""

import json
import os
import sys
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Final

from network_analyser.credentials import SecretScan
from network_analyser.records import events
from network_analyser.records.events import AuditEvent
from network_analyser.run_output.folder import RunFolder

AUDIT_LOG_NAME: Final = "audit.log"

# The fixed name and field list of every event type (#30 section 6). A field added to a
# record without being added here is refused at the first write.
AUDIT_SCHEMA: Final[Mapping[type[AuditEvent], tuple[str, tuple[str, ...]]]] = {
    events.RunStarted: (
        "run_started",
        (
            "tool_version",
            "windows_account",
            "pc_name",
            "run_folder",
            "scope",
            "exclusions",
            "seeds",
            "label",
            "parallel",
            "failure_budget",
            "sweep",
            "credential_sets",
        ),
    ),
    events.RunEnded: (
        "run_ended",
        (
            "ended",
            "devices_visited",
            "devices_unvisited",
            "backups_written",
            "secret_scan_hits",
        ),
    ),
    events.CtrlCPressed: ("ctrl_c_pressed", ("press", "sessions_running")),
    events.ConnectionAttempted: ("connection_attempted", ("ip", "port", "result", "retry")),
    events.ProbeAttempted: ("probe_attempted", ("ip", "port", "result", "banner_read")),
    events.OutOfScopeRefused: ("out_of_scope_refused", ("ip", "port", "placement")),
    events.HostKeyChecked: (
        "host_key_checked",
        ("ip", "port", "key_type", "fingerprint", "verdict", "trusted_fingerprint"),
    ),
    events.LoginAttempted: ("login_attempted", ("ip", "credential_set", "username", "result")),
    events.CredentialSetRetired: (
        "credential_set_retired",
        ("credential_set", "username", "failures"),
    ),
    events.DeviceIdentified: ("device_identified", ("ip", "platform", "landing_privilege")),
    events.CommandSent: (
        "command_sent",
        ("ip", "command", "duration_ms", "bytes_received", "result"),
    ),
    events.ParseFailed: ("parse_failed", ("ip", "command", "parser", "reason")),
    events.BackupWritten: (
        "backup_written",
        ("ip", "path", "ciphertext_sha256", "scrypt_level"),
    ),
    events.DeviceFinished: ("device_finished", ("ip", "outcome", "reason")),
    events.AliasFound: ("alias_found", ("ip", "same_as", "evidence")),
    events.NeighbourNotVisited: (
        "neighbour_not_visited",
        ("reported_by", "addresses", "reason"),
    ),
    events.ErrorRaised: ("error_raised", ("ip", "step", "error_type", "message")),
}

if sys.platform == "win32":
    _FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_BINARY
else:
    _FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND


class AuditLogError(Exception):
    """`audit.log` could not be created or written. The message is fixed text."""


class AuditEventRefusedError(TypeError):
    """An event is not on the fixed schema, or holds a value that is not plain data.

    A bug in the tool, never the operator's doing. The message is fixed text and never
    quotes the value.
    """


type Write = Callable[[int, bytes], int]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def open_audit_log(
    folder: RunFolder,
    scan: SecretScan,
    *,
    now: Callable[[], datetime] = _utc_now,
    write: Write = os.write,
) -> AuditLog:
    """Create `audit.log` in a new Run folder and return its writer.

    The file is created exclusively: an existing one is never appended to or replaced.

    Args:
        folder: the Run folder, just created.
        scan: the Run's secret scan.
        now: the clock, UTC; a seam for tests.
        write: writes bytes to a file handle; a seam for tests (a full disk).

    Raises:
        AuditLogError: the file could not be created.
    """
    try:
        handle = os.open(folder.io_path / AUDIT_LOG_NAME, _FLAGS, 0o600)
    except OSError as error:
        msg = "audit.log could not be created"
        raise AuditLogError(msg) from error
    return AuditLog(handle, scan, now=now, write=write)


class AuditLog:
    """The Run's `audit.log`, open for appending. Safe to use from several threads."""

    __slots__ = ("_broken", "_handle", "_lock", "_now", "_scan", "_write")

    def __init__(
        self, handle: int, scan: SecretScan, *, now: Callable[[], datetime], write: Write
    ) -> None:
        """Wrap a handle `open_audit_log` opened. Use `open_audit_log`, not this."""
        self._handle: int | None = handle
        self._scan = scan
        self._now = now
        self._write = write
        self._broken = False
        self._lock = threading.Lock()

    def record(self, event: AuditEvent) -> None:
        """Append one event as one line, on disk before this returns.

        Raises:
            AuditEventRefusedError: the event is not on the schema or not plain data.
            AuditLogError: the line could not be written, now or earlier this Run.
        """
        line = self._line(event)
        with self._lock:
            if self._broken or self._handle is None:
                msg = "audit.log could not be written"
                raise AuditLogError(msg)
            try:
                _write_all(self._write, self._handle, line)
            except OSError as error:
                self._broken = True
                msg = "audit.log could not be written"
                raise AuditLogError(msg) from error

    def close(self) -> None:
        """Close the file. Safe to call twice; later records raise `AuditLogError`."""
        with self._lock:
            if self._handle is not None:
                handle, self._handle = self._handle, None
                try:
                    os.close(handle)
                except OSError:
                    self._broken = True

    def _line(self, event: AuditEvent) -> bytes:
        entry = AUDIT_SCHEMA.get(type(event))
        if entry is None:
            msg = "this event type is not in the Audit log schema"
            raise AuditEventRefusedError(msg)
        name, fields = entry
        if tuple(getattr(type(event), "__dataclass_fields__", ())) != fields:
            msg = "this event's fields differ from its fixed list"
            raise AuditEventRefusedError(msg)
        stamp = self._now().astimezone(UTC).isoformat(timespec="milliseconds")
        values: dict[str, object] = {
            "time": stamp.replace("+00:00", "Z"),
            "event": name,
            "severity": event.severity.value,
        }
        for field in fields:
            values[field] = self._plain(getattr(event, field))
        text = json.dumps(values, ensure_ascii=True, separators=(", ", ": "))
        redacted, _hits = self._scan.contains_secret(text)
        return f"{redacted}\n".encode("ascii")

    def _plain(self, value: object) -> object:
        """Return `value` as JSON data, every text scanned; refuse anything not plain."""
        if value is None or isinstance(value, bool | int):
            return value
        if isinstance(value, str):
            return self._scan.contains_secret(value)[0]
        if isinstance(value, Enum):
            return self._plain(value.value)
        if isinstance(value, IPv4Address | IPv4Network):
            return str(value)
        if isinstance(value, tuple):
            return [self._plain(item) for item in value]
        msg = "an Audit log value must be plain data"
        raise AuditEventRefusedError(msg)


def _write_all(write: Write, handle: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = write(handle, view.tobytes())
        view = view[written:]
