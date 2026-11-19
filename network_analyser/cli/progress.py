"""Progress while the crawl runs: a live panel, log lines, or quiet (ticket #56; stories 77-81).

`Progress` is fed the Run's Audit log events as they happen (from the visit threads) and is
ticked by the crawl on the main thread at least every `discovery.TICK_S` seconds.

- **live** (the default on a console): a panel redrawn in place, with the elapsed time;
  Visited / In progress / Queued / Unvisited counts; Backups locked and waiting; each
  Credential Set's state; every device in progress with its stage and time in that stage;
  the latest 4 attention items; and a banner for notices (story 77).
- **log** (`--progress log`, and always when output is redirected, story 79): one
  timestamped line per device-level event, plus a status line every minute. Command-level
  events stay in `audit.log`.
- **quiet** (`--progress quiet`): attention items and notices only, with one status line
  kept in place on a console.

Counts, never a percentage: the size of the network is not known in advance (story 78). A
device handing over its Backup shows `locking Backup`, and a line says how many Backups are
still being locked once the crawl ends, so progress never looks frozen (story 80). Every
piece of device or operator text is escaped (story 81), and everything is written through
the Run's scanned console. Output is plain ASCII.
"""

import shutil
import sys
import textwrap
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address
from typing import Final

from network_analyser.cli import summary
from network_analyser.cli.text import escape_controls
from network_analyser.records import CredentialSetView
from network_analyser.records.events import (
    AliasFound,
    AuditEvent,
    BackupWritten,
    ConnectionAttempted,
    ConnectionResult,
    CredentialSetRetired,
    DeviceFinished,
    DeviceIdentified,
    DeviceOutcome,
    ErrorRaised,
    HostKeyChecked,
    LoginAttempted,
    LoginResult,
    NeighbourNotVisited,
)

REDRAW_S: Final = 0.2
"""The live panel is redrawn at most this often."""
STATUS_EVERY_S: Final = 60
"""Log mode prints a status line this often."""
LATEST_ATTENTION: Final = 4
_ATTENTION_REASONS: Final = frozenset(r.value for r in summary.ATTENTION_REASONS)
_BACKUP_NOT_WRITTEN_STEP: Final = "write Backup"
_STAGE_LIMIT: Final = 40
_TEXT_LIMIT: Final = 80


@unique
class Mode(Enum):
    """How progress is shown (`--progress`)."""

    LIVE = "live"
    LOG = "log"
    QUIET = "quiet"


def choose_mode(requested: str | None, *, live_ok: bool) -> Mode:
    """The mode to use: the one asked for, but never live when output is redirected."""
    mode = Mode(requested) if requested is not None else Mode.LIVE
    if mode is Mode.LIVE and not live_ok:
        return Mode.LOG
    return mode


def console_write(text: str) -> None:
    """Write `text` to standard output (the Run's scanned console) at once."""
    sys.stdout.write(text)
    sys.stdout.flush()


@dataclass(slots=True)
class _SetState:
    username: str
    logged_in: int = 0
    failed: int = 0
    retired: bool = False

    def shown(self) -> str:
        if self.retired:
            return "retired"
        failed = f", {self.failed} failed" if self.failed else ""
        return f"{self.logged_in} ok{failed}"


class Progress:
    """What the operator sees while the crawl runs. `event` is safe from any thread."""

    def __init__(  # noqa: PLR0913 (the mode, the Run's settings and the console, by name)
        self,
        mode: Mode,
        *,
        sets: Sequence[CredentialSetView],
        parallel: int,
        write: Callable[[str], None] = console_write,
        clock: Callable[[], float] = time.monotonic,
        width: int | None = None,
        in_place: bool = True,
    ) -> None:
        """Get ready to show progress; nothing is written until the first event or tick.

        Args:
            mode: live, log or quiet.
            sets: the Run's Credential Sets, in order (usernames only).
            parallel: devices worked on at once, shown beside the In progress count.
            write: takes console text; standard output unless a test replaces it.
            clock: seconds, for the elapsed time; `time.monotonic` unless a test fakes it.
            width: the console's width; measured when None.
            in_place: True when output is a console, so quiet mode may keep its status
                line in place.
        """
        self._mode = mode
        self._parallel = parallel
        self._write = write
        self._clock = clock
        self._width = (width or shutil.get_terminal_size().columns) - 1
        self._in_place = in_place
        self._lock = threading.Lock()
        self._started = clock()
        self._stages: dict[IPv4Address, tuple[str, float]] = {}
        self._visited = 0
        self._unvisited: set[IPv4Address] = set()
        self._need_attention: set[IPv4Address] = set()
        self._locked = 0
        self._taken = 0
        self._not_written = 0
        self._queued = 0
        self._sets = {view.number: _SetState(view.username) for view in sets}
        self._attention: deque[str] = deque(maxlen=LATEST_ATTENTION)
        self._banner = ""
        self._stopping = 0
        self._drawn = 0
        self._last_draw: float | None = None
        self._next_status = float(STATUS_EVERY_S)
        self._status_len = 0

    # -- Fed from the visits ----------------------------------------------------------------

    def event(self, event: AuditEvent) -> None:
        """Take one Audit log event, as it happens."""
        with self._lock:
            line = self._take(event)
            if line is not None:
                self._line(*line)

    def backup_taken(self, ip: IPv4Address) -> None:
        """Note a config handed to the locking worker (it may wait for room)."""
        with self._lock:
            self._taken += 1
            if ip in self._stages:
                self._stages[ip] = ("locking Backup", self._clock())

    # -- Ticked on the main thread ----------------------------------------------------------

    def tick(self, queued: int) -> None:
        """Redraw (live), or print the minute's status line (log) or the status (quiet)."""
        with self._lock:
            self._queued = queued
            now = self._clock()
            if self._mode is Mode.LIVE:
                if self._last_draw is None or now - self._last_draw >= REDRAW_S:
                    self._draw(now)
            elif self._mode is Mode.LOG:
                if now - self._started >= self._next_status:
                    self._next_status += STATUS_EVERY_S
                    self._emit_line(".. status: " + self._status_text())
            elif self._in_place:
                self._status_in_place()

    def ctrl_c(self, press: int, *, sessions: int) -> None:
        """Tell the operator what a Ctrl+C does now (stories 82-83)."""
        n = _count(sessions, "session")
        if press == 1:
            text = (
                f"Stopping: no new logins will start. Waiting for {n} in progress to finish "
                "(each ends within its timeouts). Press Ctrl+C again to close them now."
            )
        elif press == 2:  # noqa: PLR2004 (the second press)
            text = (
                f"Closing {n} now. No partial Backup is written; Backups already captured "
                "are still locked."
            )
        else:
            text = "Every session is already closed or closing; the outputs are being written."
        with self._lock:
            self._stopping = max(self._stopping, min(press, 2))
            self._notice(text)

    def finish(self) -> None:
        """The last redraw; then say how many Backups are still being locked, if any."""
        with self._lock:
            if self._mode is Mode.LIVE:
                self._draw(self._clock())
            elif self._mode is Mode.QUIET and self._in_place:
                self._status_in_place()
                self._write("\n")
                self._status_len = 0
            waiting = self._waiting()
            if waiting:
                self._write(
                    f"Locking {_count(waiting, 'Backup')} still waiting; each takes a few "
                    "seconds.\n"
                )

    # -- State ------------------------------------------------------------------------------

    def _take(self, event: AuditEvent) -> tuple[str, str] | None:  # noqa: C901 (one branch per event kind)
        """Update the counts; return the (mark, text) of a device-level line, if any."""
        now = self._clock()
        if isinstance(event, ConnectionAttempted):
            connected = event.result is ConnectionResult.CONNECTED
            stage = "checking host key" if connected else "connection failed"
            self._stages[event.ip] = (stage, now)
        elif isinstance(event, HostKeyChecked):
            self._stages[event.ip] = ("logging in", now)
        elif isinstance(event, LoginAttempted):
            state = self._sets.get(event.credential_set)
            succeeded = event.result is LoginResult.SUCCEEDED
            if state is not None:
                state.logged_in += int(succeeded)
                state.failed += int(not succeeded)
            self._stages[event.ip] = ("identifying" if succeeded else "login failed", now)
        elif isinstance(event, DeviceIdentified):
            self._stages[event.ip] = ("reading Neighbours and config", now)
        elif isinstance(event, BackupWritten):
            self._locked += 1
            return ("OK", f"{_ip(event.ip)} Backup locked")
        elif isinstance(event, ErrorRaised) and event.step == _BACKUP_NOT_WRITTEN_STEP:
            self._not_written += 1
        elif isinstance(event, CredentialSetRetired):
            state = self._sets.get(event.credential_set)
            if state is not None:
                state.retired = True
            notice = summary.retirement_notice(event)
            self._attention.append(notice)
            return ("!!", notice)
        elif isinstance(event, AliasFound):
            self._stages.pop(event.ip, None)
            return ("--", f"{_ip(event.ip)} is the same device as {event.same_as}")
        elif isinstance(event, DeviceFinished):
            return self._finished(event)
        elif isinstance(event, NeighbourNotVisited):
            return self._not_visited(event)
        return None

    def _finished(self, event: DeviceFinished) -> tuple[str, str]:
        self._stages.pop(event.ip, None)
        reason = escape_controls(event.reason or "", limit=_TEXT_LIMIT)
        if event.outcome is DeviceOutcome.VISITED:
            self._visited += 1
            return ("OK", f"{_ip(event.ip)} visited")
        if event.outcome is DeviceOutcome.PARTIAL:
            self._visited += 1
            text = f"{_ip(event.ip)} partial: {reason}"
            self._attention.append(text)
            return ("!!", text)
        self._unvisited.add(event.ip)
        text = f"{_ip(event.ip)} unvisited: {reason}"
        if event.reason in _ATTENTION_REASONS:
            self._need_attention.add(event.ip)
            self._attention.append(text)
            return ("!!", text)
        return ("--", text)

    def _not_visited(self, event: NeighbourNotVisited) -> tuple[str, str] | None:
        if not event.addresses:
            return None
        self._unvisited.update(event.addresses)
        reason = escape_controls(event.reason, limit=_TEXT_LIMIT)
        first = event.addresses[0]
        more = f" (+{len(event.addresses) - 1} more)" if len(event.addresses) > 1 else ""
        return ("--", f"{_ip(first)} not visited: {reason}{more}")

    def _waiting(self) -> int:
        return max(0, self._taken - self._locked - self._not_written)

    def _status_text(self) -> str:
        return (
            f"{self._visited} Visited, {len(self._stages)} in progress, {self._queued} queued, "
            f"{len(self._unvisited)} Unvisited ({len(self._need_attention)} need attention), "
            f"{self._locked} Backups locked, {self._waiting()} waiting"
        )

    # -- Writing ----------------------------------------------------------------------------

    def _elapsed(self) -> str:
        return _clock(self._clock() - self._started)

    def _line(self, mark: str, text: str) -> None:
        """Print a device-level line in log mode, or an attention item in quiet mode."""
        if self._mode is Mode.LOG:
            self._emit_line(f"{mark} {text}")
        elif self._mode is Mode.QUIET and mark == "!!":
            self._clear_status()
            self._write(f"!! {text}\n")

    def _emit_line(self, text: str) -> None:
        """A log line, never cut: a redirected log has no width, and a cut loses facts."""
        self._write(f"[{self._elapsed()}] {text}\n")

    def _notice(self, text: str) -> None:
        if self._mode is Mode.LIVE:
            self._banner = text
            self._draw(self._clock())
        elif self._mode is Mode.LOG:
            self._emit_line(f"** {text}")
        else:
            self._clear_status()
            self._write(f"** {text}\n")

    def _clear_status(self) -> None:
        if self._status_len:
            self._write("\r" + " " * self._status_len + "\r")
            self._status_len = 0

    def _status_in_place(self) -> None:
        text = self._fit(
            f"[{self._elapsed()}] Visited {self._visited}  In progress {len(self._stages)}  "
            f"Queued {self._queued}  Unvisited {len(self._unvisited)}  Backups {self._locked}"
        )
        self._write("\r" + text.ljust(self._status_len))
        self._status_len = len(text)

    def _draw(self, now: float) -> None:
        """Redraw the live panel in place: up to its first line, then each line afresh."""
        self._last_draw = now
        lines = self._panel(now)
        out = [f"\x1b[{self._drawn}F"] if self._drawn else []
        out.extend(f"\x1b[2K{self._fit(line)}\n" for line in lines)
        out.append("\x1b[0J")  # a shorter panel leaves nothing of the last one below it
        self._write("".join(out))
        self._drawn = len(lines)

    def _panel(self, now: float) -> list[str]:
        sets = "   ".join(
            f"{number} {escape_controls(state.username, limit=32)}: {state.shown()}"
            for number, state in self._sets.items()
        )
        lines = [
            f" Network Analyser   Elapsed {self._elapsed()}",
            (
                f" Visited {self._visited}   In progress {len(self._stages)}/{self._parallel}"
                f"   Queued {self._queued}   Unvisited {len(self._unvisited)} "
                f"({len(self._need_attention)} need attention)"
            ),
            f" Backups locked {self._locked}, waiting {self._waiting()}",
            f" Credential Sets   {sets}",
            " In progress",
        ]
        for ip, (stage, since) in sorted(self._stages.items(), key=lambda kv: kv[1][1]):
            lines.append(f"   {_ip(ip)} {stage:<{_STAGE_LIMIT}} {_clock(now - since)}")
        lines.append(f" Needs attention (latest {LATEST_ATTENTION}; all are listed at the end)")
        lines.extend(f"   {item}" for item in self._attention)
        if self._banner:
            wrapped = textwrap.wrap(self._banner, max(self._width - 4, 20))
            lines.extend(f" {'**' if i == 0 else '  '} {part}" for i, part in enumerate(wrapped))
        lines.append(
            " Ctrl+C stops the Run (outputs are still written)."
            if not self._stopping
            else " Ctrl+C again closes the sessions now."
            if self._stopping == 1
            else ""
        )
        return lines

    def _fit(self, text: str) -> str:
        return text if len(text) <= self._width else text[: max(self._width - 3, 0)] + "..."


def _ip(ip: IPv4Address) -> str:
    return f"{ip!s:<15}"


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def _clock(seconds: float) -> str:
    whole = max(int(seconds), 0)
    return f"{whole // 3600}:{whole // 60 % 60:02d}:{whole % 60:02d}"
