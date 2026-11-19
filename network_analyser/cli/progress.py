"""Progress while the crawl runs: a live panel, a log, or quiet (ticket #56; stories 77-81).

- `live` (the default on a console): a panel redrawn in place, at most once a second, with
  the elapsed time; Visited / In progress / Queued / Unvisited counts; Backups locked and
  waiting; each Credential Set's state; every device in progress with its stage and time
  in stage; the latest 4 attention items; and a banner for notices (story 77).
- `log`: one timestamped line per event, plus a status line every minute. Used whenever
  output is not a console (story 79), so a redirected file never holds cursor codes.
- `quiet`: attention items and notices as they come, and one status line at the end.

Counts are shown, never a percentage: the size of a crawl is not known until it ends
(story 78). pyrage holds the GIL for a few seconds per Backup, so nothing can redraw while
it locks; a static `Locking...` line is printed before each lock, so the panel never looks
frozen without saying why (story 80). Device and operator text has its control characters
escaped before it is shown (story 81); everything goes out through the console, which the
Run's secret scan sits in front of. Visits call `event` from their threads; the crawl's thread calls
`tick`. All output is written under one lock, so lines never interleave.
"""

import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum, unique
from ipaddress import IPv4Address
from typing import Final, TextIO

from network_analyser import run_output
from network_analyser.cli import summary
from network_analyser.cli.text import escape_controls
from network_analyser.records import CredentialSetView
from network_analyser.records import events as ev

REDRAW_EVERY_S: Final = 1.0
STATUS_EVERY_S: Final = 60.0
ATTENTION_SHOWN: Final = 4
_STAGE_LIMIT: Final = 48
_TEXT_LIMIT: Final = 120
_QUIET_REASONS: Final = frozenset(r.value for r in summary.NOT_ATTENTION)
"""Unvisited reasons that are not attention items: the fence, or the operator's own stop."""


@unique
class Mode(Enum):
    """How progress is shown (`--progress`)."""

    LIVE = "live"
    LOG = "log"
    QUIET = "quiet"


def choose_mode(asked: str | None, *, is_console: bool) -> Mode:
    """The mode to use: as asked, but `log` in place of `live` when output is redirected."""
    mode = Mode(asked) if asked is not None else Mode.LIVE
    if mode is Mode.LIVE and not is_console:
        return Mode.LOG
    return mode


@dataclass(slots=True)
class _SetState:
    view: CredentialSetView
    worked: int = 0
    failed: int = 0
    retired: bool = False

    def line(self) -> str:
        view = self.view
        limit = f", {view.platform_limit.value} only" if view.platform_limit else ""
        state = ", retired" if self.retired else ""
        return (
            f"Set {view.number} ({_text(view.username, 64)}{limit}): "
            f"{self.worked} worked, {self.failed} failed{state}"
        )


class Progress:
    """What the crawl is doing, shown in one of three modes. Safe across threads."""

    def __init__(
        self,
        out: TextIO,
        mode: Mode,
        *,
        sets: Sequence[CredentialSetView],
        clock: Callable[[], float] = time.monotonic,
        utc: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        """Show progress on `out` in `mode`; `sets` are the Run's Credential Sets."""
        self._out = out
        self._mode = mode
        self._clock = clock
        self._utc = utc
        self._lock = threading.Lock()
        self._started = clock()
        self._last_draw: float | None = None
        self._last_status = self._started
        self._drawn = 0
        self._in_progress: dict[IPv4Address, tuple[str, float]] = {}
        self._visited = 0
        self._partial = 0
        self._unvisited = 0
        self._queued = 0
        self._locked = 0
        self._waiting = 0
        self._sets = {view.number: _SetState(view) for view in sets}
        self._attention: deque[str] = deque(maxlen=ATTENTION_SHOWN)
        self._banner: str | None = None

    # -- What happens -----------------------------------------------------------------------

    def event(self, event: ev.AuditEvent) -> None:
        """Take one Audit log event as a visit emits it."""
        with self._lock:
            attention = self._apply(event)
            if self._mode is Mode.LOG:
                self._write(f"{self._stamp()} {_describe(event)}\n")
            elif attention is not None and self._mode is Mode.QUIET:
                self._write(f"{attention}\n")
            if isinstance(event, ev.CtrlCPressed) and self._banner is not None:
                self._static(self._banner)

    def tick(self, queued: int) -> None:
        """Note how many devices are queued; redraw the panel or print the minute's status."""
        with self._lock:
            self._queued = queued
            now = self._clock()
            if self._mode is Mode.LIVE:
                if self._last_draw is None or now - self._last_draw >= REDRAW_EVERY_S:
                    self._redraw()
            elif self._mode is Mode.LOG and now - self._last_status >= STATUS_EVERY_S:
                self._last_status = now
                self._write(f"{self._stamp()} Status: {self._status()}\n")

    def notice(self, text: str) -> None:
        """Show a notice from the tool (fixed text, device text already escaped) at once."""
        with self._lock:
            self._banner = text
            self._static(text)

    def locking(self, ip: IPv4Address) -> None:
        """Say a Backup is about to be locked: the display may pause meanwhile (story 80)."""
        with self._lock:
            self._waiting += 1
            if self._mode is not Mode.QUIET:
                self._static(
                    f"Locking the Backup of {ip}: the display may pause for a few seconds."
                )

    def finish(self) -> None:
        """The crawl has ended: draw the panel once more, or print the closing status."""
        with self._lock:
            if self._mode is Mode.LIVE:
                self._redraw()
            elif self._mode is Mode.QUIET:
                self._write(f"Status: {self._status()}\n")

    # -- State ------------------------------------------------------------------------------

    def _apply(self, event: ev.AuditEvent) -> str | None:  # noqa: C901, PLR0912 (one arm per event type)
        """Update the counts from `event`; return the attention item it raises, if any."""
        now = self._clock()
        match event:
            case ev.ConnectionAttempted(ip=ip, retry=retry):
                stage = "retrying the connection" if retry else "connecting"
                self._in_progress[ip] = (stage, now)
            case ev.HostKeyChecked(ip=ip):
                self._stage(ip, "checking the host key", now)
            case ev.LoginAttempted(ip=ip, credential_set=number, result=result):
                state = self._sets.get(number)
                if state is not None:
                    if result is ev.LoginResult.SUCCEEDED:
                        state.worked += 1
                    else:
                        state.failed += 1
                self._stage(ip, f"logging in with set {number}", now)
            case ev.DeviceIdentified(ip=ip, platform=platform):
                self._stage(ip, f"identified as {platform.value}", now)
            case ev.CommandSent(ip=ip, command=command):
                self._stage(ip, _text(command, _STAGE_LIMIT), now)
            case ev.AliasFound(ip=ip):
                self._in_progress.pop(ip, None)
            case ev.DeviceFinished():
                return self._finished(event)
            case ev.NeighbourNotVisited(addresses=addresses):
                self._unvisited += len(addresses)
            case ev.CredentialSetRetired(credential_set=number, username=username):
                state = self._sets.get(number)
                if state is not None:
                    state.retired = True
                return self._attend(f"Credential Set {number} ({_text(username, 64)}) retired")
            case ev.BackupWritten():
                self._locked += 1
                self._waiting = max(0, self._waiting - 1)
            case ev.ErrorRaised(step=step) if step == "write Backup":
                self._waiting = max(0, self._waiting - 1)
                return self._attend(f"{event.ip}: the Backup could not be written")
            case ev.CtrlCPressed(press=press, sessions_running=running):
                self._banner = _stop_banner(press, running)
            case _:
                pass
        return None

    def _stage(self, ip: IPv4Address, stage: str, now: float) -> None:
        if ip in self._in_progress:
            self._in_progress[ip] = (stage, now)

    def _finished(self, event: ev.DeviceFinished) -> str | None:
        self._in_progress.pop(event.ip, None)
        if event.outcome is ev.DeviceOutcome.UNVISITED:
            self._unvisited += 1
            if event.reason is None or event.reason in _QUIET_REASONS:
                return None
        else:
            self._visited += 1
            if event.outcome is not ev.DeviceOutcome.PARTIAL:
                return None
            self._partial += 1
        reason = _text(event.reason or "no reason recorded", _TEXT_LIMIT)
        return self._attend(f"{event.ip}: {reason}")

    def _attend(self, item: str) -> str:
        shown = f"!! {item}"
        self._attention.append(shown)
        return shown

    # -- Output (under the lock) ------------------------------------------------------------

    def _status(self) -> str:
        partial = f" ({self._partial} partial)" if self._partial else ""
        return (
            f"Visited {self._visited}{partial} | In progress {len(self._in_progress)} | "
            f"Queued {self._queued} | Unvisited {self._unvisited}"
        )

    def _panel(self) -> list[str]:
        now = self._clock()
        lines = [
            f"Network Analyser: {_elapsed(now - self._started)} elapsed. Ctrl+C stops the Run.",
            self._status(),
            f"Backups: {self._locked} locked, {self._waiting} waiting",
            *(f"  {state.line()}" for state in self._sets.values()),
        ]
        if self._in_progress:
            lines.append("In progress:")
            for ip, (stage, since) in sorted(self._in_progress.items()):
                lines.append(f"  {ip!s:<15}  {stage:<{_STAGE_LIMIT}}  {_elapsed(now - since)}")
        if self._attention:
            lines.append(f"Needs your attention (latest {ATTENTION_SHOWN}):")
            lines.extend(f"  {item}" for item in self._attention)
        if self._banner is not None:
            lines.append(self._banner)
        return lines

    def _redraw(self) -> None:
        self._erase()
        lines = self._panel()
        self._write("".join(f"{line}\n" for line in lines))
        self._drawn = len(lines)
        self._last_draw = self._clock()

    def _erase(self) -> None:
        if self._drawn:
            self._write(f"\x1b[{self._drawn}F\x1b[J")
            self._drawn = 0

    def _static(self, text: str) -> None:
        """Print a line that stays: above the panel in live mode, timestamped in log mode."""
        if self._mode is Mode.LIVE:
            redraw = self._drawn > 0
            self._erase()
            self._write(f"{text}\n")
            if redraw:
                self._redraw()
        elif self._mode is Mode.LOG:
            self._write(f"{self._stamp()} {text}\n")
        else:
            self._write(f"{text}\n")

    def _write(self, text: str) -> None:
        self._out.write(text)
        self._out.flush()

    def _stamp(self) -> str:
        return self._utc().astimezone(UTC).strftime("%H:%M:%SZ")


def _stop_banner(press: int, running: int) -> str:
    sessions = f"{running} session{'' if running == 1 else 's'}"
    if press == 1:
        return (
            f"!! Stopping: no new logins or probes. Waiting on {sessions} to finish. "
            "Press Ctrl+C again to close them at once."
        )
    return f"!! Closing {sessions} at once. Identified devices are kept as partial."


def _describe(event: ev.AuditEvent) -> str:
    """One log line: the Audit log's event name and its fields, every text escaped."""
    name, fields = run_output.AUDIT_SCHEMA.get(type(event), (type(event).__name__, ()))
    parts = [name]
    for field in fields:
        value = getattr(event, field)
        if value is None:
            continue
        if isinstance(value, Enum):
            value = value.value
        if isinstance(value, tuple):
            value = ",".join(str(v) for v in value)
        parts.append(f"{field}={_text(str(value), _TEXT_LIMIT)}")
    return " ".join(parts)


def _text(text: str, limit: int) -> str:
    return escape_controls(text, limit=limit)


def _elapsed(seconds: float) -> str:
    whole = max(0, int(seconds))
    hours, rest = divmod(whole, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}"
