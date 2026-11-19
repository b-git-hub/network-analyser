"""Stopping a Run: what Ctrl+C means to every visit under way (ticket #56; stories 82-84).

One `RunStop` per Run, shared by `cli` (whose Ctrl+C handler presses it), the crawl (which
starts no new visit once it is pressed, and closes the sessions after the second press)
and each visit (which opens no new connection once it is pressed).

- The first `press` (the first Ctrl+C): no new connection is opened, so no new login or
  probe starts, no connection is retried and no next Credential Set is tried; a session
  already open finishes its work within its timeouts.
- The second `press`: every session stops at its next step, and `close_now` (called by the
  crawl from ordinary code) closes every connection still open. A device already
  identified is left partial; one not yet identified is `not attempted (Run stopped)`. A
  config not yet whole is never a Backup (story 84).
- `halt(reason)`: the Run stops for a reason that is not the operator's, such as the Trust
  Store that cannot be written; it works like the first press.

`press` only counts and sets plain flags (no lock, no I/O), so a signal handler may call it
whatever the main thread is doing. Worker threads only read the flags.
"""

import threading
import time
from typing import Final, Protocol

CLOSED_BY_OPERATOR: Final = "the session was closed at the second Ctrl+C before it finished"
"""The fixed reason an identified device left by the second Ctrl+C is partial (story 83)."""
_PAUSE_SLICE_S: Final = 0.25


class Closeable(Protocol):
    """An open connection to a device: `link.Link` has this."""

    def close(self) -> None:
        """Close the connection."""
        ...


class RunStop:
    """Whether the Run is stopping, and the connections to close if every session must."""

    def __init__(self) -> None:
        """Nothing is stopping yet, and no connection is open."""
        self._presses = 0
        self._requested = False
        self._closing = False
        self._reason: str | None = None
        self._audited = 0
        self._lock = threading.Lock()
        self._open: list[Closeable] = []

    @property
    def requested(self) -> bool:
        """True once the Run is stopping: no new connection may be opened."""
        return self._requested

    @property
    def closing(self) -> bool:
        """True once every session is to close at once (the second Ctrl+C)."""
        return self._closing

    @property
    def presses(self) -> int:
        """How many times the operator pressed Ctrl+C."""
        return self._presses

    @property
    def reason(self) -> str | None:
        """The fixed reason given to `halt`; None when the stop is the operator's, or none."""
        return self._reason

    def press(self) -> None:
        """Count one Ctrl+C: the first stops gracefully, the second closes every session.

        Safe in a signal handler: plain assignments only.
        """
        self._presses += 1
        self._requested = True
        if self._presses >= 2:  # noqa: PLR2004 (the second press)
            self._closing = True

    def halt(self, reason: str) -> None:
        """Stop the Run for `reason` (fixed text): no new connection from now on."""
        if self._reason is None and not self._requested:
            self._reason = reason
        self._requested = True

    def presses_to_audit(self) -> range:
        """The press numbers not yet handed out, to be audited once each. Main thread only."""
        pressed = self._presses
        new = range(self._audited + 1, pressed + 1)
        self._audited = pressed
        return new

    def close_now(self) -> None:
        """Close every open connection at once. Ordinary code only, never a signal handler."""
        self._requested = True
        self._closing = True
        with self._lock:
            still_open, self._open = self._open, []
        for connection in still_open:
            connection.close()

    def pause(self, seconds: float) -> None:
        """Wait `seconds`, or less if the Run starts stopping meanwhile."""
        until = time.monotonic() + seconds
        while not self._requested:
            left = until - time.monotonic()
            if left <= 0:
                return
            time.sleep(min(_PAUSE_SLICE_S, left))

    def track(self, connection: Closeable) -> None:
        """Keep `connection`, to close it if every session is closed at once.

        A connection opened once sessions are being closed is closed at once.
        """
        with self._lock:
            if not self._closing:
                self._open.append(connection)
                return
        connection.close()

    def release(self, connection: Closeable) -> None:
        """Close `connection`, unless `close_now` already closed it."""
        with self._lock:
            kept = next((i for i, c in enumerate(self._open) if c is connection), None)
            if kept is None:
                closed_already = self._closing
            else:
                del self._open[kept]
                closed_already = False
        if not closed_already:
            connection.close()
