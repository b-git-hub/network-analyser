"""Stopping a Run: what Ctrl+C means to every visit under way (ticket #56; stories 82-84).

One `RunStop` per Run, shared by `cli` (which presses it), the crawl (which starts no new
visit once it is pressed) and each visit (which opens no new connection once it is
pressed).

- `stop_gracefully` (the first Ctrl+C): no new connection is opened, so no new login or
  probe starts; a session already open finishes its work within its timeouts. A wait
  before a connection retry ends at once, and the retry is not made.
- `close_now` (the second Ctrl+C): every connection still open is closed at once, from the
  caller's thread. A device already identified is left partial; one not yet identified is
  `not attempted (Run stopped)`. A config not yet whole is never a Backup (story 84).

`stop_gracefully` only stores a flag, taking no lock, so a signal handler may call it;
`close_now` closes connections, so it is called from ordinary code, never from inside a
signal handler.
"""

import contextlib
import threading
import time
from typing import Final, Protocol

CLOSED_BY_OPERATOR: Final = "the session was closed at the second Ctrl+C before it finished"
"""The fixed reason an identified device left by the second Ctrl+C is partial (story 83)."""
_PAUSE_SLICE_S: Final = 0.1
"""How often a pause looks at the stop flag."""


class Closeable(Protocol):
    """An open connection to a device: `link.Link` has this."""

    def close(self) -> None:
        """Close the connection."""
        ...


class RunStop:
    """Whether the operator asked the Run to stop, and the connections to close if so."""

    def __init__(self) -> None:
        """Nothing is stopping yet, and no connection is open."""
        self._requested = False
        self._closing = False
        self._lock = threading.Lock()
        self._open: list[Closeable] = []

    @property
    def requested(self) -> bool:
        """True once the Run is stopping: no new connection may be opened."""
        return self._requested

    @property
    def closing(self) -> bool:
        """True once every session is being closed at once (the second Ctrl+C)."""
        return self._closing

    @property
    def open_count(self) -> int:
        """How many connections are open now: the sessions a graceful stop waits on."""
        with self._lock:
            return len(self._open)

    def stop_gracefully(self) -> None:
        """Open no new connection from now on (the first Ctrl+C). Safe in a signal handler."""
        self._requested = True

    def close_now(self) -> None:
        """Close every open connection at once (the second Ctrl+C).

        One connection that fails to close does not keep the others open.
        """
        self._requested = True
        with self._lock:
            self._closing = True
            still_open, self._open = self._open, []
        for connection in still_open:
            with contextlib.suppress(Exception):  # it is being torn down either way
                connection.close()

    def pause(self, seconds: float) -> None:
        """Wait `seconds`, or less if the Run starts stopping meanwhile."""
        deadline = time.monotonic() + seconds
        while not self._requested:
            left = deadline - time.monotonic()
            if left <= 0:
                return
            time.sleep(min(left, _PAUSE_SLICE_S))

    def track(self, connection: Closeable) -> None:
        """Keep `connection`, to close it if every session is closed at once.

        A connection opened while sessions are being closed is closed at once.
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
                return
            del self._open[kept]
        connection.close()
