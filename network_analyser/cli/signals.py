"""Ctrl+C during the crawl: count the presses, stop the Run (ticket #56; stories 82-83).

While the crawl runs, SIGINT does not raise `KeyboardInterrupt`: an exception thrown into
the main thread while it waits on the visit pool would abandon the visits without closing
their sessions or locking the Backups already captured. Instead the handler only counts
the press and sets the Run's stop flag (`RunStop.stop_gracefully`, which takes no lock),
which is all a signal handler may safely do.

The main thread calls `CtrlC.handle` on every crawl tick: each new press is announced and
audited there, and the second press then closes every session at once
(`RunStop.close_now`), from ordinary code. Before and after the crawl, Ctrl+C is the
interpreter's `KeyboardInterrupt` again (exit 3).
"""

import signal
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from types import FrameType
from typing import Final

from network_analyser.device_gateway import RunStop

CLOSE_NOW_PRESS: Final = 2
"""The press that closes every session at once."""


class CtrlC:
    """The Ctrl+C presses of one crawl, and what each one does."""

    def __init__(self, stop: RunStop) -> None:
        """Count presses against `stop`, the Run's shared stop state."""
        self._stop = stop
        self._presses = 0
        self._handled = 0

    @property
    def presses(self) -> int:
        """How many times Ctrl+C was pressed during the crawl."""
        return self._presses

    def on_signal(self, _signum: int, _frame: FrameType | None) -> None:
        """The SIGINT handler: count the press and stop new logins. Nothing else."""
        self._presses += 1
        self._stop.stop_gracefully()

    def handle(self, announce: Callable[[int], None]) -> None:
        """Announce each press not yet handled (1, 2, ...); close every session at the 2nd.

        Call on the main thread, never from the signal handler.
        """
        while self._handled < self._presses:
            self._handled += 1
            announce(self._handled)
            if self._handled == CLOSE_NOW_PRESS:
                self._stop.close_now()


@contextmanager
def ctrl_c_stops(stop: RunStop) -> Iterator[CtrlC]:
    """Inside the block, Ctrl+C stops the Run through `stop` instead of raising."""
    ctrl_c = CtrlC(stop)
    previous = signal.signal(signal.SIGINT, ctrl_c.on_signal)
    try:
        yield ctrl_c
    finally:
        signal.signal(signal.SIGINT, previous)
