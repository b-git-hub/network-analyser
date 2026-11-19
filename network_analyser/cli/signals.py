"""Ctrl+C during a Run's crawl: each press goes to the Run's stop (ticket #56; stories 82-83).

While the crawl runs, SIGINT does not raise `KeyboardInterrupt` (which would land in the
main thread while the visits' threads carry on, and leave sessions half done). Instead the
handler presses the Run's `RunStop`: the first press stops gracefully, the second closes
every session at once. The handler only counts and sets flags, so it is safe whatever the
main thread was doing; the crawl audits each press and closes the sessions itself.
"""

import signal
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from types import FrameType

from network_analyser.device_gateway import RunStop

type Handler = Callable[[int, FrameType | None], object] | int | signal.Handlers | None
type Install = Callable[[int, Handler], Handler]


@contextmanager
def ctrl_c_presses(stop: RunStop, install: Install | None = None) -> Iterator[None]:
    """Inside the block, each Ctrl+C presses `stop` instead of raising `KeyboardInterrupt`.

    `install` sets a signal handler and returns the one before (`signal.signal` unless a
    test replaces it). Python only lets the main thread set one; elsewhere the block
    changes nothing.
    """
    if install is None:
        if threading.current_thread() is not threading.main_thread():
            yield
            return
        install = _install

    def press(_signum: int, _frame: FrameType | None) -> None:
        stop.press()

    previous = install(signal.SIGINT, press)
    try:
        yield
    finally:
        install(signal.SIGINT, previous)


def _install(signum: int, handler: Handler) -> Handler:
    return signal.signal(signum, handler)
