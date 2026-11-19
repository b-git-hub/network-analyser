"""Ctrl+C during the crawl presses the Run's stop and never raises (ticket #56; story 82-83).

Tested through an injected `install` (no real signal is sent): the handler it receives is
called the way Python calls a SIGINT handler, on the main thread.
"""

import signal
from types import FrameType

import pytest

from network_analyser.cli import signals
from network_analyser.device_gateway import RunStop

type Handler = signals.Handler


class Installed:
    """Stands in for `signal.signal`: keeps each handler set, hands back the previous one."""

    def __init__(self) -> None:
        self.handlers: list[tuple[int, Handler]] = []
        self.current: Handler = signal.default_int_handler

    def __call__(self, signum: int, handler: Handler) -> Handler:
        previous, self.current = self.current, handler
        self.handlers.append((signum, handler))
        return previous

    def press(self) -> None:
        handler = self.current
        assert callable(handler)
        frame: FrameType | None = None
        handler(signal.SIGINT, frame)


def test_the_first_press_stops_gracefully_and_raises_nothing() -> None:
    stop = RunStop()
    installed = Installed()

    with signals.ctrl_c_presses(stop, install=installed):
        installed.press()  # would raise KeyboardInterrupt with the default handler

    assert installed.handlers[0][0] == signal.SIGINT
    assert stop.requested
    assert not stop.closing
    assert stop.presses == 1


def test_the_second_press_closes_and_later_presses_are_counted() -> None:
    stop = RunStop()
    installed = Installed()

    with signals.ctrl_c_presses(stop, install=installed):
        installed.press()
        installed.press()
        installed.press()

    assert stop.closing
    assert stop.presses == 3


def test_the_previous_handler_is_put_back_after_the_block() -> None:
    stop = RunStop()
    installed = Installed()

    with signals.ctrl_c_presses(stop, install=installed):
        pass

    assert installed.current is signal.default_int_handler


def test_the_previous_handler_is_put_back_after_an_error() -> None:
    stop = RunStop()
    installed = Installed()

    class InsideTheBlockError(Exception):
        pass

    with pytest.raises(InsideTheBlockError), signals.ctrl_c_presses(stop, install=installed):
        raise InsideTheBlockError

    assert installed.current is signal.default_int_handler
