"""Ctrl+C during the crawl (ticket #56; stories 82-83).

The handler is called directly here, as the interpreter would call it on SIGINT, so no
signal is ever raised in the test process.
"""

import signal

from network_analyser.cli import signals
from network_analyser.device_gateway import RunStop


class _Link:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


def test_the_first_press_stops_gracefully_at_once_and_closes_nothing() -> None:
    stop = RunStop()
    link = _Link()
    stop.track(link)
    ctrl_c = signals.CtrlC(stop)

    ctrl_c.on_signal(signal.SIGINT, None)

    assert stop.requested
    assert not stop.closing
    assert link.closed == 0


def test_each_press_is_handled_once_in_order_on_the_main_thread() -> None:
    stop = RunStop()
    ctrl_c = signals.CtrlC(stop)
    seen: list[int] = []
    ctrl_c.on_signal(signal.SIGINT, None)

    ctrl_c.handle(seen.append)
    ctrl_c.handle(seen.append)

    assert seen == [1]


def test_the_second_press_closes_every_session_after_it_is_announced() -> None:
    stop = RunStop()
    link = _Link()
    stop.track(link)
    ctrl_c = signals.CtrlC(stop)
    closed_when_announced: list[int] = []

    ctrl_c.on_signal(signal.SIGINT, None)
    ctrl_c.on_signal(signal.SIGINT, None)
    ctrl_c.handle(lambda _press: closed_when_announced.append(link.closed))

    assert closed_when_announced == [0, 0]
    assert link.closed == 1
    assert stop.closing


def test_the_handler_is_installed_only_for_the_block() -> None:
    before = signal.getsignal(signal.SIGINT)

    with signals.ctrl_c_stops(RunStop()) as ctrl_c:
        assert signal.getsignal(signal.SIGINT) == ctrl_c.on_signal

    assert signal.getsignal(signal.SIGINT) == before


def test_presses_are_counted() -> None:
    ctrl_c = signals.CtrlC(RunStop())

    for _ in range(3):
        ctrl_c.on_signal(signal.SIGINT, None)

    assert ctrl_c.presses == 3
