"""`RunStop`, the Run's Ctrl+C state, on its own (ticket #56; stories 82-83)."""

import time

from network_analyser.device_gateway import RunStop


class _Link:
    def __init__(self, closed: list[str], name: str, *, fails: bool = False) -> None:
        self.closed = closed
        self.name = name
        self.fails = fails

    def close(self) -> None:
        self.closed.append(self.name)
        if self.fails:
            msg = "the socket was already gone"
            raise OSError(msg)


def test_nothing_is_stopping_at_first() -> None:
    stop = RunStop()

    assert not stop.requested
    assert not stop.closing
    assert stop.open_count == 0


def test_the_first_ctrl_c_opens_nothing_new_and_closes_nothing() -> None:
    closed: list[str] = []
    stop = RunStop()
    stop.track(_Link(closed, "a"))

    stop.stop_gracefully()

    assert stop.requested
    assert not stop.closing
    assert closed == []
    assert stop.open_count == 1


def test_one_connection_failing_to_close_does_not_keep_the_rest_open() -> None:
    closed: list[str] = []
    stop = RunStop()
    for link in (_Link(closed, "a"), _Link(closed, "b", fails=True), _Link(closed, "c")):
        stop.track(link)

    stop.close_now()

    assert closed == ["a", "b", "c"]
    assert stop.open_count == 0


def test_a_connection_opened_while_closing_is_closed_at_once() -> None:
    closed: list[str] = []
    stop = RunStop()
    stop.close_now()

    stop.track(_Link(closed, "late"))

    assert closed == ["late"]
    assert stop.open_count == 0


def test_releasing_a_connection_closes_it_once() -> None:
    closed: list[str] = []
    stop = RunStop()
    link = _Link(closed, "a")
    stop.track(link)

    stop.release(link)
    stop.release(link)

    assert closed == ["a"]


def test_a_pause_ends_early_once_the_run_is_stopping() -> None:
    stop = RunStop()
    stop.stop_gracefully()

    started = time.monotonic()
    stop.pause(30)

    assert time.monotonic() - started < 1
