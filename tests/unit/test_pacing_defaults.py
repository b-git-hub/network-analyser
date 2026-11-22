"""A default `Pacer` takes the clock and wait it finds, so no test waits for real (#149).

The Run's own online step builds a `Pacer` with no arguments, so `tests/conftest.py` injects a
fake clock for every test. That only works if the default is looked up when the `Pacer` is
made, never bound when the module is imported.
"""

import pytest

from network_analyser.advisories import pacing
from network_analyser.records.cisco import CiscoEndpoint


def test_a_default_pacer_uses_the_clock_and_wait_in_force_when_it_is_made(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [0.0]
    waits: list[float] = []

    def wait(seconds: float) -> None:
        waits.append(seconds)
        now[0] += seconds

    monkeypatch.setattr(pacing, "monotonic", lambda: now[0])
    monkeypatch.setattr(pacing, "sleep", wait)

    pacer = pacing.Pacer()
    pacer.ready(CiscoEndpoint.EOX)
    pacer.ready(CiscoEndpoint.EOX)

    assert waits == [pacing.OTHER_INTERVAL_S]
    assert pacer.now() == pacing.OTHER_INTERVAL_S
