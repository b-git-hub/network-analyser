"""Pacing under Cisco's limits, and the one retry's wait (#95; story 19; ADR 0007).

openVuln allows 30 calls a minute, so two openVuln calls are never closer than two seconds.
Cisco publishes no figures for EoX and Software Suggestion, so they are paced at ten calls a
second, far under anything it has been seen to allow. The token is asked once.

`Retry-After` decides the one retry's wait when Cisco sends it. A wait longer than two minutes
is not taken: the source is marked unavailable instead, because a Run must not hang on Cisco.
A source that refuses a few calls in a row is not asked again, so a persistent limit cannot
walk the estate one value at a time (#154).
"""

import time
from collections.abc import Callable
from typing import Final

from network_analyser.advisories.numbers import whole_number
from network_analyser.records.cisco import CiscoEndpoint

OPENVULN_INTERVAL_S: Final = 2.0
"""30 calls a minute (story 19)."""

OTHER_INTERVAL_S: Final = 0.1
"""Ten calls a second: a fraction of what EoX and Software Suggestion have been seen to allow."""

INTERVAL_S: Final[dict[CiscoEndpoint, float]] = {
    CiscoEndpoint.TOKEN: 0.0,
    CiscoEndpoint.OPENVULN: OPENVULN_INTERVAL_S,
    CiscoEndpoint.EOX: OTHER_INTERVAL_S,
    CiscoEndpoint.SUGGESTION: OTHER_INTERVAL_S,
    CiscoEndpoint.COMPATIBLE: OTHER_INTERVAL_S,
}

DEFAULT_RETRY_WAIT_S: Final = 2.0
"""How long to wait before the one retry when Cisco sends no `Retry-After`."""

MAX_RETRY_WAIT_S: Final = 120.0
"""The longest `Retry-After` the tool will honour; beyond it, the source is unavailable."""

CONSECUTIVE_REFUSALS: Final = 3
"""How many calls in a row one source may refuse, with a limit or a 5xx, before it is stopped.

A shorter run than this can be one odd value; a persistent limit is not, and the values still
to be asked are answered with fixed text instead of being sent one at a time (#154).
"""


class Pacer:
    """Waits so Cisco's limits are never reached, counting what it waited for tests."""

    __slots__ = ("_clock", "_last", "_wait", "waits")

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[float], None] = time.sleep,
    ) -> None:
        """Use `clock` for time and `wait` to pause; tests replace both, so none waits."""
        self._clock = clock
        self._wait = wait
        self._last: dict[CiscoEndpoint, float] = {}
        self.waits: list[float] = []

    def now(self) -> float:
        """Return the clock's time, so the token's life is measured on the same clock."""
        return self._clock()

    def ready(self, endpoint: CiscoEndpoint) -> None:
        """Wait until `endpoint` may be called again."""
        interval = INTERVAL_S[endpoint]
        last = self._last.get(endpoint)
        if last is not None and interval > 0:
            remaining = interval - (self._clock() - last)
            if remaining > 0:
                self._pause(remaining)
        self._last[endpoint] = self._clock()

    def back_off(self, seconds: float) -> None:
        """Wait `seconds` before the one retry."""
        if seconds > 0:
            self._pause(seconds)

    def _pause(self, seconds: float) -> None:
        self.waits.append(seconds)
        self._wait(seconds)


def retry_delay(retry_after: str | None) -> float | None:
    """Return how long to wait before the one retry, or None when it would be too long.

    Cisco's `Retry-After` is whole seconds in ASCII digits; anything else, however odd, is
    treated as absent and never raises (#133).
    """
    seconds = None if retry_after is None else whole_number(retry_after.strip())
    if seconds is None:
        return DEFAULT_RETRY_WAIT_S
    return None if seconds > MAX_RETRY_WAIT_S else float(seconds)
