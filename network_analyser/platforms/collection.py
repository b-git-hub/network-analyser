"""What one Platform's collection hands back to `device_gateway` (#59, #60; contract from #52).

The gateway gives a Platform's collector a `Send`: it sends one allow-listed command through
the gate and returns the reply, or `Unknown` when the command could not be sent or got no
reply (the session was dropped). The collector sends its commands, parses each reply into
the collected-record contract (`records.collected`) and returns a `Collection`: the
`Collected` record and the `Problem`s the gateway writes to the Audit log as `parse_failed`
events. A denied or unreadable command leaves its data unknown; it never ends the visit.
Nothing here keeps or quotes the replies (#30 section 8).
"""

from collections.abc import Callable
from dataclasses import dataclass

from network_analyser.records.collected import Collected
from network_analyser.records.unknown import Unknown

type Send = Callable[[str], str | Unknown]
"""Sends one allow-listed command and returns its reply; `Unknown` when there was none."""


@dataclass(frozen=True, slots=True)
class Problem:
    """A command whose reply gave no data, for the Audit log.

    Attributes:
        command: the command, exactly as sent.
        reason: why, as fixed text such as `denied` or `not understood`; never device text.
    """

    command: str
    reason: str


@dataclass(frozen=True, slots=True)
class Collection:
    """What a collector learned from one device.

    Attributes:
        collected: the collected record, every part a `Reading` or `Unknown`.
        problems: each command the device denied or whose reply was not understood.
        parser: the parser's name, for the Audit log's `parse_failed` events.
    """

    collected: Collected
    problems: tuple[Problem, ...]
    parser: str
