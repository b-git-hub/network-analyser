"""How the IOS/IOS-XE collector asks for data and notes what it could not get (#59).

The gateway hands the collector a `platforms.collection.Send`. The collector asks through an
`Asker`, which classifies each reply (`ios_xe.replies`) before a reader sees it, and builds
each part of `records.collected.Collected` with a `Part`: a `Reading` of the commands that
answered, with a gap for each that did not, or `Unknown` when none did.

A denied command, or a reply no reader understands, is a `Problem` for the Audit log, with
fixed text as its reason (`denied`, `not understood`); the reply itself is never kept. A reply
of `Unknown` (the session was dropped) is passed on as it is: the gateway has recorded it.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from network_analyser.platforms.collection import Problem, Send
from network_analyser.platforms.ios_xe import replies
from network_analyser.records.collected import Reading
from network_analyser.records.unknown import Unknown

NOT_UNDERSTOOD: Final = "not understood"


class Asker:
    """Asks a device for data through `send`, once per command; used by one collection."""

    def __init__(self, send: Send) -> None:
        """Ask through `send`; nothing is sent until `ask`."""
        self._send = send
        self._replies: dict[str, str | Unknown] = {}
        self.problems: list[Problem] = []

    def ask[T](
        self,
        command: str,
        read: Callable[[str], T | None],
        *,
        off: T | Unknown | None = None,
    ) -> T | Unknown:
        """Send `command` (once, however often it is asked for) and read its reply.

        Args:
            command: the exact allow-listed command.
            read: turns the reply into a value; None when it does not understand it.
            off: what a "feature not enabled or running" reply means, such as no BGP
                neighbours; None when such a reply is not understood.

        Returns:
            The value, or `Unknown` naming the command: not sent, denied, or not understood.
        """
        if command not in self._replies:
            self._replies[command] = self._send(command)
        reply = self._replies[command]
        if isinstance(reply, Unknown):
            return reply
        if replies.is_denied(reply):
            return self._problem(command, replies.DENIED)
        if off is not None and replies.is_feature_off(reply):
            return off
        value = None if replies.is_error(reply) else read(reply)
        if value is None:
            return self._problem(command, NOT_UNDERSTOOD)
        return value

    def _problem(self, command: str, reason: str) -> Unknown:
        problem = Problem(command, reason)
        if problem not in self.problems:  # one reply read for two parts is one problem
            self.problems.append(problem)
        return Unknown(f"{command}: {reason}")


@dataclass
class Part:
    """One part of `Collected` being built: the commands that answered and the gaps."""

    commands: list[str] = field(default_factory=list)
    gaps: list[Unknown] = field(default_factory=list)

    def take[T](self, command: str, value: T | Unknown) -> T | None:
        """Note what `command` gave: its value, or a gap (then None)."""
        if isinstance(value, Unknown):
            self.gaps.append(value)
            return None
        if command not in self.commands:
            self.commands.append(command)
        return value

    def gap(self, reason: str) -> None:
        """Note something this part could not read, as fixed text."""
        self.gaps.append(Unknown(reason))

    def reading[T](self, value: T) -> Reading[T] | Unknown:
        """Return `value` with its evidence, or the first gap when no command answered."""
        if not self.commands:
            return self.gaps[0] if self.gaps else Unknown(NOT_UNDERSTOOD)
        return Reading(tuple(self.commands), value, tuple(self.gaps))
