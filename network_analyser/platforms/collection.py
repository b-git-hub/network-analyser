"""How a Platform's collectors ask for data and record what they could not get (#59, #60).

`device_gateway` hands a collector a `Send`: one allow-listed command in, its output out, or
`Unknown` when it was not sent (the session was dropped). A collector asks through an
`Asker`, which classifies each reply (`platforms.replies`) before a reader sees it, and
builds each part of `records.collected.Collected` with a `Part`: a `Reading` of the commands
that answered, with a gap for each that did not, or `Unknown` when none did.

Every reason is fixed text that names the command, such as `show vlan brief: denied or not
supported by the device`; none quotes device output. A reply the reader does not understand
is also a `ParseProblem`, which the gateway records in the Audit log as `parse_failed`
(#30 section 8); the output itself is never kept.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

from network_analyser.platforms import replies
from network_analyser.records.collected import Collected, Reading
from network_analyser.records.unknown import Unknown

type Send = Callable[[str], str | Unknown]
"""Send one allow-listed command; return its output, or `Unknown(reason)` if it was not."""

NOT_UNDERSTOOD = "not understood"


@dataclass(frozen=True, slots=True)
class ParseProblem:
    """A reply a reader could not understand, for the Audit log: never the reply itself.

    Attributes:
        command: the command, exactly as sent.
        parser: the reader's name, such as `ntc-templates cisco_ios`.
        reason: why, as fixed text.
    """

    command: str
    parser: str
    reason: str


@dataclass(frozen=True, slots=True)
class Collection:
    """What a Platform's collector learned, and the replies it could not read.

    Attributes:
        collected: every part, each a `Reading` or `Unknown`.
        parse_problems: one per reply that was not understood, in the order asked.
    """

    collected: Collected
    parse_problems: tuple[ParseProblem, ...] = ()


class Asker:
    """Asks a device for data through `send`, once per command; used by one collection."""

    def __init__(self, send: Send) -> None:
        """Ask through `send`; nothing is sent until `ask`."""
        self._send = send
        self._replies: dict[str, str | Unknown] = {}
        self.problems: list[ParseProblem] = []

    def ask[T](
        self,
        command: str,
        read: Callable[[str], T | None],
        *,
        parser: str,
        off: T | Unknown | None = None,
    ) -> T | Unknown:
        """Send `command` (once, however often it is asked for) and read its reply.

        Args:
            command: the exact allow-listed command.
            read: turns the reply into a value; None when it does not understand it.
            parser: the reader's name, for a `ParseProblem`.
            off: what a "feature not enabled or running" reply means, such as no BGP
                neighbours; None when such a reply is not understood.

        Returns:
            The value, or `Unknown` naming the command: not sent, denied, or not understood.
        """
        if command not in self._replies:
            self._replies[command] = self._send(command)
        reply = self._replies[command]
        if isinstance(reply, Unknown):
            return Unknown(f"{command}: {reply.reason}")
        if replies.is_denied(reply):
            return Unknown(f"{command}: {replies.DENIED}")
        if off is not None and replies.is_feature_off(reply):
            return off
        value = None if replies.is_error(reply) else read(reply)
        if value is None:
            problem = ParseProblem(command, parser, NOT_UNDERSTOOD)
            if problem not in self.problems:  # one reply read for two parts is one problem
                self.problems.append(problem)
            return Unknown(f"{command}: {NOT_UNDERSTOOD}")
        return value


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


def nothing_collected(reason: str) -> Collection:
    """A `Collection` with every part unknown for `reason`."""
    return Collection(Collected.nothing(reason))
