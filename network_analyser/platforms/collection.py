"""What one Platform's collection hands back to `device_gateway` (#59, #60; contract from #52).

The gateway gives a Platform's collector a `Send`: it sends one allow-listed command through
the gate and returns the reply, or `Unknown` when the command could not be sent or got no
reply (the session was dropped). The collector sends its commands, parses each reply into
the collected-record contract (`records.collected`) and returns a `Collection`: the
`Collected` record and the `Problem`s the gateway writes to the Audit log as `parse_failed`
events. A denied or unreadable command leaves its data unknown; it never ends the visit.
Nothing here keeps or quotes the replies (#30 section 8).

A denied command can also mean the device's Device Role predates it (#97, story 80): the
Role was generated from an older allow-list, so the view refuses the new command. Both
Platforms report a denied command as `<command>: denied`; `outdated_role` turns those into
one record naming the Check ids that could not run, and the platform module supplies the
command-to-Check map. `analysis.role` turns that record into the one Medium Finding per
device (#102).
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from typing import Final

from network_analyser.records.collected import Collected, Reading
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


DENIED_REASON: Final = "denied"
"""The fixed reason both Platforms give a command the device refused, after the command.

`ios_xe.replies.DENIED` and `nxos.json_reply.DENIED` are the same word, so a record's
`Unknown("<command>: denied")` can be read back here without importing either Platform.
"""
DEVICE_ROLE_CHECK: Final = "Device Role out of date"
"""The Check name the out-of-date Role Finding carries (story 80; #102 gives it an id)."""
DEVICE_ROLE_OUT_OF_DATE: Final = "Device Role is out of date"
"""The Finding's own opening words (story 80, and the Finding order in story 108)."""
DEVICE_ROLE_LEVEL: Final = "Medium"
"""Its level (spec #92, Levels). `analysis.role` now raises the Finding itself (#102)."""


@dataclass(frozen=True, slots=True)
class DeviceRoleOutOfDate:
    """One device's Device Role stopped some Checks because it predates their commands.

    This is the collection side's record; `analysis.role` turns it into one Medium Finding per
    device, naming every Check and pointing at `role-snippet` (story 80; #102).

    Attributes:
        commands: the refused allow-listed commands, in collection order.
        checks: the stable Check ids those commands would have fed, in the same order, without
            duplicates (#102's final ids, from the Platform's map).
    """

    commands: tuple[str, ...]
    checks: tuple[str, ...]

    @property
    def count(self) -> int:
        """How many Checks could not run."""
        return len(self.checks)


def denied_commands(collected: Collected) -> tuple[str, ...]:
    """Return every collection command the device refused, in collection order.

    A part the device denied is `Unknown("<command>: denied")`; inside a part that was
    partly read, the same text sits in its `gaps`. Nothing else counts: a reply the tool
    could not parse is a parser problem, not an out-of-date Role.
    """
    found: list[str] = []
    for field in fields(collected):
        found.extend(_denied_in(getattr(collected, field.name)))
    return tuple(dict.fromkeys(found))


def _denied_in(value: object) -> list[str]:
    """The commands denied in one part of `Collected`, whether it is whole or a gap."""
    unknown = value.gaps if isinstance(value, Reading) else (value,)
    return [
        command
        for one in unknown
        if isinstance(one, Unknown)
        and (command := one.reason.removesuffix(f": {DENIED_REASON}")) != one.reason
    ]


def outdated_role(
    collected: Collected, checks_by_command: Mapping[str, tuple[str, ...]]
) -> DeviceRoleOutOfDate | None:
    """Return the device's out-of-date Role record, or None when every mapped command ran.

    `checks_by_command` is the Platform's map from each allow-listed command to the Checks
    that need it. Only commands in that map count, so a denied command that no Check reads
    is not blamed on the Role.
    """
    commands = tuple(
        command for command in denied_commands(collected) if command in checks_by_command
    )
    checks = tuple(
        dict.fromkeys(name for command in commands for name in checks_by_command[command])
    )
    return DeviceRoleOutOfDate(commands, checks) if checks else None
