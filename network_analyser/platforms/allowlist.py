"""The shape of a compiled-in command allow-list (spec #37 stories 53-56; ADR 0005).

An entry is an exact string, or a template whose parameters must each match a strict
pattern (story 54), so no command can be smuggled in through a parameter. A command is
permitted only when it equals an exact entry, or fills a template in full. Nothing here
reads a file or the environment: every allow-list is literals in its Platform module
(story 56).
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

_PLACEHOLDER: Final = re.compile(r"\{([a-z_]+)\}")


@dataclass(frozen=True, slots=True)
class Exact:
    """A command permitted exactly as written."""

    command: str


@dataclass(frozen=True, slots=True)
class Template:
    """A command with parameters, such as `show user-account {username}`.

    Attributes:
        text: the command, with each parameter as `{name}`.
        parameters: each parameter's pattern. A pattern must not match a space, so a
            parameter is always one word; it is matched in full, ASCII only.
    """

    text: str
    parameters: Mapping[str, str]

    def __post_init__(self) -> None:
        """Refuse a template whose placeholders and parameters differ, or that has none."""
        named = _PLACEHOLDER.findall(self.text)
        if not named or sorted(named) != sorted(self.parameters):
            msg = "a template's placeholders must be exactly its parameters"
            raise ValueError(msg)
        if any(re.fullmatch(p, " ", flags=re.ASCII) for p in self.parameters.values()):
            msg = "a template parameter must never match a space"
            raise ValueError(msg)
        # Read-only from here on, so the compiled-in list cannot be widened at run time.
        object.__setattr__(self, "parameters", MappingProxyType(dict(self.parameters)))

    def fill(self, **values: str) -> str | None:
        """Return the command with these values, or None when one breaks its pattern."""
        if sorted(values) != sorted(self.parameters):
            return None
        for name, value in values.items():
            if not re.fullmatch(self.parameters[name], value, flags=re.ASCII):
                return None
        return _PLACEHOLDER.sub(lambda m: values[m.group(1)], self.text)

    def matches(self, command: str) -> bool:
        """Say whether `command` is this template filled with values that fit."""
        pieces = _PLACEHOLDER.split(self.text)
        pattern = "".join(
            re.escape(piece) if index % 2 == 0 else f"(?P<{piece}>{self.parameters[piece]})"
            for index, piece in enumerate(pieces)
        )
        return re.fullmatch(pattern, command, flags=re.ASCII) is not None


type Entry = Exact | Template


@dataclass(frozen=True, slots=True)
class AllowList:
    """One Platform's commands: the only text ever sent to its devices."""

    entries: tuple[Entry, ...]

    def permits(self, command: str) -> bool:
        """Say whether `command` may be sent, exactly as given."""
        return any(
            command == entry.command if isinstance(entry, Exact) else entry.matches(command)
            for entry in self.entries
        )

    @property
    def exact_commands(self) -> frozenset[str]:
        """The exact-string entries."""
        return frozenset(e.command for e in self.entries if isinstance(e, Exact))
