"""Every record in `records/` is plain data (CODING_STANDARDS.md "Data between modules"; #38, #52).

A record is a `@dataclass(frozen=True, slots=True)` whose fields hold only str, int, float,
bool, None, tuples, frozensets, read-only mappings, `ipaddress` objects, UTC datetimes, enums
and other records. Never a `Secret`, a callable, a socket, a file, a list or a dict: those
could carry a live session or a secret between modules, or be changed after hand-over.

The rule reads each field's type as written, so it also runs over planted records below,
which must be caught.
"""

import dataclasses
import datetime as dt
import importlib
import ipaddress
import pkgutil
import types
import typing
from collections.abc import Callable, Mapping
from enum import Enum

import network_analyser.records

_SCALARS = frozenset({str, int, float, bool, type(None)})
_IPADDRESS = frozenset(
    {
        ipaddress.IPv4Address,
        ipaddress.IPv6Address,
        ipaddress.IPv4Network,
        ipaddress.IPv6Network,
        ipaddress.IPv4Interface,
        ipaddress.IPv6Interface,
    }
)
_CONTAINERS = frozenset({tuple, frozenset, Mapping})


def record_classes() -> list[type]:
    """Every dataclass defined in a `records` module."""
    found: list[type] = []
    package = network_analyser.records
    for info in pkgutil.iter_modules(package.__path__, f"{package.__name__}."):
        module = importlib.import_module(info.name)
        found.extend(
            value
            for value in vars(module).values()
            if isinstance(value, type)
            and dataclasses.is_dataclass(value)
            and value.__module__ == module.__name__
        )
    return found


def record_problems(cls: type) -> list[str]:
    """Return why `cls` is not a plain-data record; empty when it is one."""
    name = cls.__qualname__
    problems: list[str] = []
    params = getattr(cls, "__dataclass_params__", None)
    if params is None or not params.frozen:
        problems.append(f"{name} is not frozen")
    if "__slots__" not in vars(cls):
        problems.append(f"{name} has no slots")
    hints = typing.get_type_hints(cls)
    for field in dataclasses.fields(cls):
        problems.extend(f"{name}.{field.name} {why}" for why in _type_problems(hints[field.name]))
    return problems


def _type_problems(hint: object) -> list[str]:  # noqa: PLR0911 (one return per kind of type)
    if isinstance(hint, typing.TypeAliasType):
        return _type_problems(hint.__value__)
    if isinstance(hint, typing.TypeVar):
        return []  # a generic record's parameter: checked where the record is used
    origin = typing.get_origin(hint)
    if origin is typing.Union or origin is types.UnionType:
        return [p for arg in typing.get_args(hint) for p in _type_problems(arg)]
    if origin is not None:
        if not (
            origin in _CONTAINERS or _is_record(origin) or isinstance(origin, typing.TypeAliasType)
        ):
            return [f"holds {hint!r}"]
        own = _type_problems(origin.__value__) if isinstance(origin, typing.TypeAliasType) else []
        args = (arg for arg in typing.get_args(hint) if arg is not Ellipsis)
        return own + [p for arg in args for p in _type_problems(arg)]
    if hint in _SCALARS or hint in _IPADDRESS or hint is dt.datetime:
        return []
    if isinstance(hint, type) and (issubclass(hint, Enum) or _is_record(hint)):
        return []
    return [f"holds {hint!r}"]


def _is_record(cls: object) -> bool:
    return isinstance(cls, type) and dataclasses.is_dataclass(cls)


def test_every_record_in_records_is_plain_data() -> None:
    classes = record_classes()

    assert len(classes) > 10  # the scan found the records
    assert [p for cls in classes for p in record_problems(cls)] == []


@dataclasses.dataclass(frozen=True, slots=True)
class _Good:
    name: str
    count: int | None
    addresses: tuple[ipaddress.IPv4Address, ...]
    vlans: frozenset[int]
    when: dt.datetime
    by_name: Mapping[str, int]


@dataclasses.dataclass(frozen=True, slots=True)
class _Generic[T]:
    value: T


@dataclasses.dataclass
class _Loose:
    names: list[str]
    lookup: dict[str, int]
    on_done: Callable[[], None]
    session: object
    nested: tuple[_Good | set[int], ...]
    held: _Generic[list[int]]


def test_a_planted_loose_record_is_caught() -> None:
    assert record_problems(_Good) == []
    assert record_problems(_Generic) == []
    problems = record_problems(_Loose)

    assert problems[:2] == ["_Loose is not frozen", "_Loose has no slots"]
    assert [p.split(" ", 1)[0] for p in problems[2:]] == [
        "_Loose.names",
        "_Loose.lookup",
        "_Loose.on_done",
        "_Loose.session",
        "_Loose.nested",
        "_Loose.held",
    ]
