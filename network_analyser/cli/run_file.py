"""The TOML run file given with `--from` (spec #37 stories 2, 12-13; decision #31).

It holds only `label`, `scope`, `exclude`, `seeds`, `parallel`, `failure_budget` and `sweep`.
It is checked strictly and fails closed: a key that looks like a secret, `runs_dir`, any
other unknown key, or a value of the wrong kind refuses the Run. Values are never echoed,
and neither is the parser's error text, in case a line holds a secret typed by mistake.
"""

import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from network_analyser import run_output
from network_analyser.cli.parser import FAILURE_BUDGET_MAX, PARALLEL_MAX
from network_analyser.cli.text import escape_controls

RUN_FILE_KEYS = ("label", "scope", "exclude", "seeds", "parallel", "failure_budget", "sweep")

# The same names `tests/unit/test_cli.py` keeps out of the option list.
_SECRET_LIKE = re.compile(r"pass|secret|key(?!s)|token|pwd|credential", re.IGNORECASE)
_RUNS_DIR = "runs_dir"
_LARGEST_FILE = 64 * 1024
_SECRETS = (
    "A run file never holds secrets (story 12): Credential Set passwords and the Backup "
    "Passphrase are only ever typed at the hidden prompts. Remove these keys:"
)


@dataclass(frozen=True, slots=True)
class RunFile:
    """The settings a run file gave; None means the file left that setting out."""

    path: str
    label: str | None = None
    scope: tuple[str, ...] | None = None
    exclude: tuple[str, ...] | None = None
    seeds: tuple[str, ...] | None = None
    parallel: int | None = None
    failure_budget: int | None = None
    sweep: bool | None = None


@dataclass(frozen=True, slots=True)
class RunFileRefused:
    """The run file was refused; every problem is listed, without any value from the file."""

    path: str
    problems: tuple[str, ...]


def load(path: str) -> RunFile | RunFileRefused:
    """Read and check a run file."""
    data = _read(path)
    if isinstance(data, RunFileRefused):
        return data
    problems = _key_problems(data)
    if problems:
        return RunFileRefused(path, problems)
    checked = {key: _check_value(key, value) for key, value in data.items()}
    problems = tuple(f"{k}: {v.text}" for k, v in checked.items() if isinstance(v, _Problem))
    if problems:
        return RunFileRefused(path, problems)
    return RunFile(
        path=path,
        label=_get(checked, "label", str),
        scope=_get(checked, "scope", tuple),
        exclude=_get(checked, "exclude", tuple),
        seeds=_get(checked, "seeds", tuple),
        parallel=_get(checked, "parallel", int),
        failure_budget=_get(checked, "failure_budget", int),
        sweep=_get(checked, "sweep", bool),
    )


def _get[T](checked: dict[str, object], key: str, kind: type[T]) -> T | None:
    value = checked.get(key)
    return value if isinstance(value, kind) else None


def _read(path: str) -> dict[str, object] | RunFileRefused:
    try:
        with Path(path).open("rb") as file:
            raw = file.read(_LARGEST_FILE + 1)
    except OSError:
        return RunFileRefused(path, ("the file cannot be read",))
    if len(raw) > _LARGEST_FILE:
        return RunFileRefused(path, (f"the file is larger than {_LARGEST_FILE // 1024} KiB",))
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return RunFileRefused(path, ("the file is not UTF-8 text",))
    except tomllib.TOMLDecodeError as error:
        return RunFileRefused(path, (f"the file is not valid TOML (line {error.lineno})",))


def _key_problems(data: dict[str, object]) -> tuple[str, ...]:
    secret_keys = [name for name in _every_key(data) if _SECRET_LIKE.search(name)]
    if secret_keys:
        return (_SECRETS + " " + ", ".join(escape_controls(k) for k in secret_keys),)
    problems: list[str] = []
    for key in data:
        if key.lower().replace("-", "_") == _RUNS_DIR:
            problems.append(
                f"{escape_controls(key)}: the Runs folder is set only with --runs-dir on the "
                "command line, so where outputs go never changes unnoticed (story 13)"
            )
        elif key not in RUN_FILE_KEYS:
            problems.append(
                f"{escape_controls(key)}: not a run file key "
                f"(a run file may hold only {', '.join(RUN_FILE_KEYS)})"
            )
    return tuple(problems)


def _every_key(value: object) -> Iterator[str]:
    """Yield every key in a TOML document, nested tables and arrays of tables included."""
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key)
            yield from _every_key(inner)
    elif isinstance(value, list):
        for item in value:
            yield from _every_key(item)


@dataclass(frozen=True, slots=True)
class _Problem:
    text: str


def _check_value(key: str, value: object) -> object:
    match key:
        case "label":
            if not isinstance(value, str):
                return _Problem("must be text")
            problem = run_output.label_problem(value)  # the Run folder name rules (#42)
            return value if problem is None else _Problem(problem)
        case "scope" | "exclude" | "seeds":
            return _text_list(value, may_be_empty=key == "exclude")
        case "parallel":
            return _whole_number(value, PARALLEL_MAX)
        case "failure_budget":
            return _whole_number(value, FAILURE_BUDGET_MAX)
        case _:  # "sweep": the keys were checked before the values
            return value if isinstance(value, bool) else _Problem("must be true or false")


def _text_list(value: object, *, may_be_empty: bool) -> tuple[str, ...] | _Problem:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return _Problem("must be a list of text entries")
    if not value and not may_be_empty:
        return _Problem("must not be empty")
    return tuple(str(item) for item in value)


def _whole_number(value: object, high: int) -> int | _Problem:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= high:
        return _Problem(f"must be a whole number from 1 to {high}")
    return value
