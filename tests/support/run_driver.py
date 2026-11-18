"""Drive `network-analyser run` as the operator would, with what they type on stdin.

Standard input is not a console in tests, so every prompt (the hidden ones too) reads one
line. On Linux the crash-dump guard cannot read the registry, so it always asks for `YES`.
The secrets are synthetic canaries; `use_fake_age` keeps the check file fast.
"""

import io
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from network_analyser import run_output
from network_analyser.cli import main

BACKUP_CANARY = "CANARY-pp-4e7a-backup"
DEVICE_CANARY = "CANARY-pw-7c1d-device"
FLAGS = ("--scope", "192.0.2.0/24", "--seed", "192.0.2.1")


@dataclass(frozen=True)
class Outcome:
    code: int
    out: str
    err: str


def typed(*lines: str) -> str:
    """Return what the operator types: each line followed by Enter."""
    return "".join(f"{line}\n" for line in lines)


def first_run(*, start: str = "y") -> str:
    """Answers for a first Run with one Credential Set, after the Scope and Seeds."""
    return typed("YES", BACKUP_CANARY, BACKUP_CANARY, "netops-ro", DEVICE_CANARY, "", "n", start)


def later_run(*, start: str = "y") -> str:
    """Answers for a Run once the check file exists, after the Scope and Seeds."""
    return typed("YES", BACKUP_CANARY, "netops-ro", DEVICE_CANARY, "", "n", start)


class Runner:
    """Runs `network-analyser run` with what the operator types on stdin."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        self._monkeypatch = monkeypatch
        self._capsys = capsys

    def __call__(self, *argv: str, typed: str = "") -> Outcome:
        self._monkeypatch.setattr("sys.stdin", io.StringIO(typed))
        code = main(["run", *argv])
        captured = self._capsys.readouterr()
        return Outcome(code, captured.out, captured.err)


def data_folder() -> run_output.DataFolder:
    """The per-user data folder conftest.py gives this test."""
    return run_output.locate_data_folder(Path(os.environ["LOCALAPPDATA"]))
