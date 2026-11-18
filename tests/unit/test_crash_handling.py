"""An internal error shows its type and a file:line stack only (spec #37, story 91)."""

import argparse
import re
import sys
import threading

import pytest

from network_analyser.cli import ExitCode, install_crash_hooks, main
from network_analyser.cli.commands import COMMANDS

CANARY = "canary-Pa55w0rd-7c2b"


class DeviceSaidError(Exception):
    pass


def _fails_holding_a_secret(_args: argparse.Namespace) -> ExitCode:
    password = CANARY
    msg = f"device echoed: {password}"
    raise DeviceSaidError(msg)


def test_a_crash_exits_4_with_the_type_and_file_line_stack_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(COMMANDS, "render", _fails_holding_a_secret)

    code = main(["render", "runs/x"])

    captured = capsys.readouterr()
    assert code == ExitCode.INTERNAL_ERROR
    assert CANARY not in captured.out + captured.err
    assert "device echoed" not in captured.err
    assert "DeviceSaidError" in captured.err
    assert re.search(r"test_crash_handling\.py:\d+\n", captured.err)
    assert re.search(r"network_analyser/cli/app\.py:\d+\n", captured.err)
    assert "Traceback" not in captured.err


def test_ctrl_c_during_a_command_exits_3_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def interrupted(_args: argparse.Namespace) -> ExitCode:
        raise KeyboardInterrupt

    monkeypatch.setitem(COMMANDS, "render", interrupted)

    code = main(["render", "runs/x"])

    assert code == ExitCode.STOPPED
    assert "Traceback" not in capsys.readouterr().err


def test_an_uncaught_error_in_a_thread_shows_no_exception_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    monkeypatch.setattr(sys, "unraisablehook", sys.unraisablehook)
    install_crash_hooks()

    worker = threading.Thread(target=_fails_holding_a_secret, args=(argparse.Namespace(),))
    worker.start()
    worker.join()

    err = capsys.readouterr().err
    assert CANARY not in err
    assert "DeviceSaidError" in err
    assert "Traceback" not in err
