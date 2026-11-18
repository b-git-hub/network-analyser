"""The masked prompt: one `*` per character, and nothing typed ever shown (spec #37, 25-26, 29).

The real console needs Windows, so these tests drive the reader through a fake console that
hands out key codes the way `msvcrt.getwch()` does.
"""

import argparse
import io
from collections.abc import Iterable

import pytest

from network_analyser.cli import ExitCode, main
from network_analyser.cli.commands import COMMANDS
from network_analyser.cli.prompts import Prompter
from network_analyser.credentials import Secret

CANARY = "CANARY-pw-7f3a"


class FakeConsole:
    """Hands out key codes like `msvcrt.getwch()`, and records what is written."""

    def __init__(self, keys: Iterable[str]) -> None:
        self._keys = iter(keys)
        self.shown = ""

    def read_key(self) -> str:
        return next(self._keys)

    def write(self, text: str) -> None:
        self.shown += text


def _prompter(console: FakeConsole) -> Prompter:
    return Prompter(console=console, stdin=io.StringIO(), stderr=io.StringIO())


def test_each_character_shows_one_star_and_the_secret_holds_what_was_typed() -> None:
    console = FakeConsole([*CANARY, "\r"])

    secret = _prompter(console).secret("Password for netops-ro: ")

    assert isinstance(secret, Secret)
    assert secret.same_as(Secret(CANARY))
    assert console.shown == "Password for netops-ro: " + "*" * len(CANARY) + "\r\n"


def test_backspace_removes_the_last_character_and_its_star() -> None:
    console = FakeConsole(["\x08", "a", "b", "x", "\x08", "c", "\r"])

    secret = _prompter(console).secret("> ")

    assert secret.same_as(Secret("abc"))
    assert console.shown == "> ***\b \b*\r\n"


def test_arrow_and_function_keys_put_nothing_into_the_secret() -> None:
    # getwch() gives an arrow or function key as a prefix (\x00 or \xe0) then a second code;
    # the second code is often a plain letter: "K" is Left, "H" is Up, ";" is F1.
    left, up, f1, f11 = ["\xe0", "K"], ["\xe0", "H"], ["\x00", ";"], ["\xe0", "\x85"]
    console = FakeConsole(["a", *left, "b", *up, *f1, *f11, "c", "\r"])

    secret = _prompter(console).secret("> ")

    assert secret.same_as(Secret("abc"))
    assert console.shown == "> ***\r\n"


def test_other_control_codes_are_dropped_but_any_printable_character_is_kept() -> None:
    # Tab, Escape, Ctrl+V (when the console does not paste on it), Ctrl+Z, DEL and a C1 code.
    controls = ["\t", "\x1b", "\x16", "\x1a", "\x7f", "\x9b"]
    console = FakeConsole(["a", *controls, "é", " ", "ß", "\r"])

    secret = _prompter(console).secret("> ")

    assert secret.same_as(Secret("aé ß"))
    assert console.shown == "> ****\r\n"


def test_ctrl_c_at_a_secret_prompt_cancels_with_exit_3_and_no_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    console = FakeConsole([*CANARY, "\x03", "never", "read"])

    def asks_for_a_password(_args: argparse.Namespace) -> ExitCode:
        _prompter(console).secret("Backup Passphrase: ")
        return ExitCode.CLEAN

    monkeypatch.setitem(COMMANDS, "change-passphrase", asks_for_a_password)

    code = main(["change-passphrase"])

    captured = capsys.readouterr()
    assert code == ExitCode.STOPPED
    assert console.shown == "Backup Passphrase: " + "*" * len(CANARY) + "\r\n"
    assert "Traceback" not in captured.err
    assert CANARY not in captured.out + captured.err


def test_without_a_console_a_secret_is_read_as_one_line_and_never_written() -> None:
    stdin, stderr = io.StringIO(f"{CANARY} \r\nnext answer\n"), io.StringIO()
    prompter = Prompter(console=None, stdin=stdin, stderr=stderr)

    secret = prompter.secret("Password for netops-ro: ")

    assert secret.same_as(Secret(f"{CANARY} "))
    assert stdin.readline() == "next answer\n"
    shown = stderr.getvalue()
    assert "Password for netops-ro: " in shown
    assert "not a console" in shown
    assert CANARY not in shown


def test_input_that_ends_before_the_answer_cancels_with_exit_3(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def asks_for_a_password(_args: argparse.Namespace) -> ExitCode:
        Prompter(console=None, stdin=io.StringIO(""), stderr=io.StringIO()).secret("> ")
        return ExitCode.CLEAN

    monkeypatch.setitem(COMMANDS, "change-passphrase", asks_for_a_password)

    code = main(["change-passphrase"])

    assert code == ExitCode.STOPPED
    assert "Traceback" not in capsys.readouterr().err
