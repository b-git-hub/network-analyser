"""The operator's prompts, and the masked reader for secrets (spec #37, stories 25-26, 29).

The masked reader is our own loop over `msvcrt.getwch()` key codes, not
`getpass(echo_char="*")` (decision #29). It shows one `*` per character, so a paste from a
password manager is visibly received; showing the length is a deliberate trade-off (#15).
It never writes a typed character anywhere, and it returns a `Secret`, never a `str`.

Ctrl+C at any prompt raises KeyboardInterrupt, and input that ends before the answer raises
EOFError; `cli.app` turns both into exit code 3 with no traceback.

A known limit of `getwch()`: it returns the letter a-grave (U+00E0) as the same code that
starts an arrow or function key, so that letter, and the key typed after it, never reach the
secret. The lab checklist (G6) records how this behaves on Windows.
"""

import sys
import unicodedata
from typing import Self, TextIO

from network_analyser import _winsys
from network_analyser._winsys.console import Console
from network_analyser.credentials import Secret

_ENTER = frozenset({"\r", "\n"})
_BACKSPACE = "\x08"
_CTRL_C = "\x03"  # getwch() reads Ctrl+C as a key, not as a signal
# getwch() returns an arrow or function key as one of these, then a second code.
_TWO_CODE_KEY = frozenset({"\x00", "\xe0"})

NOT_A_CONSOLE_NOTICE = (
    "(Input is not a console, so this answer cannot be masked. It is read as one line.)"
)


class Prompter:
    """Asks the operator questions, at the console or on redirected input."""

    def __init__(self, *, console: Console | None, stdin: TextIO, stderr: TextIO) -> None:
        """Ask through `console` when there is one; otherwise read lines from `stdin`.

        Args:
            console: the key-by-key console, or None when input is not a console.
            stdin: where plain answers are read from, and secrets when there is no console.
            stderr: where questions are shown, except the masked prompt's own text.
        """
        self._console = console
        self._stdin = stdin
        self._stderr = stderr

    @classmethod
    def for_this_process(cls) -> Self:
        """Ask at this process's console, or on its redirected standard input."""
        return cls(console=_winsys.open_console(), stdin=sys.stdin, stderr=sys.stderr)

    def say(self, text: str) -> None:
        """Show a line of text that goes with the questions (a warning, a reason to stop)."""
        self._stderr.write(f"{text}\n")
        self._stderr.flush()

    def line(self, prompt: str) -> str:
        """Ask a plain question; return the answer without its line ending.

        Raises:
            EOFError: input ended before an answer was given.
        """
        self._stderr.write(prompt)
        self._stderr.flush()
        answer = self._stdin.readline()
        if not answer:
            raise EOFError
        return answer.rstrip("\r\n")

    def yes_no(self, question: str, *, default: bool) -> bool:
        """Ask a yes-or-no question; Enter gives `default`, and other answers ask again.

        Raises:
            EOFError: input ended before an answer was given.
        """
        while True:
            answer = self.line(question).strip().lower()
            if answer in {"y", "yes"} or (default and not answer):
                return True
            if answer in {"n", "no"} or (not default and not answer):
                return False
            self.say("  Answer y or n.")

    def secret(self, prompt: str) -> Secret:
        """Ask for a secret and return it, showing one `*` per character typed.

        Raises:
            KeyboardInterrupt: the operator pressed Ctrl+C.
            EOFError: input is not a console and ended before an answer was given.
        """
        if self._console is None:
            self.say(NOT_A_CONSOLE_NOTICE)
            return Secret(self.line(prompt))
        return _read_masked(self._console, prompt)


def _read_masked(console: Console, prompt: str) -> Secret:
    console.write(prompt)
    typed: list[str] = []
    try:
        while (key := console.read_key()) not in _ENTER:
            if key == _CTRL_C:
                console.write("\r\n")
                raise KeyboardInterrupt  # the Run is cancelled: cli.app exits 3
            if key in _TWO_CODE_KEY:
                console.read_key()  # the key's second code: never part of the secret
            elif key == _BACKSPACE:
                if typed:
                    typed.pop()
                    console.write("\b \b")
            elif unicodedata.category(key) != "Cc":  # other control codes are dropped
                typed.append(key)
                console.write("*")
        console.write("\r\n")
        return Secret("".join(typed))
    finally:
        typed.clear()
