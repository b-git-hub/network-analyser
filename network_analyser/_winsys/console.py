"""The Windows console, key by key, for the masked prompt (spec #37, stories 25-26; #29).

`open_console()` gives a `Console` only when standard input is a Windows console. It then
reads one key code at a time with `msvcrt.getwch()`, which neither echoes nor buffers, and
writes with `msvcrt.putwch()`, which reaches the console even when stdout or stderr is
redirected. Everything the codes mean (Enter, Backspace, Ctrl+C, the two-code arrow and
function keys) is decided by the caller, so it can be tested on any OS with a fake.
"""

import sys
from typing import Protocol


class Console(Protocol):
    """A console read one key code at a time, the way `msvcrt.getwch()` returns them."""

    def read_key(self) -> str:
        """Wait for the next key code, without echoing it."""
        ...

    def write(self, text: str) -> None:
        """Show `text` on the console."""
        ...


if sys.platform == "win32":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _WindowsConsole:
        """The real console, through the C runtime's unbuffered console calls."""

        def read_key(self) -> str:
            return msvcrt.getwch()

        def write(self, text: str) -> None:
            for character in text:
                msvcrt.putwch(character)

    def open_console() -> Console | None:
        """Return the console if standard input is one; None if input is redirected."""
        if sys.stdin is None:
            return None
        try:
            handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        except OSError, ValueError:
            return None
        mode = wintypes.DWORD()
        # GetConsoleMode succeeds only on a console handle; a file, pipe or NUL fails it.
        if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return None
        return _WindowsConsole()

    def stdout_is_console() -> bool:
        """Say whether standard output is a console window, not a file, pipe or NUL (#57).

        `show-backup` prints a decrypted config only to a console, so a redirect can never
        put the plaintext on disk.
        """
        if sys.stdout is None:
            return False
        try:
            handle = msvcrt.get_osfhandle(sys.stdout.fileno())
        except OSError, ValueError:
            return False
        mode = wintypes.DWORD()
        return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))

else:

    def stdout_is_console() -> bool:
        """Say whether standard output is a terminal, not a file or pipe (#57)."""
        return sys.stdout is not None and sys.stdout.isatty()

    def open_console() -> Console | None:
        """Say there is no console to mask: v1 runs only on Windows.

        Prompts then read a line from standard input instead (the echoed fallback).
        """
        return None
