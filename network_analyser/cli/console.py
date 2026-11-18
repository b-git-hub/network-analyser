"""The console, scanned for the Run's secrets (spec #37 story 164; decision #30 section 11).

Once a Run's secrets are typed, `scanned_console` puts a `ScannedStream` in front of
standard output and standard error, so every line any part of the tool prints passes
through the secret scan first, and a typed secret shows as `[blocked]`. Text is held until
its line ends, so a secret printed in pieces on one line is still caught; a prompt with no
line end is scanned and shown when it is flushed.
"""

import io
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TextIO, cast, override

from network_analyser.credentials import SecretScan


class ScannedStream(io.TextIOBase):
    """A text stream that scans each line for the Run's secrets before passing it on."""

    def __init__(self, inner: TextIO, scan: SecretScan) -> None:
        """Pass scanned text on to `inner`."""
        super().__init__()
        self._inner = inner
        self._scan = scan
        self._pending = ""

    @override
    def write(self, text: str, /) -> int:
        """Take `text`; write every complete line, scanned, and hold the rest."""
        self._pending += text
        complete, newline, rest = self._pending.rpartition("\n")
        if newline:
            self._pending = rest
            self._inner.write(self._scan.contains_secret(complete + newline)[0])
        return len(text)

    @override
    def flush(self) -> None:
        """Write any partial line, scanned, then flush the console."""
        if self._pending:
            pending, self._pending = self._pending, ""
            self._inner.write(self._scan.contains_secret(pending)[0])
        self._inner.flush()

    @override
    def writable(self) -> bool:
        return True

    @override
    def isatty(self) -> bool:
        return self._inner.isatty()


@contextmanager
def scanned_console(scan: SecretScan) -> Iterator[None]:
    """Scan everything printed to standard output and standard error inside the block."""
    out, err = sys.stdout, sys.stderr
    scanned_out, scanned_err = ScannedStream(out, scan), ScannedStream(err, scan)
    sys.stdout = cast("TextIO", scanned_out)
    sys.stderr = cast("TextIO", scanned_err)
    try:
        yield
    finally:
        sys.stdout, sys.stderr = out, err
        scanned_out.flush()
        scanned_err.flush()
