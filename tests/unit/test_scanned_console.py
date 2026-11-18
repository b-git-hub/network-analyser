import io
import sys

import pytest

from network_analyser.cli.console import ScannedStream, scanned_console
from network_analyser.credentials import Secret, SecretScan

CANARY = "CANARY-pw-a1e0"


def _scan() -> SecretScan:
    scan = SecretScan()
    scan.watch(Secret(CANARY))
    return scan


def test_a_line_holding_a_secret_is_written_with_it_blocked() -> None:
    inner = io.StringIO()
    stream = ScannedStream(inner, _scan())
    stream.write(f"Set 1: {CANARY}\nnext line\n")

    assert inner.getvalue() == "Set 1: [blocked]\nnext line\n"


def test_a_secret_written_in_pieces_on_one_line_is_still_blocked() -> None:
    inner = io.StringIO()
    stream = ScannedStream(inner, _scan())
    print("value:", CANARY[:5], end="", file=stream)
    print(CANARY[5:], file=stream)

    assert inner.getvalue() == "value: [blocked]\n"


def test_a_prompt_without_a_line_end_is_shown_on_flush() -> None:
    inner = io.StringIO()
    stream = ScannedStream(inner, _scan())
    stream.write("Start the Run? [Y/n] ")
    stream.flush()

    assert inner.getvalue() == "Start the Run? [Y/n] "


def test_the_console_streams_are_scanned_inside_the_block_and_restored_after(
    capsys: pytest.CaptureFixture[str],
) -> None:
    scan = _scan()
    with scanned_console(scan):
        sys.stdout.write(f"out {CANARY}\n")
        sys.stderr.write(f"err {CANARY}\n")
    sys.stdout.write(f"after {CANARY}\n")

    captured = capsys.readouterr()
    assert captured.out == f"out [blocked]\nafter {CANARY}\n"
    assert captured.err == "err [blocked]\n"
    assert scan.hits == 2


def test_a_partial_line_is_written_when_the_block_ends(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with scanned_console(_scan()):
        sys.stdout.write(CANARY)

    assert capsys.readouterr().out == "[blocked]"
