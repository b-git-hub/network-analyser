"""Running elevated gets a warning, never a refusal (spec #37, story 17)."""

import pytest

from network_analyser.cli import ExitCode, main


def test_running_elevated_warns_but_still_runs(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--version"], elevated=lambda: True)

    captured = capsys.readouterr()
    assert code == ExitCode.CLEAN
    assert "running elevated" in captured.err
    assert captured.out.startswith("network-analyser ")


def test_a_standard_user_gets_no_warning(capsys: pytest.CaptureFixture[str]) -> None:
    main(["--version"], elevated=lambda: False)

    assert "elevated" not in capsys.readouterr().err
