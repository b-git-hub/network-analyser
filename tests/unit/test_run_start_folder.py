"""The first Run-start step: the lock and the Run folder checks, before any prompt (#42).

Driven through `main(argv)` as the operator would. conftest.py gives every test its own
`%LOCALAPPDATA%` and working folder.
"""

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from network_analyser import backup_store, run_output
from network_analyser.cli import ExitCode, main
from network_analyser.cli.run_folder import create_and_register

NOT_BUILT = "not built yet"


def data_folder() -> run_output.DataFolder:
    return run_output.locate_data_folder(Path(os.environ["LOCALAPPDATA"]))


@pytest.mark.parametrize("command", ["run", "change-passphrase"])
def test_a_second_run_or_change_passphrase_is_refused_while_one_is_active(
    command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    held = run_output.take_instance_lock(data_folder())
    assert held is not None

    with held:
        code = main([command])

    err = capsys.readouterr().err
    assert code == ExitCode.REFUSED
    assert "another Run or change-passphrase is in progress" in err
    assert NOT_BUILT not in err


@pytest.mark.parametrize("command", ["run", "change-passphrase"])
def test_the_lock_is_let_go_when_the_command_ends(command: str) -> None:
    main([command])

    lock = run_output.take_instance_lock(data_folder())
    assert lock is not None
    lock.release()


def test_a_run_first_makes_the_default_runs_folder_and_leaves_it_empty(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["run", "--scope", "192.0.2.0/24", "--seed", "192.0.2.1"])

    assert NOT_BUILT in capsys.readouterr().err  # the later steps come in other tickets
    assert code == ExitCode.INTERNAL_ERROR
    assert data_folder().runs.is_dir()
    assert list(data_folder().runs.iterdir()) == []


def test_runs_dir_names_another_parent(tmp_path: Path) -> None:
    main(["run", "--runs-dir", str(tmp_path / "team-share" / "runs")])

    assert (tmp_path / "team-share" / "runs").is_dir()
    assert not data_folder().runs.exists()


def test_a_place_that_cannot_hold_a_run_folder_is_refused_before_any_prompt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    not_a_folder = tmp_path / "file.txt"
    not_a_folder.write_text("", encoding="utf-8")

    code = main(["run", "--runs-dir", str(not_a_folder / "runs")])  # Scope would be asked

    captured = capsys.readouterr()
    assert code == ExitCode.REFUSED
    assert "cannot be created and written" in captured.err
    assert str(not_a_folder / "runs") in captured.err
    assert "Scope" not in captured.out + captured.err  # refused before the first prompt


def test_permissions_the_tool_cannot_read_are_warned_about(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main(["run"])  # the permissions read is written for Windows only

    assert "could not read who can modify the Run folder" in capsys.readouterr().err


def test_a_run_without_a_per_user_folder_is_refused(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("LOCALAPPDATA")

    code = main(["run"])

    assert code == ExitCode.REFUSED
    assert "LOCALAPPDATA" in capsys.readouterr().err


def test_an_unsafe_label_is_refused_without_echoing_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["run", "--label", "CANARY label"])

    captured = capsys.readouterr()
    assert code == ExitCode.REFUSED
    assert "CANARY" not in captured.out + captured.err
    assert "--label" in captured.err


def test_the_run_folder_enters_the_register_the_moment_it_is_created(tmp_path: Path) -> None:
    data = data_folder()
    check = run_output.check_runs_parent(tmp_path / "runs")
    started = datetime(2026, 11, 18, 10, 15, 30, tzinfo=UTC)

    folder = create_and_register(data, check, started, label="lab")

    assert folder.path == tmp_path / "runs" / "20261118T101530Z_lab"
    assert folder.path.is_dir()
    assert backup_store.registered_run_folders(data.run_register) == (folder.path,)
