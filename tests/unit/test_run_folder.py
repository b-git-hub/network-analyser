"""Run folders: named by UTC start and label, created exclusively, never reused (#42, #26)."""

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from network_analyser import run_output

STARTED = datetime(2026, 11, 18, 10, 15, 30, tzinfo=UTC)


def test_a_run_folder_is_named_by_its_utc_start(tmp_path: Path) -> None:
    folder = run_output.create_run_folder(tmp_path, STARTED, label=None)

    assert folder.path == tmp_path / "20261118T101530Z"
    assert folder.path.is_dir()


def test_a_label_follows_the_start_time(tmp_path: Path) -> None:
    folder = run_output.create_run_folder(tmp_path, STARTED, label="dc1-core")

    assert folder.path.name == "20261118T101530Z_dc1-core"


def test_the_name_uses_utc_whatever_zone_the_start_time_is_in(tmp_path: Path) -> None:
    started = STARTED.astimezone(timezone(timedelta(hours=10)))

    folder = run_output.create_run_folder(tmp_path, started, label=None)

    assert folder.path.name == "20261118T101530Z"


def test_a_taken_name_gets_2_then_3_and_the_old_folders_are_left_alone(tmp_path: Path) -> None:
    first = run_output.create_run_folder(tmp_path, STARTED, label="lab")
    (first.path / "audit.log").write_text("first Run", encoding="utf-8")

    second = run_output.create_run_folder(tmp_path, STARTED, label="lab")
    third = run_output.create_run_folder(tmp_path, STARTED, label="lab")

    assert [second.path.name, third.path.name] == [
        "20261118T101530Z_lab-2",
        "20261118T101530Z_lab-3",
    ]
    assert (first.path / "audit.log").read_text(encoding="utf-8") == "first Run"


def test_a_run_folder_that_cannot_be_created_is_a_fixed_error(tmp_path: Path) -> None:
    missing_parent = tmp_path / "not-there"

    with pytest.raises(run_output.RunFolderError):
        run_output.create_run_folder(missing_parent, STARTED, label=None)

    assert not missing_parent.exists()


def test_an_unsafe_label_never_reaches_the_disk(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()

    with pytest.raises(run_output.RunFolderError):
        run_output.create_run_folder(runs, STARTED, label="dc1 core")

    assert list(tmp_path.iterdir()) == [runs]
    assert list(runs.iterdir()) == []


@pytest.mark.parametrize("label", ["dc1-core", "lab", "site_a.2026", "A" * 32, "0", "-", "_x"])
def test_a_label_of_safe_characters_is_accepted(label: str) -> None:
    assert run_output.label_problem(label) is None


@pytest.mark.parametrize(
    "label",
    [
        pytest.param("", id="empty"),
        pytest.param("A" * 33, id="33 characters"),
        pytest.param("dc1 core", id="space"),
        pytest.param("..\\escape", id="backslash"),
        pytest.param("../escape", id="slash"),
        pytest.param("con:", id="colon"),
        pytest.param("café", id="non-ASCII letter"),
        pytest.param("a\x1bb", id="control character"),
        pytest.param("lab.", id="trailing dot, which Windows drops"),
    ],
)
def test_a_label_outside_the_allow_list_is_refused(label: str) -> None:
    assert run_output.label_problem(label) is not None
