"""The Run register: every Run folder the tool has created, so change-passphrase finds them.

A plain list with no secrets (#22), added to the moment a Run folder is created (#26,
story 123).
"""

from pathlib import Path

from network_analyser import backup_store


def test_an_empty_register_lists_nothing(tmp_path: Path) -> None:
    assert backup_store.registered_run_folders(tmp_path / "run-register.txt") == ()


def test_registered_run_folders_are_listed_in_the_order_they_were_added(tmp_path: Path) -> None:
    register = tmp_path / "run-register.txt"
    first = tmp_path / "runs" / "20261118T101530Z"
    second = tmp_path / "share" / "20261118T111530Z_lab"

    backup_store.register_run_folder(register, first)
    backup_store.register_run_folder(register, second)

    assert backup_store.registered_run_folders(register) == (first, second)


def test_the_register_is_a_plain_list_of_paths_one_per_line(tmp_path: Path) -> None:
    register = tmp_path / "run-register.txt"
    folder = tmp_path / "runs" / "20261118T101530Z"

    backup_store.register_run_folder(register, folder)

    assert register.read_text(encoding="utf-8") == f"{folder}\n"


def test_a_folder_registered_twice_is_listed_once(tmp_path: Path) -> None:
    register = tmp_path / "run-register.txt"
    folder = tmp_path / "runs" / "20261118T101530Z"

    backup_store.register_run_folder(register, folder)
    backup_store.register_run_folder(register, folder)

    assert backup_store.registered_run_folders(register) == (folder,)


def test_a_registered_folder_that_has_gone_is_still_listed(tmp_path: Path) -> None:
    register = tmp_path / "run-register.txt"
    moved = tmp_path / "runs" / "20261118T101530Z"  # never created: moved or deleted

    backup_store.register_run_folder(register, moved)

    assert backup_store.registered_run_folders(register) == (moved,)


def test_registering_leaves_no_temporary_file_behind(tmp_path: Path) -> None:
    register = tmp_path / "run-register.txt"

    backup_store.register_run_folder(register, tmp_path / "runs" / "20261118T101530Z")

    assert sorted(p.name for p in tmp_path.iterdir()) == ["run-register.txt"]


def test_blank_lines_in_a_hand_edited_register_are_ignored(tmp_path: Path) -> None:
    register = tmp_path / "run-register.txt"
    folder = tmp_path / "runs" / "20261118T101530Z"
    register.write_text(f"\n{folder}\n\n", encoding="utf-8")

    assert backup_store.registered_run_folders(register) == (folder,)
