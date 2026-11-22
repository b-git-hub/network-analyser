r"""Before any prompt, the tool checks that only the operator can read or change the data.

#7 decided the per-user `trust\` folder is readable and writable only by the operator's
Windows user (ticket #69); #150 extended the check to the data folder that holds the Cisco API
key file. Anyone else who can change the Trust Store could make the tool trust an impostor's
host key and so send it a password, and anyone else who can reach the data folder could read or
replace the stored key, so another account that can read or change either refuses the Run;
SYSTEM and Administrators, who can reach every file anyway, raise nothing. Windows answers are
faked here; they are checked by hand on a Windows PC (lab checklist, G14).
"""

from pathlib import Path

import pytest

from network_analyser import _winsys, run_output

OPERATOR = _winsys.Grant(sid="S-1-5-21-1000-1000-1000-1001", name="PC1\\operator")
SYSTEM = _winsys.Grant(sid="S-1-5-18", name="NT AUTHORITY\\SYSTEM")
ADMINISTRATORS = _winsys.Grant(sid="S-1-5-32-544", name="BUILTIN\\Administrators")
USERS = _winsys.Grant(sid="S-1-5-32-545", name="BUILTIN\\Users")
EVERYONE = _winsys.Grant(sid="S-1-1-0", name="Everyone")
COLLEAGUE = _winsys.Grant(sid="S-1-5-21-1000-1000-1000-1002", name="PC1\\colleague")
OWNER_ONLY = (OPERATOR, SYSTEM, ADMINISTRATORS)


class FakeWindows:
    """Answers the permission reads for each path, and records which paths were read."""

    def __init__(
        self,
        *,
        modify: dict[Path, tuple[_winsys.Grant, ...] | None] | None = None,
        read: dict[Path, tuple[_winsys.Grant, ...] | None] | None = None,
        user_sid: str | None = OPERATOR.sid,
    ) -> None:
        self._modify = modify or {}
        self._read = read or {}
        self._user_sid = user_sid
        self.read_paths: list[Path] = []

    def facts(self) -> run_output.FolderFacts:
        return run_output.FolderFacts(
            modify_grants=lambda path: self._answer(self._modify, path),
            read_grants=lambda path: self._answer(self._read, path),
            user_sid=lambda: self._user_sid,
        )

    def _answer(
        self, answers: dict[Path, tuple[_winsys.Grant, ...] | None], path: str
    ) -> tuple[_winsys.Grant, ...] | None:
        self.read_paths.append(Path(path))
        return answers.get(Path(path), OWNER_ONLY)


@pytest.fixture
def data(tmp_path: Path) -> run_output.DataFolder:
    folder = run_output.locate_data_folder(tmp_path / "LocalAppData")
    folder.trust_store.parent.mkdir(parents=True)
    return folder


def test_a_trust_folder_only_the_operator_can_reach_passes(data: run_output.DataFolder) -> None:
    check = run_output.check_trust_folder(data, facts=FakeWindows().facts())

    assert check.refusal is None
    assert check.warning is None


@pytest.mark.parametrize("other", [USERS, EVERYONE, COLLEAGUE])
def test_another_account_that_can_change_the_folder_refuses(
    data: run_output.DataFolder, other: _winsys.Grant
) -> None:
    windows = FakeWindows(modify={data.trust_store.parent: (*OWNER_ONLY, other)})

    check = run_output.check_trust_folder(data, facts=windows.facts())

    assert check.refusal is not None
    assert other.name in check.refusal
    assert "impostor" in check.refusal
    assert str(data.trust_store.parent) in check.refusal
    assert check.warning is None


def test_another_account_that_can_only_read_the_folder_refuses_too(
    data: run_output.DataFolder,
) -> None:
    windows = FakeWindows(read={data.trust_store.parent: (*OWNER_ONLY, USERS)})

    check = run_output.check_trust_folder(data, facts=windows.facts())

    assert check.refusal is not None
    assert USERS.name in check.refusal


def test_system_administrators_and_creator_owner_raise_nothing(
    data: run_output.DataFolder,
) -> None:
    creator_owner = _winsys.Grant(sid="S-1-3-0", name="CREATOR OWNER")
    everyone_trusted = (*OWNER_ONLY, creator_owner)
    windows = FakeWindows(
        modify={data.trust_store.parent: everyone_trusted},
        read={data.trust_store.parent: everyone_trusted},
    )

    check = run_output.check_trust_folder(data, facts=windows.facts())

    assert check.refusal is None


def test_an_account_on_the_known_hosts_file_itself_is_caught(
    data: run_output.DataFolder,
) -> None:
    data.trust_store.write_text("", encoding="utf-8")
    windows = FakeWindows(read={data.trust_store: (*OWNER_ONLY, COLLEAGUE)})

    check = run_output.check_trust_folder(data, facts=windows.facts())

    assert check.refusal is not None
    assert COLLEAGUE.name in check.refusal


def test_another_account_on_the_data_folder_refuses_too(data: run_output.DataFolder) -> None:
    """The data folder holds the Cisco API key file, so its permissions matter as well (#150)."""
    root = _winsys.os_path(data.root)
    windows = FakeWindows(read={root: (*OWNER_ONLY, COLLEAGUE)})

    check = run_output.check_trust_folder(data, facts=windows.facts())

    assert check.refusal is not None
    assert COLLEAGUE.name in check.refusal
    assert str(data.root) in check.refusal
    assert "Cisco API key" in check.refusal
    assert check.warning is None


def test_an_account_on_the_cisco_key_file_itself_is_caught(data: run_output.DataFolder) -> None:
    data.cisco_key_file.write_bytes(b"age ciphertext, never a real key")
    key_file = _winsys.os_path(data.cisco_key_file)
    windows = FakeWindows(read={key_file: (*OWNER_ONLY, COLLEAGUE)})

    check = run_output.check_trust_folder(data, facts=windows.facts())

    assert check.refusal is not None
    assert COLLEAGUE.name in check.refusal
    assert str(data.cisco_key_file) in check.refusal


def test_before_the_first_run_the_folder_it_will_inherit_from_is_read(tmp_path: Path) -> None:
    data = run_output.locate_data_folder(tmp_path / "LocalAppData")
    data.root.mkdir(parents=True)  # the lock file is made there before this check
    windows = FakeWindows(modify={data.root: (*OWNER_ONLY, USERS)})

    check = run_output.check_trust_folder(data, facts=windows.facts())

    assert windows.read_paths
    assert set(windows.read_paths) == {data.root}
    assert not data.trust_store.parent.exists()  # the check creates nothing
    assert check.refusal is not None
    assert str(data.root) in check.refusal
    assert USERS.name in check.refusal


@pytest.mark.parametrize("unread", ["modify", "read"])
def test_permissions_windows_will_not_give_refuse(data: run_output.DataFolder, unread: str) -> None:
    answers: dict[Path, tuple[_winsys.Grant, ...] | None] = {data.trust_store.parent: None}
    windows = FakeWindows(modify=answers) if unread == "modify" else FakeWindows(read=answers)

    check = run_output.check_trust_folder(data, facts=windows.facts())

    assert check.refusal is not None
    assert "could not read" in check.refusal
    assert check.warning is None


def test_where_the_operator_account_is_unknown_it_only_warns(
    data: run_output.DataFolder,
) -> None:
    windows = FakeWindows(modify={data.trust_store.parent: None}, user_sid=None)

    check = run_output.check_trust_folder(data, facts=windows.facts())

    assert check.refusal is None
    assert check.warning is not None
    assert check.warning.startswith("Warning: could not read who can read or change")
    assert check.warning.isascii()
