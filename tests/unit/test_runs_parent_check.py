"""Before any prompt, the tool checks it can create and write a Run folder where it will go.

It also says when that place is a network, cloud-synced or removable location, and warns
when accounts other than the operator, SYSTEM and Administrators can modify what is put
there (#42, stories 119-121; decided on #26). Windows answers are faked here; they are
checked by hand on a Windows PC (lab checklist, G10 and G11).
"""

from pathlib import Path

import pytest

from network_analyser import _winsys, run_output

OPERATOR = _winsys.Grant(sid="S-1-5-21-1000-1000-1000-1001", name="PC1\\operator")
SYSTEM = _winsys.Grant(sid="S-1-5-18", name="NT AUTHORITY\\SYSTEM")
ADMINISTRATORS = _winsys.Grant(sid="S-1-5-32-544", name="BUILTIN\\Administrators")
AUTHENTICATED_USERS = _winsys.Grant(sid="S-1-5-11", name="NT AUTHORITY\\Authenticated Users")
EVERYONE = _winsys.Grant(sid="S-1-1-0", name="Everyone")
CREATOR_OWNER = _winsys.Grant(sid="S-1-3-0", name="CREATOR OWNER")


def facts(
    *,
    drive: _winsys.DriveKind = _winsys.DriveKind.LOCAL,
    sync_roots: tuple[str, ...] = (),
    grants: tuple[_winsys.Grant, ...] | None = (OPERATOR, SYSTEM, ADMINISTRATORS),
    user_sid: str | None = OPERATOR.sid,
) -> run_output.FolderFacts:
    return run_output.FolderFacts(
        drive_kind=lambda _path: drive,
        sync_roots=lambda: sync_roots,
        modify_grants=lambda _path: grants,
        user_sid=lambda: user_sid,
    )


def test_a_writable_parent_passes_and_nothing_is_left_behind(tmp_path: Path) -> None:
    check = run_output.check_runs_parent(tmp_path, facts=facts())

    assert check.parent == tmp_path
    assert list(tmp_path.iterdir()) == []


def test_a_missing_parent_is_created(tmp_path: Path) -> None:
    runs = tmp_path / "LocalAppData" / "NetworkAnalyser" / "runs"

    run_output.check_runs_parent(runs, facts=facts())

    assert runs.is_dir()
    assert list(runs.iterdir()) == []


def test_a_relative_parent_is_made_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    check = run_output.check_runs_parent(Path("runs"), facts=facts())

    assert check.parent == tmp_path / "runs"


def test_a_parent_that_cannot_hold_a_folder_is_refused(tmp_path: Path) -> None:
    not_a_folder = tmp_path / "file.txt"
    not_a_folder.write_text("", encoding="utf-8")

    with pytest.raises(run_output.RunFolderError):
        run_output.check_runs_parent(not_a_folder / "runs", facts=facts())


def test_a_local_folder_owned_by_the_operator_gets_no_notice(tmp_path: Path) -> None:
    check = run_output.check_runs_parent(tmp_path, facts=facts())

    assert check.location_notice is None
    assert check.permissions_warning is None
    assert check.notices == ()


@pytest.mark.parametrize(
    ("drive", "place"),
    [
        (_winsys.DriveKind.NETWORK, "network location"),
        (_winsys.DriveKind.REMOVABLE, "removable drive"),
    ],
)
def test_a_network_or_removable_location_is_accepted_with_a_one_line_notice(
    tmp_path: Path, drive: _winsys.DriveKind, place: str
) -> None:
    check = run_output.check_runs_parent(tmp_path, facts=facts(drive=drive))

    assert check.location_notice is not None
    assert "\n" not in check.location_notice
    assert place in check.location_notice
    assert "plaintext" in check.location_notice
    assert "Findings report" in check.location_notice
    assert "old passphrase" in check.location_notice
    assert check.notices == (check.location_notice,)


def test_a_folder_inside_a_sync_root_gets_the_cloud_synced_notice(tmp_path: Path) -> None:
    sync_root = str(tmp_path).upper()  # Windows paths compare without case
    runs = tmp_path / "Team" / "runs"

    check = run_output.check_runs_parent(runs, facts=facts(sync_roots=(sync_root,)))

    assert check.location_notice is not None
    assert "cloud-synced folder" in check.location_notice
    assert "Findings report" in check.location_notice


def test_a_folder_beside_a_sync_root_gets_no_notice(tmp_path: Path) -> None:
    sync_root = str(tmp_path / "OneDrive")

    check = run_output.check_runs_parent(
        tmp_path / "OneDrive-old", facts=facts(sync_roots=(sync_root,))
    )

    assert check.location_notice is None


def test_others_who_can_modify_the_folder_are_named_in_a_warning(tmp_path: Path) -> None:
    grants = (OPERATOR, SYSTEM, ADMINISTRATORS, CREATOR_OWNER, AUTHENTICATED_USERS, EVERYONE)

    check = run_output.check_runs_parent(tmp_path, facts=facts(grants=grants))

    warning = check.permissions_warning
    assert warning is not None
    assert "\n" not in warning
    assert "NT AUTHORITY\\Authenticated Users, Everyone" in warning
    assert "booby-trapped diagram.html" in warning
    assert "fake Backup" in warning
    for trusted in (OPERATOR, SYSTEM, ADMINISTRATORS, CREATOR_OWNER):
        assert trusted.name not in warning
    assert check.notices == (warning,)


def test_permissions_that_cannot_be_read_get_a_warning_too(tmp_path: Path) -> None:
    unreadable = run_output.check_runs_parent(tmp_path, facts=facts(grants=None))
    unknown_operator = run_output.check_runs_parent(tmp_path, facts=facts(user_sid=None))

    for check in (unreadable, unknown_operator):
        assert check.permissions_warning is not None
        assert "could not read" in check.permissions_warning


def test_an_account_name_is_shown_in_ascii_with_controls_escaped(tmp_path: Path) -> None:
    odd = _winsys.Grant(sid="S-1-5-21-9-9-9-2001", name="PC1\\opérateur\x1b[2J")

    check = run_output.check_runs_parent(tmp_path, facts=facts(grants=(OPERATOR, odd)))

    assert check.permissions_warning is not None
    assert "PC1\\op\\xe9rateur\\x1b[2J" in check.permissions_warning
    assert check.permissions_warning.isascii()


def test_permissions_are_read_from_a_folder_made_where_the_run_folder_will_go(
    tmp_path: Path,
) -> None:
    seen: list[Path] = []

    def grants(path: str) -> tuple[_winsys.Grant, ...]:
        probe = Path(path)
        seen.append(probe)
        assert probe.is_dir()
        return (OPERATOR,)

    checker = facts()
    run_output.check_runs_parent(
        tmp_path,
        facts=run_output.FolderFacts(
            drive_kind=checker.drive_kind,
            sync_roots=checker.sync_roots,
            modify_grants=grants,
            user_sid=checker.user_sid,
        ),
    )

    assert [p.parent for p in seen] == [tmp_path]
    assert not seen[0].exists()
