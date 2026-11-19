"""`network-analyser show-backup` (ticket #57; spec #37 stories 102 and 112; #12, #22).

Driven through `main(argv)` with what the operator types. Backups and check files use the
fast fake age (tests/support/fake_age), except one test that opens a real age file. The
configs are synthetic.
"""

import io
from pathlib import Path

import pyrage
import pytest

from network_analyser import _winsys, backup_store
from network_analyser.backup_store import check_file
from network_analyser.cli import ExitCode, main
from network_analyser.credentials import Secret, SecretScan
from tests.support import fake_age
from tests.support.run_driver import BACKUP_CANARY, Outcome, data_folder, typed

OTHER_CANARY = "CANARY-pp-91c2-other-one"
CONFIG = (
    "!\n"
    "version 17.9\n"
    "hostname sw-a\n"
    "enable secret 9 CANARY-hash-5d1e\n"
    "banner motd ^C\x1b[2Jhello\x07^C\n"
    " description uplink\x0cto\x85core\r\n"
    "end\n"
)


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.fixture(autouse=True)
def _to_a_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """Standard output is a console window, as when the operator runs it by hand."""
    monkeypatch.setattr(_winsys, "stdout_is_console", lambda: True)


class ShowBackup:
    """Runs `network-analyser show-backup` with what the operator types on stdin."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        self._monkeypatch = monkeypatch
        self._capsys = capsys

    def __call__(self, *argv: str, typed: str = "") -> Outcome:
        self._monkeypatch.setattr("sys.stdin", io.StringIO(typed))
        code = main(["show-backup", *argv])
        captured = self._capsys.readouterr()
        return Outcome(code, captured.out, captured.err)


@pytest.fixture
def show(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> ShowBackup:
    return ShowBackup(monkeypatch, capsys)


def _check_file(passphrase: str = BACKUP_CANARY) -> None:
    backup_store.create_check_file(data_folder().check_file, Secret(passphrase))


def _backup(
    folder: Path, name: str = "sw-a__TEST0000A01.cfg.age", passphrase: str = BACKUP_CANARY
) -> Path:
    path = folder / "backups" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(fake_age.lock(CONFIG.encode(), passphrase))
    return path


def _every_file(*roots: Path) -> dict[Path, bytes]:
    return {p: p.read_bytes() for root in roots for p in root.rglob("*") if p.is_file()}


def test_it_asks_for_the_passphrase_and_prints_the_config_escaped_writing_nothing(
    show: ShowBackup, tmp_path: Path
) -> None:
    _check_file()
    backup = _backup(tmp_path)
    before = _every_file(tmp_path, data_folder().root)

    got = show(str(backup), typed=typed("YES", BACKUP_CANARY))

    assert got.code == ExitCode.CLEAN, got.err
    assert "Backup Passphrase: " in got.err
    assert got.out == (
        "!\n"
        "version 17.9\n"
        "hostname sw-a\n"
        "enable secret 9 CANARY-hash-5d1e\n"
        "banner motd ^C\\x1b[2Jhello\\x07^C\n"
        " description uplink\\x0cto\\x85core\n"
        "end\n"
    )
    assert BACKUP_CANARY not in got.out + got.err
    assert _every_file(tmp_path, data_folder().root) == before


def test_it_refuses_when_output_is_not_a_console_so_no_redirect_puts_plaintext_on_disk(
    show: ShowBackup, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_winsys, "stdout_is_console", lambda: False)
    _check_file()
    backup = _backup(tmp_path)

    got = show(str(backup), typed=typed("YES", BACKUP_CANARY))

    assert got.code == ExitCode.REFUSED
    assert got.out == ""
    assert "only to a console window" in got.err
    assert "Backup Passphrase: " not in got.err


@pytest.mark.parametrize(
    ("content", "message"),
    [
        pytest.param(None, "cannot be read", id="missing"),
        pytest.param(b"hostname sw-a\n", "not a Backup", id="plaintext"),
        pytest.param(b"age-encryption.org/v1\n-> X25519 abc\n", "not a Backup", id="key pair"),
        pytest.param(b"age-encryption.org/v1\n" + b"A" * 17_000_000, "too big", id="too big"),
    ],
)
def test_a_file_that_is_not_a_backup_is_refused_before_the_passphrase_is_asked(
    show: ShowBackup, tmp_path: Path, content: bytes | None, message: str
) -> None:
    _check_file()
    path = tmp_path / "sw-a.cfg.age"
    if content is not None:
        path.write_bytes(content)

    got = show(str(path), typed=typed("YES", BACKUP_CANARY))

    assert got.code == ExitCode.REFUSED
    assert message in got.err
    assert "Backup Passphrase: " not in got.err
    assert "Traceback" not in got.err
    assert got.out == ""


def _assert_not_shown(got: Outcome) -> None:
    assert got.out == ""
    assert "hostname sw-a" not in got.err
    assert "Traceback" not in got.err
    for secret in (BACKUP_CANARY, OTHER_CANARY):
        assert secret not in got.err


def test_a_wrong_passphrase_gives_a_fixed_message_and_exit_2(
    show: ShowBackup, tmp_path: Path
) -> None:
    _check_file()
    backup = _backup(tmp_path)

    got = show(str(backup), typed=typed("YES", OTHER_CANARY))

    assert got.code == ExitCode.REFUSED
    assert f"Not shown: {backup}: that passphrase does not open it, and it is not the " in got.err
    _assert_not_shown(got)


def test_with_no_check_file_a_backup_that_does_not_open_says_it_cannot_tell_why(
    show: ShowBackup, tmp_path: Path
) -> None:
    backup = _backup(tmp_path)

    got = show(str(backup), typed=typed("YES", OTHER_CANARY))

    assert got.code == ExitCode.REFUSED
    assert "There is no check file here to tell a wrong passphrase from a damaged file" in got.err
    _assert_not_shown(got)


def test_a_damaged_backup_under_the_right_passphrase_gives_a_fixed_message_and_exit_1(
    show: ShowBackup, tmp_path: Path
) -> None:
    _check_file()
    backup = _backup(tmp_path)
    header, tag, body = backup.read_bytes().partition(b"\n--- fake\n")
    backup.write_bytes(header[:-1] + (b"0" if header[-1:] != b"0" else b"1") + tag + body)

    got = show(str(backup), typed=typed("YES", BACKUP_CANARY))

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert "though that passphrase unlocks the check file. The file is damaged" in got.err
    _assert_not_shown(got)


def test_stopping_at_the_crash_dump_check_asks_for_no_passphrase(
    show: ShowBackup, tmp_path: Path
) -> None:
    _check_file()
    backup = _backup(tmp_path)

    got = show(str(backup), typed=typed("no", BACKUP_CANARY))

    assert got.code == ExitCode.REFUSED
    assert "Stopped at the crash-dump check. No secret was typed." in got.err
    assert "Backup Passphrase: " not in got.err
    _assert_not_shown(got)


def test_input_that_ends_at_the_passphrase_prompt_cancels_with_exit_3(
    show: ShowBackup, tmp_path: Path
) -> None:
    _check_file()
    backup = _backup(tmp_path)

    got = show(str(backup), typed=typed("YES"))

    assert got.code == ExitCode.STOPPED
    _assert_not_shown(got)


# -- while a change-passphrase is unfinished (story 112) ----------------------------------


@pytest.fixture
def change_pending() -> None:
    """Mid-change: the check file is under the new passphrase, the previous under the old."""
    data = data_folder()
    _check_file(OTHER_CANARY)  # the new passphrase
    backup_store.create_check_file(data.previous_check_file, Secret(BACKUP_CANARY))
    data.change_pending.write_text("{}", encoding="utf-8")


@pytest.mark.usefixtures("change_pending")
@pytest.mark.parametrize("passphrase", [BACKUP_CANARY, OTHER_CANARY])
def test_it_keeps_working_while_a_change_is_pending(
    show: ShowBackup, tmp_path: Path, passphrase: str
) -> None:
    backup = _backup(tmp_path, passphrase=passphrase)

    got = show(str(backup), typed=typed("YES", passphrase))

    assert got.code == ExitCode.CLEAN, got.err
    assert "hostname sw-a\n" in got.out


@pytest.mark.usefixtures("change_pending")
def test_mid_change_the_new_passphrase_on_a_file_not_yet_relocked_says_it_is_under_the_old(
    show: ShowBackup, tmp_path: Path
) -> None:
    backup = _backup(tmp_path, passphrase=BACKUP_CANARY)

    got = show(str(backup), typed=typed("YES", OTHER_CANARY))

    assert got.code == ExitCode.REFUSED
    assert "which is the new one" in got.err
    assert "probably still under the old passphrase" in got.err
    _assert_not_shown(got)


@pytest.mark.usefixtures("change_pending")
def test_mid_change_the_old_passphrase_on_a_relocked_file_says_it_is_under_the_new(
    show: ShowBackup, tmp_path: Path
) -> None:
    backup = _backup(tmp_path, passphrase=OTHER_CANARY)

    got = show(str(backup), typed=typed("YES", BACKUP_CANARY))

    assert got.code == ExitCode.REFUSED
    assert "which is the old one" in got.err
    assert "probably already under the new passphrase" in got.err
    _assert_not_shown(got)


@pytest.mark.usefixtures("change_pending")
def test_mid_change_a_passphrase_that_is_neither_is_wrong(show: ShowBackup, tmp_path: Path) -> None:
    backup = _backup(tmp_path)

    got = show(str(backup), typed=typed("YES", "CANARY-pp-3b3b-neither-one"))

    assert got.code == ExitCode.REFUSED
    assert "it is not the Backup Passphrase" in got.err
    _assert_not_shown(got)


# -- listing a Run's Backups (story 102; #42 follow-up) ----------------------------------


def _registered_run(parent: Path, name: str, *backups: str) -> Path:
    folder = parent / name
    folder.mkdir(parents=True)
    for backup in backups:
        _backup(folder, backup)
    backup_store.register_run_folder(data_folder().run_register, folder, scan=SecretScan())
    return folder


def test_with_no_file_it_lists_the_registered_runs_and_the_latest_runs_backups(
    show: ShowBackup, tmp_path: Path
) -> None:
    first = _registered_run(tmp_path, "20261118T101530Z_site-a", "sw-a__TEST0000A01.cfg.age")
    moved = _registered_run(tmp_path, "20261118T111530Z")
    moved.rmdir()
    latest = _registered_run(
        tmp_path,
        "20261119T090000Z_site-b",
        "sw-c__TEST0000C03.cfg.age",
        "sw-b__TEST0000B02.cfg.age",
    )
    (latest / "backups" / "manifest.age").write_bytes(b"age-encryption.org/v1\n")
    (latest / "backups" / ".sw-d__X.cfg.age.tmp-0123456789abcdef").write_bytes(b"")

    got = show()

    assert got.code == ExitCode.CLEAN, got.err
    assert got.out == (
        "Runs in the Run register, oldest first:\n"
        f"  {first}  1 Backup\n"
        f"  {moved}  not found\n"
        f"  {latest}  2 Backups\n"
        f"Backups of the latest Run, {latest}:\n"
        f"  {latest / 'backups' / 'sw-b__TEST0000B02.cfg.age'}\n"
        f"  {latest / 'backups' / 'sw-c__TEST0000C03.cfg.age'}\n"
    )
    assert 'network-analyser show-backup "BACKUP_FILE"' in got.err
    assert "Passphrase" not in got.err


def test_with_an_empty_register_it_says_so(show: ShowBackup) -> None:
    got = show()

    assert got.code == ExitCode.CLEAN
    assert "No Run folder is in the Run register yet" in got.err


def test_run_folder_lists_that_runs_backups_even_when_it_is_not_registered(
    show: ShowBackup, tmp_path: Path
) -> None:
    _registered_run(tmp_path, "20261119T090000Z", "sw-c__TEST0000C03.cfg.age")
    elsewhere = tmp_path / "copied" / "20261101T080000Z"
    _backup(elsewhere)

    got = show("--run-folder", str(elsewhere))

    assert got.code == ExitCode.CLEAN, got.err
    assert got.out == (
        f"Backups of {elsewhere}:\n  {elsewhere / 'backups' / 'sw-a__TEST0000A01.cfg.age'}\n"
    )
    assert not (data_folder().run_register.read_text(encoding="utf-8").count("copied"))


def test_a_run_folder_with_no_backups_says_so(show: ShowBackup, tmp_path: Path) -> None:
    got = show("--run-folder", str(tmp_path))

    assert got.code == ExitCode.CLEAN
    assert got.out == f"Backups of {tmp_path}:\n  none\n"


def test_a_run_folder_that_is_not_there_is_refused(show: ShowBackup, tmp_path: Path) -> None:
    got = show("--run-folder", str(tmp_path / "gone"))

    assert got.code == ExitCode.REFUSED
    assert f"{tmp_path / 'gone'}: not found" in got.err


def test_a_file_and_run_folder_together_are_refused(show: ShowBackup, tmp_path: Path) -> None:
    backup = _backup(tmp_path)

    got = show(str(backup), "--run-folder", str(tmp_path), typed=typed("YES", BACKUP_CANARY))

    assert got.code == ExitCode.REFUSED
    assert "--run-folder lists a Run's Backups" in got.err
    assert got.out == ""


# -- real age (story 103: Backups stay standard age files) --------------------------------

REAL_AGE = check_file.AGE


@pytest.mark.parametrize("cut", [0, 20], ids=["whole", "truncated"])
def test_a_real_age_backup_opens_and_a_truncated_one_gives_a_fixed_message(
    show: ShowBackup, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cut: int
) -> None:
    monkeypatch.setattr(check_file, "AGE", REAL_AGE)
    locked = pyrage.passphrase.encrypt(CONFIG.encode(), BACKUP_CANARY)
    backup = tmp_path / "sw-a__TEST0000A01.cfg.age"
    backup.write_bytes(locked[: len(locked) - cut])

    got = show(str(backup), typed=typed("YES", BACKUP_CANARY))

    if cut:
        assert got.code == ExitCode.REFUSED
        assert "There is no check file here" in got.err
        _assert_not_shown(got)
    else:
        assert got.code == ExitCode.CLEAN, got.err
        assert "enable secret 9 CANARY-hash-5d1e\n" in got.out


REAL_STDOUT_IS_CONSOLE = _winsys.stdout_is_console


def test_captured_output_does_not_count_as_a_console() -> None:
    assert REAL_STDOUT_IS_CONSOLE() is False
