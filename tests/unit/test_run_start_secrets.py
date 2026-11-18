"""Run start from the crash-dump check to the confirm (ticket #45; spec #37 stories 14-15,
20-24, 27-28 and 30; decided on #6, #12, #15, #31 and ADR 0004).

    crash-dump check -> Backup Passphrase -> Credential Sets -> Ready to start
    -> Start the Run? [Y/n] -> Run folder created and registered

Driven through `main(argv)` with what the operator types. The check file uses the fast fake
age; tests/unit/test_check_file.py covers real age.
"""

from pathlib import Path

import pytest

from network_analyser import backup_store
from network_analyser.cli import ExitCode
from tests.support import fake_age
from tests.support.run_driver import (
    BACKUP_CANARY,
    DEVICE_CANARY,
    FLAGS,
    Outcome,
    Runner,
    data_folder,
    first_run,
    later_run,
    typed,
)

NOTHING_CONTACTED = "Nothing was contacted."


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    return Runner(monkeypatch, capsys)


@pytest.fixture
def check_file_exists(run: Runner) -> None:
    """A first Run has already set the Backup Passphrase."""
    assert run(*FLAGS, typed=first_run(start="n")).code == ExitCode.STOPPED
    assert data_folder().check_file.is_file()


def _run_folders() -> list[Path]:
    runs = data_folder().runs
    return sorted(runs.iterdir()) if runs.is_dir() else []


def _assert_no_secret_shown(got: Outcome) -> None:
    for secret in (BACKUP_CANARY, DEVICE_CANARY):
        assert secret not in got.out + got.err


def _files_hold(root: Path, secret: str) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file() and secret.encode() in p.read_bytes()]


# -- a whole first Run start (stories 14, 20, 23, 28) -------------------------------------


def test_a_first_run_sets_the_passphrase_takes_a_set_confirms_and_creates_the_run_folder(
    run: Runner,
) -> None:
    got = run(*FLAGS, "--label", "site-a", typed=first_run())

    assert got.code == ExitCode.CLEAN
    assert data_folder().check_file.is_file()
    (folder,) = _run_folders()
    assert folder.name.endswith("_site-a")
    assert f"Run folder created: {folder}\n" in got.out
    assert backup_store.registered_run_folders(data_folder().run_register) == (folder,)
    assert "the crawl is not built yet" in got.err
    _assert_no_secret_shown(got)
    for secret in (BACKUP_CANARY, DEVICE_CANARY):
        assert _files_hold(data_folder().root, secret) == []


def test_the_first_run_warns_there_is_no_recovery_and_asks_twice(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run())

    assert "cannot be recovered" in got.err
    assert "password manager" in got.err
    assert "New Backup Passphrase: " in got.err
    assert "Type it again: " in got.err


def test_the_prompts_come_in_the_decided_order(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run())

    order = [
        "Type YES to carry on",
        "New Backup Passphrase: ",
        "Set 1 username: ",
        "Password for netops-ro: ",
        "Limit netops-ro to a Platform?",
        "Add another Credential Set? [y/N] ",
        "Start the Run? [Y/n] ",
    ]
    positions = [got.err.index(text) for text in order]
    assert positions == sorted(positions)


def test_the_ready_block_recaps_everything_and_where_it_came_from(
    run: Runner, tmp_path: Path
) -> None:
    run_file = tmp_path / "site-a.toml"
    run_file.write_text(
        'scope = ["192.0.2.0/24"]\nexclude = ["192.0.2.128/25"]\nparallel = 20\n',
        encoding="utf-8",
    )
    answers = typed(
        "YES",
        BACKUP_CANARY,
        BACKUP_CANARY,
        "netops-ro",
        DEVICE_CANARY,
        "1",
        "y",
        "svc-nexus",
        "CANARY-pw-second",
        "2",
        "y",
        "any-user",
        "CANARY-pw-third",
        "",
        "n",
        "n",
    )

    got = run(
        "--from", str(run_file), "--seed", "192.0.2.1", "--failure-budget", "2", typed=answers
    )

    ready = got.out[got.out.index("Ready to start") :]
    assert f"  Run folder      {data_folder().runs}" in ready
    assert "(default; created when you start the Run)" in ready
    assert "  Scope           128 addresses in 1 range (run file)\n" in ready
    assert "                    192.0.2.0/24\n" in ready
    assert "  Exclusions      (run file)\n                    192.0.2.128/25\n" in ready
    assert "  Seeds           192.0.2.1 (command line)\n" in ready
    assert "  Set 1           netops-ro: IOS/IOS-XE only; password held in memory\n" in ready
    assert "  Set 2           svc-nexus: NX-OS only; password held in memory\n" in ready
    assert "  Set 3           any-user: any Platform; password held in memory\n" in ready
    assert "  Failure budget  2 failed logins per set, then it is retired (command line)\n" in (
        ready
    )
    assert (
        "  Options         no label (default); parallel 20 (run file); Sweep off (default)\n"
    ) in ready
    assert "CANARY" not in got.out + got.err


def test_runs_dir_is_shown_as_coming_from_the_command_line(run: Runner, tmp_path: Path) -> None:
    got = run(*FLAGS, "--runs-dir", str(tmp_path / "runs"), typed=first_run(start="n"))

    assert f"  Run folder      {tmp_path / 'runs'}" in got.out
    assert "(command line; created when you start the Run)" in got.out


# -- the Backup Passphrase (stories 20-22) ------------------------------------------------


def test_a_short_passphrase_is_refused_and_asked_again(run: Runner) -> None:
    got = run(*FLAGS, typed=typed("YES", "CANARY-pp-14ch") + first_run()[len("YES\n") :])

    assert got.code == ExitCode.CLEAN
    assert "it must be at least 15 characters" in got.err
    assert "CANARY-pp-14ch" not in got.out + got.err


def test_three_mismatched_entries_stop_the_first_run_before_any_device_password(
    run: Runner,
) -> None:
    other = "CANARY-pp-different"
    answers = typed(
        "YES", BACKUP_CANARY, other, BACKUP_CANARY, other, BACKUP_CANARY, other, "netops-ro"
    )

    got = run(*FLAGS, typed=answers)

    assert got.code == ExitCode.REFUSED
    assert got.err.count("The two entries differ.") == 3
    assert "Set 1 username" not in got.err
    assert not data_folder().check_file.exists()
    assert NOTHING_CONTACTED in got.err


@pytest.mark.usefixtures("check_file_exists")
def test_a_later_run_types_the_passphrase_once_and_it_must_unlock_the_check_file(
    run: Runner,
) -> None:
    got = run(*FLAGS, typed=later_run())

    assert got.code == ExitCode.CLEAN
    assert "Type it again" not in got.err
    assert "it unlocked the check file" in got.err


@pytest.mark.usefixtures("check_file_exists")
def test_a_later_run_gets_three_tries_then_stops_before_any_device_password(
    run: Runner,
) -> None:
    wrong = "CANARY-pp-wrong-one"
    got = run(*FLAGS, typed=typed("YES", wrong, "short", wrong, "netops-ro"))

    assert got.code == ExitCode.REFUSED
    assert "does not unlock the check file (try 1 of 3)" in got.err
    assert "(try 3 of 3)" in got.err
    assert "Set 1 username" not in got.err
    assert NOTHING_CONTACTED in got.err
    assert _run_folders() == []


@pytest.mark.usefixtures("check_file_exists")
def test_a_wrong_passphrase_then_the_right_one_carries_on(run: Runner) -> None:
    got = run(*FLAGS, typed=typed("YES", "CANARY-pp-wrong-one") + later_run()[len("YES\n") :])

    assert got.code == ExitCode.CLEAN
    assert "(try 1 of 3)" in got.err


def test_a_check_file_that_is_not_one_refuses_the_run(run: Runner) -> None:
    check = data_folder().check_file
    check.parent.mkdir(parents=True, exist_ok=True)
    check.write_bytes(fake_age.lock(b"not the check phrase\n", BACKUP_CANARY))

    got = run(*FLAGS, typed=later_run())

    assert got.code == ExitCode.REFUSED
    assert "the check file does not hold the check phrase" in got.err
    assert str(check) in got.err
    assert "Set 1 username" not in got.err


def test_a_run_is_refused_while_a_passphrase_change_is_pending(run: Runner) -> None:
    marker = data_folder().change_pending
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("{}", encoding="utf-8")

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.REFUSED
    assert "change-passphrase" in got.err
    assert "Scope" not in got.out + got.err  # refused before the first question


def test_declining_the_crash_dump_check_stops_before_any_secret(run: Runner) -> None:
    got = run(*FLAGS, typed=typed("no", BACKUP_CANARY, BACKUP_CANARY))

    assert got.code == ExitCode.REFUSED
    assert "Backup Passphrase" not in got.err
    assert not data_folder().check_file.exists()


# -- Credential Sets (stories 23-24, 27) ---------------------------------------------------


def test_up_to_five_sets_are_taken_and_a_sixth_is_never_offered(run: Runner) -> None:
    sets = [line for n in range(1, 6) for line in (f"user{n}", f"CANARY-pw-{n}", "", "y")]
    answers = typed("YES", BACKUP_CANARY, BACKUP_CANARY, *sets[:-1], "y")

    got = run(*FLAGS, typed=answers)

    assert got.code == ExitCode.CLEAN
    assert got.err.count("Add another Credential Set?") == 4
    assert "Set 5           user5: any Platform" in got.out
    assert "Set 6" not in got.out + got.err
    assert "5 Credential Sets, the most a Run takes" in got.err


def test_an_empty_password_is_refused_and_asked_again(run: Runner) -> None:
    answers = typed(
        "YES", BACKUP_CANARY, BACKUP_CANARY, "netops-ro", "", DEVICE_CANARY, "", "n", "y"
    )

    got = run(*FLAGS, typed=answers)

    assert got.code == ExitCode.CLEAN
    assert "A Credential Set needs a password." in got.err
    assert got.err.count("Password for netops-ro: ") == 2


def test_an_empty_username_is_asked_again(run: Runner) -> None:
    answers = typed(
        "YES", BACKUP_CANARY, BACKUP_CANARY, "  ", "netops-ro", DEVICE_CANARY, "", "n", "y"
    )

    got = run(*FLAGS, typed=answers)

    assert got.code == ExitCode.CLEAN
    assert "A username is needed." in got.err


def test_a_platform_choice_that_is_not_on_the_menu_is_asked_again(run: Runner) -> None:
    answers = typed(
        "YES", BACKUP_CANARY, BACKUP_CANARY, "netops-ro", DEVICE_CANARY, "3", "2", "n", "y"
    )

    got = run(*FLAGS, typed=answers)

    assert "Not a choice" in got.err
    assert "netops-ro: NX-OS only" in got.out


def test_a_device_password_that_is_the_passphrase_stops_the_run(run: Runner) -> None:
    answers = typed("YES", BACKUP_CANARY, BACKUP_CANARY, "netops-ro", BACKUP_CANARY, "", "n", "y")

    got = run(*FLAGS, typed=answers)

    assert got.code == ExitCode.REFUSED
    assert "the same as the Backup Passphrase" in got.err
    assert "network-analyser change-passphrase" in got.err
    assert NOTHING_CONTACTED in got.err
    assert "Start the Run?" not in got.err
    assert _run_folders() == []
    _assert_no_secret_shown(got)


def test_usernames_with_control_characters_are_shown_escaped(run: Runner) -> None:
    answers = typed("YES", BACKUP_CANARY, BACKUP_CANARY, "ops\x1b[2J", DEVICE_CANARY, "", "n", "y")

    got = run(*FLAGS, typed=answers)

    assert "\x1b" not in got.out + got.err
    assert "ops\\x1b[2J: any Platform" in got.out


def test_a_label_that_is_a_typed_secret_refuses_the_run_without_showing_it(
    run: Runner,
) -> None:
    label = "CANARY-pw-label"
    answers = typed("YES", BACKUP_CANARY, BACKUP_CANARY, "netops-ro", label, "", "n", "y")

    got = run(*FLAGS, "--label", label, typed=answers)

    assert got.code == ExitCode.REFUSED
    assert "label" in got.err
    assert label not in got.err
    assert _run_folders() == []


# -- cancelling before the start (story 15) -----------------------------------------------


@pytest.mark.parametrize("answer", ["n", "no", "N"])
def test_n_at_the_confirm_cancels_with_exit_3_and_creates_nothing(run: Runner, answer: str) -> None:
    got = run(*FLAGS, typed=first_run(start=answer))

    assert got.code == ExitCode.STOPPED
    assert "Run cancelled. Nothing was contacted." in got.err
    assert _run_folders() == []
    assert backup_store.registered_run_folders(data_folder().run_register) == ()


def test_enter_at_the_confirm_starts_the_run(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run(start=""))

    assert got.code == ExitCode.CLEAN
    assert len(_run_folders()) == 1


def test_an_answer_that_is_not_yes_or_no_is_asked_again(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run(start="maybe") + "y\n")

    assert got.code == ExitCode.CLEAN
    assert got.err.count("Start the Run? [Y/n] ") == 2


def test_input_ending_at_a_secret_prompt_cancels_with_exit_3(run: Runner) -> None:
    got = run(*FLAGS, typed=typed("YES", BACKUP_CANARY, BACKUP_CANARY, "netops-ro"))

    assert got.code == ExitCode.STOPPED
    assert "Cancelled." in got.err
    assert _run_folders() == []


def test_ctrl_c_at_a_prompt_cancels_with_exit_3(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(_self: object, _prompt: str) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr("network_analyser.cli.prompts.Prompter.line", interrupted)

    got = run(*FLAGS)

    assert got.code == ExitCode.STOPPED
    assert "Traceback" not in got.err
    assert _run_folders() == []


# -- secrets come only from the prompts (story 30) ----------------------------------------


@pytest.mark.parametrize(
    "name", ["NETWORK_ANALYSER_PASSPHRASE", "BACKUP_PASSPHRASE", "DEVICE_CANARY", "NA_PASSWORD"]
)
def test_a_secret_in_the_environment_is_never_used(
    run: Runner, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setenv(name, BACKUP_CANARY)

    got = run(*FLAGS, typed=typed("YES"))  # input ends where the passphrase is asked

    assert got.code == ExitCode.STOPPED
    assert "New Backup Passphrase: " in got.err
    assert not data_folder().check_file.exists()
