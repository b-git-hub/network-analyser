"""`network-analyser run` up to the checked Scope and Seeds, driven as the operator would.

Until the Run-start ticket lands, `run` stops after showing the checked Scope and Seeds
(ticket #41) and exits 4 with a "not built yet" line. Nothing is ever contacted.
"""

import io
from dataclasses import dataclass
from pathlib import Path

import pytest

from network_analyser.cli import ExitCode, main

NOT_BUILT = "The rest of the Run is not built yet; nothing was contacted."
NOTHING_CONTACTED = "Nothing was contacted."


@dataclass(frozen=True)
class Outcome:
    code: int
    out: str
    err: str


class Runner:
    """Runs `network-analyser run` with what the operator types on stdin."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        self._monkeypatch = monkeypatch
        self._capsys = capsys

    def __call__(self, *argv: str, typed: str = "") -> Outcome:
        self._monkeypatch.setattr("sys.stdin", io.StringIO(typed))
        code = main(["run", *argv])
        captured = self._capsys.readouterr()
        return Outcome(code, captured.out, captured.err)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    return Runner(monkeypatch, capsys)


def _write(tmp_path: Path, text: str) -> str:
    path = tmp_path / "site-a.toml"
    path.write_text(text, encoding="utf-8")
    return str(path)


# -- flags (stories 1, 7-10) --------------------------------------------------------------


def test_flags_give_the_scope_and_seeds_and_the_run_stops_before_anything_else(
    run: Runner,
) -> None:
    got = run("--scope", "192.0.2.0/24", "--exclude", "192.0.2.128/25", "--seed", "192.0.2.1")

    assert got.code == ExitCode.INTERNAL_ERROR
    assert "Scope (command line): 128 addresses in 1 range\n  192.0.2.0/24\n" in got.out
    assert "Exclusions (command line):\n  192.0.2.128/25\n" in got.out
    assert "Seeds (command line): 192.0.2.1\n" in got.out
    assert NOT_BUILT in got.err


def test_overlapping_flags_are_merged_and_the_warning_is_shown(run: Runner) -> None:
    got = run("--scope", "192.0.2.0/24", "--scope", "192.0.2.0/25", "--seed", "192.0.2.1")

    assert "Scope (command line): 256 addresses in 1 range" in got.out
    assert (
        "Warning: overlapping entries 192.0.2.0/24, 192.0.2.0/25 were merged into 192.0.2.0/24"
        in got.out
    )


def test_a_bad_scope_flag_refuses_the_run_in_full_with_exit_2(run: Runner) -> None:
    got = run(
        "--scope",
        "192.0.2.1/24",
        "--scope",
        "203.0.113.0/24",
        "--exclude",
        "2001:db8::1",
        "--seed",
        "203.0.113.1",
        typed="192.0.2.0/24\n\n",
    )

    assert got.code == ExitCode.REFUSED
    assert "  192.0.2.1/24: host bits are set (did you mean 192.0.2.0/24?)\n" in got.err
    assert "  exclusion 2001:db8::1: IPv6 is not supported in v1\n" in got.err
    assert NOTHING_CONTACTED in got.err
    assert "Scope>" not in got.out, "a Scope from flags is refused, never asked again"


def test_a_seed_outside_the_scope_refuses_the_run(run: Runner) -> None:
    got = run("--scope", "192.0.2.0/24", "--seed", "198.51.100.1")

    assert got.code == ExitCode.REFUSED
    assert "  Seed 198.51.100.1: this Seed is outside the Scope\n" in got.err


def test_an_exclusion_that_matches_nothing_refuses_a_scope_from_flags(run: Runner) -> None:
    got = run("--scope", "192.0.2.0/24", "--exclude", "198.51.100.0/24", "--seed", "192.0.2.1")

    assert got.code == ExitCode.REFUSED
    assert "exclusion 198.51.100.0/24: this exclusion matches nothing in the Scope" in got.err


def test_control_characters_in_a_refused_entry_are_shown_escaped(run: Runner) -> None:
    got = run("--scope", "\x1b[2Jsw-a", "--seed", "192.0.2.1")

    assert got.code == ExitCode.REFUSED
    assert "\x1b" not in got.err
    assert "\\x1b[2Jsw-a: hostnames are refused" in got.err


# -- asked at the prompt (stories 4-6) ----------------------------------------------------


def test_with_no_flags_the_scope_and_seeds_are_asked_and_bad_lines_asked_again(
    run: Runner,
) -> None:
    lines = [
        "sw-a",  # refused, asked again
        "192.0.2.0/24",
        "!192.0.2.128/25",
        "!198.51.100.0/24",  # matches nothing: dropped and named
        "",
        "198.51.100.1",  # Seed outside the Scope: asked again
        "192.0.2.1, 192.0.2.2",
    ]
    typed = "".join(f"{line}\n" for line in lines)

    got = run(typed=typed)

    assert got.code == ExitCode.INTERNAL_ERROR
    assert "Refused: sw-a: hostnames are refused; give an IPv4 address. Enter that line again." in (
        got.out
    )
    assert "Dropped !198.51.100.0/24: it matches nothing in the Scope." in got.out
    assert "Scope (asked): 128 addresses in 1 range\n  192.0.2.0/24\n" in got.out
    assert "Exclusions (asked):\n  192.0.2.128/25\n" in got.out
    assert "Refused: Seed 198.51.100.1: this Seed is outside the Scope." in got.out
    assert "Seeds (asked): 192.0.2.1, 192.0.2.2\n" in got.out


def test_an_empty_scope_is_not_accepted_at_the_prompt(run: Runner) -> None:
    got = run(typed="\n!192.0.2.5\n\n192.0.2.0/24\n\n192.0.2.1\n")

    assert got.out.count("At least one Scope entry is needed.") == 2
    assert "Seeds (asked): 192.0.2.1" in got.out


def test_exclusions_that_remove_everything_are_refused_and_the_prompt_goes_on(
    run: Runner,
) -> None:
    got = run(typed="192.0.2.0/25\n!192.0.2.0/25\n\n198.51.100.0/24\n\n198.51.100.1\n")

    assert "Refused: the exclusions remove every address in the Scope." in got.out
    assert "Scope (asked): 256 addresses in 2 ranges" in got.out


def test_seeds_are_asked_when_only_the_scope_was_given(run: Runner) -> None:
    got = run("--scope", "192.0.2.0/24", typed="\n192.0.2.9\n")

    assert "At least one Seed is needed." in got.out
    assert "Scope (command line): 256 addresses" in got.out
    assert "Seeds (asked): 192.0.2.9" in got.out


def test_input_ending_before_the_scope_is_complete_refuses_the_run(run: Runner) -> None:
    got = run(typed="192.0.2.0/24\n")

    assert got.code == ExitCode.REFUSED
    assert "Input ended before the Scope and Seeds were complete." in got.err


# -- the run file (stories 2-3, 12-13) ----------------------------------------------------

FULL_FILE = """\
# A synthetic run file.
label = "site-a"
scope = ["192.0.2.0/24", "198.51.100.0/24"]
exclude = ["192.0.2.128/25"]
seeds = ["192.0.2.1"]
parallel = 20
failure_budget = 2
sweep = true
"""


def test_a_run_file_gives_every_setting_and_says_where_each_came_from(
    run: Runner, tmp_path: Path
) -> None:
    got = run("--from", _write(tmp_path, FULL_FILE))

    assert got.code == ExitCode.INTERNAL_ERROR
    assert "Scope (run file): 384 addresses in 2 ranges" in got.out
    assert "Exclusions (run file):\n  192.0.2.128/25\n" in got.out
    assert "Seeds (run file): 192.0.2.1" in got.out
    assert (
        "Options: label site-a (run file); parallel 20 (run file); "
        "failure budget 2 (run file); Sweep on (run file)"
    ) in got.out


def test_flags_win_over_the_run_file(run: Runner, tmp_path: Path) -> None:
    got = run(
        "--from",
        _write(tmp_path, FULL_FILE),
        "--seed",
        "198.51.100.7",
        "--parallel",
        "5",
        "--label",
        "site-b",
    )

    assert "Scope (run file): 384 addresses" in got.out
    assert "Seeds (command line): 198.51.100.7" in got.out
    assert "label site-b (command line); parallel 5 (command line)" in got.out


def test_options_left_out_everywhere_take_their_defaults(run: Runner) -> None:
    got = run("--scope", "192.0.2.0/24", "--seed", "192.0.2.1")

    assert (
        "Options: no label (default); parallel 10 (default); failure budget 3 (default); "
        "Sweep off (default)"
    ) in got.out


def test_a_run_file_without_a_scope_has_it_asked(run: Runner, tmp_path: Path) -> None:
    got = run("--from", _write(tmp_path, 'seeds = ["192.0.2.1"]\n'), typed="192.0.2.0/24\n\n")

    assert "Scope (asked): 256 addresses" in got.out
    assert "Seeds (run file): 192.0.2.1" in got.out


def test_a_bad_scope_entry_in_a_run_file_refuses_the_run(run: Runner, tmp_path: Path) -> None:
    got = run(
        "--from", _write(tmp_path, 'scope = ["192.0.2.20-192.0.2.10"]\nseeds = ["192.0.2.15"]\n')
    )

    assert got.code == ExitCode.REFUSED
    assert "Refused: the Scope from the run file has problems:" in got.err
    assert "192.0.2.20-192.0.2.10: the range is reversed" in got.err


CANARY = "CANARY-pw-7c1d"


@pytest.mark.parametrize(
    "line",
    [
        f'password = "{CANARY}"',
        f'Backup_Passphrase = "{CANARY}"',
        f'api-token = "{CANARY}"',
        f'[set1]\nusername = "netops"\npassword = "{CANARY}"',
        f'[[credential_sets]]\nsecret = "{CANARY}"',
    ],
    ids=["password", "passphrase", "token", "nested", "array of tables"],
)
def test_a_run_file_holding_a_secret_refuses_the_run_without_showing_it(
    run: Runner, tmp_path: Path, line: str
) -> None:
    got = run("--from", _write(tmp_path, f'scope = ["192.0.2.0/24"]\n{line}\n'))

    assert got.code == ExitCode.REFUSED
    assert "A run file never holds secrets" in got.err
    assert CANARY not in got.out + got.err


def test_a_run_file_may_not_set_the_runs_folder(run: Runner, tmp_path: Path) -> None:
    got = run("--from", _write(tmp_path, 'scope = ["192.0.2.0/24"]\nruns_dir = "D:/x"\n'))

    assert got.code == ExitCode.REFUSED
    assert "runs_dir: the Runs folder is set only with --runs-dir on the command line" in got.err


def test_a_run_file_with_an_unknown_key_is_refused(run: Runner, tmp_path: Path) -> None:
    got = run("--from", _write(tmp_path, 'scope = ["192.0.2.0/24"]\nsweeps = true\n'))

    assert got.code == ExitCode.REFUSED
    assert "sweeps: not a run file key" in got.err


@pytest.mark.parametrize(
    ("line", "problem"),
    [
        ('parallel = "ten"', "parallel: must be a whole number from 1 to 50"),
        ("parallel = 51", "parallel: must be a whole number from 1 to 50"),
        ("parallel = true", "parallel: must be a whole number from 1 to 50"),
        ("failure_budget = 6", "failure_budget: must be a whole number from 1 to 5"),
        ('sweep = "yes"', "sweep: must be true or false"),
        ("label = 7", "label: must be text"),
        ('seeds = "192.0.2.1"', "seeds: must be a list of text entries"),
        ("seeds = []", "seeds: must not be empty"),
        ("exclude = [1]", "exclude: must be a list of text entries"),
    ],
)
def test_a_run_file_value_of_the_wrong_kind_is_refused(
    run: Runner, tmp_path: Path, line: str, problem: str
) -> None:
    got = run("--from", _write(tmp_path, f'scope = ["192.0.2.0/24"]\n{line}\n'))

    assert got.code == ExitCode.REFUSED
    assert problem in got.err


def test_a_run_file_that_is_not_toml_is_refused_without_quoting_it(
    run: Runner, tmp_path: Path
) -> None:
    got = run("--from", _write(tmp_path, f'scope = ["192.0.2.0/24"]\n{CANARY} oops\n'))

    assert got.code == ExitCode.REFUSED
    assert "is not valid TOML (line 2)" in got.err
    assert CANARY not in got.out + got.err


def test_a_missing_run_file_is_refused(run: Runner, tmp_path: Path) -> None:
    got = run("--from", str(tmp_path / "missing.toml"))

    assert got.code == ExitCode.REFUSED
    assert "cannot be read" in got.err
