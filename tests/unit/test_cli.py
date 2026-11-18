"""The command-line surface, driven through `main(argv)` as the operator would."""

import argparse
import logging
import re

import pytest

from network_analyser.cli import ExitCode, main
from network_analyser.cli.parser import build_parser


def test_exit_codes_are_the_five_the_spec_defines() -> None:
    assert {code.name: int(code) for code in ExitCode} == {
        "CLEAN": 0,
        "NEEDS_ATTENTION": 1,
        "REFUSED": 2,
        "STOPPED": 3,
        "INTERNAL_ERROR": 4,
    }


def test_version_prints_semver_0_y_z(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--version"])

    out = capsys.readouterr().out
    assert code == ExitCode.CLEAN
    assert re.fullmatch(r"network-analyser 0\.\d+\.\d+\n", out)


FINGERPRINT = "SHA256:" + "A" * 43

EVERY_COMMAND = [
    pytest.param(["run"], id="run"),
    pytest.param(["render", "runs/2026-01-01T000000Z"], id="render"),
    pytest.param(["show-backup", "backups/sw-a.cfg.age"], id="show-backup"),
    pytest.param(["show-backup"], id="show-backup listing"),
    pytest.param(["trust-key", "192.0.2.10", "--fingerprint", FINGERPRINT], id="trust-key"),
    pytest.param(["role-snippet", "ios-xe"], id="role-snippet"),
    pytest.param(["change-passphrase"], id="change-passphrase"),
]


@pytest.mark.parametrize("argv", EVERY_COMMAND)
def test_a_command_not_built_yet_says_so_and_exits_4(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(argv)

    err = capsys.readouterr().err
    assert code == ExitCode.INTERNAL_ERROR
    assert f"network-analyser {argv[0]}: not built yet\n" in err


EVERY_FLAG = [
    pytest.param(
        [
            "run",
            "--scope",
            "192.0.2.0/24",
            "--scope",
            "198.51.100.10-198.51.100.20",
            "--exclude",
            "192.0.2.128/25",
            "--exclude",
            "192.0.2.5",
            "--seed",
            "192.0.2.1",
            "--seed",
            "198.51.100.10",
            "--from",
            "site-a.toml",
            "--sweep",
            "--sweep-inflight",
            "50",
            "--parallel",
            "20",
            "--failure-budget",
            "2",
            "--strict-host-keys",
            "--known-hosts",
            "known_hosts",
            "--connect-timeout",
            "10",
            "--login-timeout",
            "20",
            "--command-timeout",
            "60",
            "--backup-timeout",
            "300",
            "--device-timeout",
            "15",
            "--runs-dir",
            "runs",
            "--label",
            "site-a",
            "--progress",
            "log",
        ],
        id="run",
    ),
    pytest.param(
        ["role-snippet", "nx-os", "--username", "netanalyser", "--tacacs"], id="role-snippet"
    ),
    pytest.param(
        ["change-passphrase", "--run-folder", "old/a", "--run-folder", "old/b"],
        id="change-passphrase",
    ),
]


@pytest.mark.parametrize("argv", EVERY_FLAG)
def test_every_flag_of_the_frozen_surface_parses(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(argv)

    assert code == ExitCode.INTERNAL_ERROR
    assert "not built yet" in capsys.readouterr().err


@pytest.mark.parametrize("progress", ["live", "log", "quiet"])
def test_every_progress_view_parses(progress: str) -> None:
    assert main(["run", "--progress", progress]) == ExitCode.INTERNAL_ERROR


REFUSED = [
    pytest.param([], id="no command"),
    pytest.param(["frobnicate"], id="unknown command"),
    pytest.param(["run", "--parallel", "0"], id="parallel below 1"),
    pytest.param(["run", "--parallel", "51"], id="parallel above 50"),
    pytest.param(["run", "--parallel", "ten"], id="parallel not a number"),
    pytest.param(["run", "--failure-budget", "6"], id="failure budget above 5"),
    pytest.param(["run", "--sweep-inflight", "101"], id="sweep inflight above 100"),
    pytest.param(["run", "--connect-timeout", "0"], id="timeout not positive"),
    pytest.param(["run", "--progress", "fancy"], id="unknown progress view"),
    pytest.param(["run", "--par", "5"], id="abbreviated flag"),
    pytest.param(["role-snippet", "pan-os"], id="unsupported platform"),
    pytest.param(["trust-key", "192.0.2.10"], id="trust-key without fingerprint"),
    pytest.param(
        ["trust-key", "192.0.2.10", "--fingerprint", "MD5:aa:bb"], id="fingerprint not SHA256"
    ),
]


@pytest.mark.parametrize("argv", REFUSED)
def test_bad_options_are_refused_with_exit_2(argv: list[str]) -> None:
    assert main(argv) == ExitCode.REFUSED


def test_run_help_says_secrets_are_never_options_or_environment_variables(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["run", "--help"])

    help_text = " ".join(capsys.readouterr().out.split())
    assert code == ExitCode.CLEAN
    assert "Secrets are never options or environment variables" in help_text
    assert "Credential Set passwords and the Backup Passphrase" in help_text


def test_a_stray_argument_is_refused_without_echoing_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    canary = "canary-Pa55w0rd-1f4e"

    code = main(["run", "--password", canary])

    captured = capsys.readouterr()
    assert code == ExitCode.REFUSED
    assert canary not in captured.out + captured.err
    assert "unrecognized arguments (not shown)" in captured.err


def test_no_option_name_invites_a_secret() -> None:
    names = _every_option_string(build_parser())

    secret_like = re.compile(r"pass|secret|key(?!s)|token|pwd|credential", re.IGNORECASE)
    assert names, "the scan found no options at all"
    assert [n for n in names if secret_like.search(n)] == []


def _every_option_string(parser: argparse.ArgumentParser) -> list[str]:
    names: list[str] = []
    for action in parser._actions:  # noqa: SLF001
        names.extend(action.option_strings)
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            for sub in action.choices.values():
                names.extend(_every_option_string(sub))
    return names


def test_nothing_the_ssh_libraries_log_reaches_the_console(
    capsys: pytest.CaptureFixture[str],
) -> None:
    main(["--version"])
    capsys.readouterr()

    for name in ("netmiko", "paramiko.transport"):
        logging.getLogger(name).error("CANARY-device-output-51e0")

    captured = capsys.readouterr()
    assert "CANARY" not in captured.out + captured.err
