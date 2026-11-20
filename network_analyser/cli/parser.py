"""The frozen command-line surface (spec #37, "CLI surface"; decided on #31).

Renaming or removing a command or flag is a breaking change (decision #32). Flags have no
argparse defaults: a flag left out parses as None, so the run file and the prompts can tell
"not given" from "given" (stories 2-4). The defaults below are shown in the help text.
"""

import argparse
import re
import sys
import textwrap
from collections.abc import Callable
from typing import NoReturn, override

from network_analyser import run_output
from network_analyser._version import __version__
from network_analyser.advisories import ProxyConfig
from network_analyser.cli.exit_codes import ExitCode

PROG = "network-analyser"

PARALLEL_DEFAULT = 10
PARALLEL_MAX = 50
FAILURE_BUDGET_DEFAULT = 3
FAILURE_BUDGET_MAX = 5
SWEEP_INFLIGHT_MAX = 100
CONNECT_TIMEOUT_DEFAULT_S = 10
LOGIN_TIMEOUT_DEFAULT_S = 20
COMMAND_TIMEOUT_DEFAULT_S = 60
BACKUP_TIMEOUT_DEFAULT_S = 300
DEVICE_TIMEOUT_DEFAULT_MIN = 15

SECRETS_ARE_NEVER_OPTIONS = (
    "Secrets are never options or environment variables: Credential Set passwords and the "
    "Backup Passphrase are only ever typed at the hidden prompts that follow, so they never "
    "land in shell history or process listings."
)

_DESCRIPTION = f"""\
Network Analyser {__version__}: logs into Cisco IOS/IOS-XE and NX-OS devices inside the IP
ranges you give, backs up their running configuration (encrypted), follows CDP/LLDP to find
more devices, and draws the topology. It is read-only: it never changes a device's
configuration."""

_EXIT_CODES = """\
exit codes (every command):
  0  finished; nothing needs attention
  1  finished; something needs attention (listed at the end and in the Run report)
  2  refused before contacting any device (bad options, Scope or Seeds; folder not
     writable; crash-dump check declined; wrong Backup Passphrase; another Run active)
  3  stopped or cancelled by the operator (Ctrl+C, or "n" at the confirm)
  4  internal error (a short message; never a traceback with values)

Run "network-analyser <command> --help" for its options."""

_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")


class _Parser(argparse.ArgumentParser):
    """An argparse parser that refuses with exit code 2 and never echoes stray arguments."""

    @override
    def error(self, message: str) -> NoReturn:
        if message.startswith("unrecognized arguments"):
            # A stray argument may be a secret typed where it does not belong: never echo it.
            message = f"unrecognized arguments (not shown). {SECRETS_ARE_NEVER_OPTIONS}"
        self.print_usage(sys.stderr)
        self.exit(ExitCode.REFUSED, f"{self.prog}: error: {message}\n")


def _int_between(low: int, high: int | None = None) -> Callable[[str], int]:
    """Return an argparse type that accepts a whole number from low to high."""

    def parse(text: str) -> int:
        try:
            value = int(text, 10)
        except ValueError:
            msg = "must be a whole number"
            raise argparse.ArgumentTypeError(msg) from None
        if value < low or (high is not None and value > high):
            msg = f"must be {low} to {high}" if high is not None else f"must be {low} or more"
            raise argparse.ArgumentTypeError(msg)
        return value

    return parse


def _label(text: str) -> str:
    problem = run_output.label_problem(text)
    if problem is not None:  # the reason never quotes the label
        raise argparse.ArgumentTypeError(problem)
    return text


def _fingerprint(text: str) -> str:
    if not _FINGERPRINT.fullmatch(text):
        msg = "must be an OpenSSH SHA256 fingerprint, SHA256: then 43 base64 characters"
        raise argparse.ArgumentTypeError(msg)
    return text


def _proxy(text: str) -> str:
    """Accept only `host:port` for `--proxy`, with no scheme, path or password (#95)."""
    try:
        ProxyConfig.explicit(text)
    except ValueError:
        msg = "must be host:port, with no scheme or password"
        raise argparse.ArgumentTypeError(msg) from None
    return text


def build_parser() -> argparse.ArgumentParser:
    """Build the parser for every command and flag."""
    parser = _Parser(
        prog=PROG,
        description=_DESCRIPTION,
        epilog=_EXIT_CODES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        color=False,
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    commands = parser.add_subparsers(
        dest="command", metavar="<command>", title="commands", required=True
    )
    _add_run(commands)
    _add_render(commands)
    _add_show_backup(commands)
    _add_trust_key(commands)
    _add_role_snippet(commands)
    _add_change_passphrase(commands)
    return parser


type _Commands = argparse._SubParsersAction[_Parser]  # noqa: SLF001


def _command(commands: _Commands, name: str, summary: str, description: str) -> _Parser:
    return commands.add_parser(
        name, help=summary, description=description, allow_abbrev=False, color=False
    )


def _add_run(commands: _Commands) -> None:
    run = _command(
        commands,
        "run",
        "discover, back up and draw a network (prompts for secrets)",
        f"Start a Run. Anything left out is asked for. {SECRETS_ARE_NEVER_OPTIONS}",
    )
    scope = run.add_argument_group("Scope and Seeds")
    scope.add_argument(
        "--scope",
        action="append",
        metavar="RANGE",
        help="IPv4 CIDR, a-b range or single IP the Run may touch. Repeatable. "
        "Asked at start if none is given.",
    )
    scope.add_argument(
        "--exclude",
        action="append",
        metavar="RANGE",
        help="never touch these addresses, even when advertised. Repeatable.",
    )
    scope.add_argument(
        "--seed",
        action="append",
        metavar="IP",
        help="a device to start the crawl from; must be inside the Scope. Repeatable. "
        "Asked at start if none is given.",
    )
    scope.add_argument(
        "--from",
        dest="run_file",
        metavar="FILE",
        help="read Scope, Seeds and options from a run file (TOML). Options also given on "
        "the command line win. A run file never holds secrets.",
    )

    discovery = run.add_argument_group("Discovery")
    discovery.add_argument(
        "--sweep",
        action="store_true",
        default=None,
        help="also probe every Scope address on TCP 22 to find more Seeds",
    )
    discovery.add_argument(
        "--sweep-inflight",
        type=_int_between(1, SWEEP_INFLIGHT_MAX),
        metavar="N",
        help=f"probes in flight during a Sweep (default {SWEEP_INFLIGHT_MAX}, "
        f"at most {SWEEP_INFLIGHT_MAX})",
    )

    connections = run.add_argument_group("Connections")
    connections.add_argument(
        "--parallel",
        type=_int_between(1, PARALLEL_MAX),
        metavar="N",
        help=f"devices worked on at once (default {PARALLEL_DEFAULT}, at most {PARALLEL_MAX}). "
        f"More than {PARALLEL_DEFAULT} adds load on TACACS+/RADIUS servers.",
    )
    connections.add_argument(
        "--failure-budget",
        type=_int_between(1, FAILURE_BUDGET_MAX),
        metavar="N",
        help="failed logins a Credential Set may spend before it is retired "
        f"(default {FAILURE_BUDGET_DEFAULT}, 1 to {FAILURE_BUDGET_MAX})",
    )
    connections.add_argument(
        "--strict-host-keys",
        action="store_true",
        default=None,
        help="log in only where the host key is already trusted",
    )
    connections.add_argument(
        "--known-hosts",
        metavar="FILE",
        help="extra trusted host keys, OpenSSH format (read, never written)",
    )
    for flag, default, unit in (
        ("--connect-timeout", CONNECT_TIMEOUT_DEFAULT_S, "seconds"),
        ("--login-timeout", LOGIN_TIMEOUT_DEFAULT_S, "seconds"),
        ("--command-timeout", COMMAND_TIMEOUT_DEFAULT_S, "seconds"),
        ("--backup-timeout", BACKUP_TIMEOUT_DEFAULT_S, "seconds"),
        ("--device-timeout", DEVICE_TIMEOUT_DEFAULT_MIN, "minutes"),
    ):
        connections.add_argument(
            flag,
            type=_int_between(1),
            metavar="S" if unit == "seconds" else "M",
            help=f"default {default} ({unit})",
        )

    outputs = run.add_argument_group("Outputs")
    outputs.add_argument(
        "--runs-dir",
        metavar="DIR",
        help=r"parent of the new Run folder (default %%LOCALAPPDATA%%\NetworkAnalyser\runs). "
        "Command line only, never from a run file.",
    )
    outputs.add_argument(
        "--label",
        type=_label,
        metavar="TEXT",
        help=f"added to the Run folder name (letters, digits, - . _; {run_output.LABEL_MAX} "
        "at most)",
    )
    outputs.add_argument(
        "--progress",
        choices=["live", "log", "quiet"],
        help="how progress is shown (default live; log when output is redirected)",
    )

    lookups = run.add_argument_group("Cisco lookups")
    lookups.add_argument(
        "--proxy",
        type=_proxy,
        metavar="HOST:PORT",
        help="HTTP proxy for Cisco's lookups (default: Windows' own proxy setting). "
        "HTTPS_PROXY-style environment variables are never read.",
    )


def _add_render(commands: _Commands) -> None:
    render = _command(
        commands,
        "render",
        "redraw the diagram of an earlier Run, in its Run folder",
        "Redraw diagram.html and diagram.drawio from topology.json, in place. "
        "No device is contacted.",
    )
    render.add_argument("run_folder", metavar="RUN_FOLDER")


def _add_show_backup(commands: _Commands) -> None:
    show_backup = _command(
        commands,
        "show-backup",
        "print one Backup to the console (asks for the Backup Passphrase)",
        "Print one Backup (.cfg.age) to the console. Nothing is written to disk. "
        "With no file named, list a Run's Backups.",
    )
    show_backup.add_argument("backup_file", metavar="BACKUP_FILE", nargs="?")
    show_backup.add_argument(
        "--run-folder",
        metavar="DIR",
        help="with no file named, list this Run folder's Backups instead of the latest Run's",
    )


def _add_trust_key(commands: _Commands) -> None:
    trust_key = _command(
        commands,
        "trust-key",
        "trust a device's new SSH host key after you have checked it",
        "Save a device's SSH host key in the Trust Store, only if the device presents "
        "exactly that fingerprint.",
    )
    trust_key.add_argument("ip", metavar="IP")
    trust_key.add_argument(
        "--fingerprint",
        required=True,
        type=_fingerprint,
        metavar="SHA256:...",
        help="the fingerprint printed in the Run report",
    )


def _add_role_snippet(commands: _Commands) -> None:
    role_snippet = _command(
        commands,
        "role-snippet",
        "print the Device Role config to give the tool's account",
        "Print the Device Role config to paste on a device or AAA server. "
        "The tool never pushes it.",
    )
    role_snippet.add_argument("platform", choices=["ios-xe", "nx-os"])
    role_snippet.add_argument(
        "--username", metavar="NAME", help="the account the role is for (not a secret)"
    )
    role_snippet.add_argument(
        "--tacacs",
        action="store_true",
        help="print the TACACS+ (ISE shell profile and command set) form",
    )


_MANUAL_RESET = r"""forgotten the Backup Passphrase?
  It cannot be recovered, and there is no reset command, so Backups are never abandoned
  by accident. To start over, delete the check file by hand:
    %LOCALAPPDATA%\NetworkAnalyser\passphrase-check.age
  If a change was left unfinished, also delete change-pending.json and
  passphrase-check.previous.age beside it. The next Run then asks for a new passphrase
  twice. Backups locked with the forgotten one stay locked for good: a later
  change-passphrase lists them as not re-locked."""


def _add_change_passphrase(commands: _Commands) -> None:
    change = commands.add_parser(
        "change-passphrase",
        help="re-lock every Backup with a new Backup Passphrase",
        description="Re-lock every Backup and Run manifest in place under a new Backup "
        "Passphrase, one file\nat a time, with no plaintext on disk. If it is interrupted, "
        "run it again to resume.\n\n" + textwrap.fill(SECRETS_ARE_NEVER_OPTIONS, 79),
        epilog=_MANUAL_RESET,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
        color=False,
    )
    change.add_argument(
        "--run-folder",
        action="append",
        metavar="DIR",
        help="also re-lock a Run folder that moved since it was registered. Repeatable.",
    )
