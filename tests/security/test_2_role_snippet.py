"""Security test 2, `role-snippet` (spec #37, Testing Decisions; stories 167-173; ADR 0005).

For each Platform, local and TACACS+, the generated Device Role permits exactly the
allow-list the tool sends from: every command on it, and nothing else. The role text is
read back here with its own small parser, never with the generator's code, so a generator
that drops, adds or rewrites a command fails.
"""

import re

import pytest

from network_analyser import platforms
from network_analyser.platforms import Exact
from network_analyser.records import Platform

pytestmark = pytest.mark.security

USERNAME = "netops-ro"
BOTH_FORMS = pytest.mark.parametrize("tacacs", [False, True], ids=["local", "TACACS+"])


def allow_list_commands(platform: Platform, username: str) -> list[str]:
    """Every command the tool may send to `platform` when it logs in as `username`."""
    commands: list[str] = []
    for entry in platforms.ALLOW_LISTS[platform].entries:
        if isinstance(entry, Exact):
            commands.append(entry.command)
        else:
            filled = entry.fill(username=username)
            assert filled is not None
            commands.append(filled)
    return commands


def config_lines(text: str) -> list[str]:
    """The lines a device would act on when the snippet is pasted: not comments, not blank."""
    return [line for line in text.splitlines() if line.strip() and not line.startswith("!")]


def commands_in(text: str) -> list[str]:
    """Every command line: those a device acts on, and those to type by hand.

    Prose comments start with one space after the `!`; a command to type by hand is
    indented by three or more.
    """
    typed = re.findall(r"^!\s{3,}(\S.*)$", text, flags=re.MULTILINE)
    return config_lines(text) + typed


def ise_command_set(text: str) -> list[str]:
    """The ISE command set rows, each read back as the one command it permits."""
    rows = re.findall(r"^!\s+(\S+)\s+(\S+)\s+\^(.*)\$$", text, flags=re.MULTILINE)
    assert rows, "no ISE command set"
    commands = []
    for grant, command, arguments in rows:
        if grant == "Grant":
            continue
        assert grant == "PERMIT"
        unescaped = re.sub(r"\\(.)", r"\1", arguments)
        commands.append(f"{command} {unescaped}" if unescaped else command)
    return commands


def exactly(found: list[str], expected: list[str]) -> None:
    assert len(found) == len(set(found)), "a command is listed twice"
    assert sorted(found) == sorted(expected)


# -- IOS/IOS-XE: a CLI view ---------------------------------------------------------------


@BOTH_FORMS
def test_the_ios_xe_view_permits_exactly_the_allow_list(*, tacacs: bool) -> None:
    text = platforms.role_snippet(Platform.IOS_XE, USERNAME, tacacs=tacacs)

    lines = config_lines(text)
    assert lines[0] == "parser view NA-READ"
    included = [line.removeprefix(" commands exec include ") for line in lines[1:]]
    assert all(line.startswith(" commands exec include ") for line in lines[1:])
    exactly(included, allow_list_commands(Platform.IOS_XE, USERNAME))


def test_the_ios_xe_fallback_level_moves_exactly_the_allow_list() -> None:
    text = platforms.role_snippet(Platform.IOS_XE, USERNAME, tacacs=False)

    moved = re.findall(r"^!\s+privilege exec level 7 (.+)$", text, flags=re.MULTILINE)
    exactly(moved, allow_list_commands(Platform.IOS_XE, USERNAME))
    restored = re.findall(r"^!\s+privilege exec level 1 (.+)$", text, flags=re.MULTILINE)
    assert "show" in restored
    assert {command.split()[0] for command in moved} == set(restored)
    assert re.findall(r"^!\s+privilege exec level (\d+) ", text, flags=re.MULTILINE) == (
        ["7"] * len(moved) + ["1"] * len(restored)
    ), "the levels go back to 1 only after every command has moved"


def test_the_ios_xe_tacacs_command_set_permits_exactly_the_allow_list() -> None:
    text = platforms.role_snippet(Platform.IOS_XE, USERNAME, tacacs=True)

    exactly(ise_command_set(text), allow_list_commands(Platform.IOS_XE, USERNAME))
    assert re.search(r"^!\s+cli-view-name=NA-READ$", text, flags=re.MULTILINE)


@BOTH_FORMS
def test_the_ios_xe_role_never_sets_a_file_privilege_or_enable(*, tacacs: bool) -> None:
    text = platforms.role_snippet(Platform.IOS_XE, USERNAME, tacacs=tacacs)

    commands = [line.strip() for line in commands_in(text)]
    assert not [c for c in commands if c.startswith(("file privilege", "enable"))]
    assert "aaa new-model" in text


# -- NX-OS: one custom role ---------------------------------------------------------------


@BOTH_FORMS
def test_the_nx_os_role_permits_exactly_the_allow_list(*, tacacs: bool) -> None:
    text = platforms.role_snippet(Platform.NX_OS, USERNAME, tacacs=tacacs)

    lines = config_lines(text)
    assert lines[0] == "role name NA-READ"
    assert lines[1].startswith("  description ")
    rules = [re.fullmatch(r"  rule (\d+) permit command (.+)", line) for line in lines[2:]]
    assert all(rules), "every other line is a permit-command rule"
    permitted = [rule.group(2) for rule in rules if rule]
    exactly(permitted, allow_list_commands(Platform.NX_OS, USERNAME))
    assert {"terminal length 0", "terminal width 511"} <= set(permitted)
    numbers = [int(rule.group(1)) for rule in rules if rule]
    assert len(set(numbers)) == len(numbers)
    assert all(1 <= n <= 256 for n in numbers)


def test_the_nx_os_tacacs_command_set_permits_exactly_the_allow_list() -> None:
    text = platforms.role_snippet(Platform.NX_OS, USERNAME, tacacs=True)

    exactly(ise_command_set(text), allow_list_commands(Platform.NX_OS, USERNAME))
    assert re.search(r'^!\s+shell:roles="NA-READ"$', text, flags=re.MULTILINE)


@BOTH_FORMS
def test_the_nx_os_role_never_uses_network_operator_or_a_read_rule(*, tacacs: bool) -> None:
    text = platforms.role_snippet(Platform.NX_OS, USERNAME, tacacs=tacacs)

    commands = [line.strip() for line in commands_in(text)]
    assert not [c for c in commands if "permit read" in c or c.startswith("enable")]
    granted = [c for c in commands if re.search(r"\brole network-operator\b", c)]
    assert set(granted) <= {f"no username {USERNAME} role network-operator"}
    assert not re.search(r"shell:roles=.*network-operator", text)
