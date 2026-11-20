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
SAMPLE_VRF = "BLUE"
BOTH_FORMS = pytest.mark.parametrize("tacacs", [False, True], ids=["local", "TACACS+"])


def allow_list_commands(platform: Platform, username: str) -> list[str]:
    """Every command the tool may send to `platform` when it logs in as `username`.

    A per-VRF template (#59) is filled with a sample VRF name.
    """
    commands: list[str] = []
    for entry in platforms.ALLOW_LISTS[platform].entries:
        if isinstance(entry, Exact):
            commands.append(entry.command)
        else:
            sample = {"username": username, "vrf": SAMPLE_VRF}
            filled = entry.fill(**{name: sample[name] for name in entry.parameters})
            assert filled is not None
            commands.append(filled)
    return commands


def role_rules(platform: Platform, username: str) -> list[str]:
    """Every allow-list entry as a CLI view or privilege-level rule names it (#59).

    An exact command, or the username template filled, is itself. A template with any other
    parameter (a VRF name) is its words before that parameter: the view and the privilege
    level cannot name every VRF (provisional: lab check C14).
    """
    rules: list[str] = []
    for entry in platforms.ALLOW_LISTS[platform].entries:
        if isinstance(entry, Exact):
            rules.append(entry.command)
        elif set(entry.parameters) == {"username"}:
            filled = entry.fill(username=username)
            assert filled is not None
            rules.append(filled)
        else:
            rules.append(entry.text.partition("{")[0].rstrip())
    return rules


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


def ise_command_set(text: str) -> list[tuple[str, str]]:
    """The ISE command set rows, each as its command word and anchored arguments pattern."""
    rows = re.findall(r"^!\s+(\S+)\s+(\S+)\s+(\^.*\$)$", text, flags=re.MULTILINE)
    assert rows, "no ISE command set"
    assert all(grant == "PERMIT" for grant, _, _ in rows)
    return [(command, arguments) for _, command, arguments in rows]


def ise_permits(rows: list[tuple[str, str]], command: str) -> list[int]:
    """The rows that permit `command`, as ISE matches it: the word, then the arguments."""
    word, _, arguments = command.partition(" ")
    return [n for n, (w, pattern) in enumerate(rows) if w == word and re.search(pattern, arguments)]


def ise_permits_exactly(text: str, platform: Platform) -> None:
    """Each allow-list command passes exactly one row; each row passes one; nothing longer."""
    rows = ise_command_set(text)
    commands = allow_list_commands(platform, USERNAME)
    assert len(rows) == len(commands)
    assert sorted(n for c in commands for n in ise_permits(rows, c)) == list(range(len(rows)))
    for command in commands:
        assert not ise_permits(rows, f"{command} detail"), command
        assert not ise_permits(rows, f"{command} | include x"), command
    assert not ise_permits(rows, f"show ip arp vrf {SAMPLE_VRF} x")
    assert not ise_permits(rows, "show ip arp vrf a b")


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
    exactly(included, role_rules(Platform.IOS_XE, USERNAME))
    assert not [line for line in included if line.startswith("all ")], "never every subcommand"


def test_a_per_vrf_rule_is_the_whole_command_up_to_the_vrf_name() -> None:
    templates = [
        e
        for e in platforms.ALLOW_LISTS[Platform.IOS_XE].entries
        if not isinstance(e, Exact) and "vrf" in e.parameters
    ]
    text = platforms.role_snippet(Platform.IOS_XE, USERNAME, tacacs=False)

    assert templates, "IOS/IOS-XE has per-VRF commands (#59)"
    for template in templates:
        filled = template.fill(vrf=SAMPLE_VRF)
        assert filled is not None
        before, _, _ = filled.partition(f" {SAMPLE_VRF}")
        assert before.endswith(" vrf")
        assert f" commands exec include {before}\n" in text


def test_the_ios_xe_fallback_level_moves_exactly_the_allow_list() -> None:
    text = platforms.role_snippet(Platform.IOS_XE, USERNAME, tacacs=False)

    moved = re.findall(r"^!\s+privilege exec level 7 (.+)$", text, flags=re.MULTILINE)
    exactly(moved, role_rules(Platform.IOS_XE, USERNAME))
    restored = re.findall(r"^!\s+privilege exec level 1 (.+)$", text, flags=re.MULTILINE)
    assert "show" in restored
    assert {command.split()[0] for command in moved} == set(restored)
    assert re.findall(r"^!\s+privilege exec level (\d+) ", text, flags=re.MULTILINE) == (
        ["7"] * len(moved) + ["1"] * len(restored)
    ), "the levels go back to 1 only after every command has moved"


def test_the_ios_xe_tacacs_command_set_permits_exactly_the_allow_list() -> None:
    text = platforms.role_snippet(Platform.IOS_XE, USERNAME, tacacs=True)

    ise_permits_exactly(text, Platform.IOS_XE)
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

    ise_permits_exactly(text, Platform.NX_OS)
    assert re.search(r'^!\s+shell:roles="NA-READ"$', text, flags=re.MULTILINE)


@BOTH_FORMS
def test_the_nx_os_role_never_uses_network_operator_or_a_read_rule(*, tacacs: bool) -> None:
    text = platforms.role_snippet(Platform.NX_OS, USERNAME, tacacs=tacacs)

    commands = [line.strip() for line in commands_in(text)]
    assert not [c for c in commands if "permit read" in c or c.startswith("enable")]
    granted = [c for c in commands if re.search(r"\brole network-operator\b", c)]
    assert set(granted) <= {f"no username {USERNAME} role network-operator"}
    assert not re.search(r"shell:roles=.*network-operator", text)
