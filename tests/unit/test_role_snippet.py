"""The Device Role snippet beyond exactness (stories 167-173; ADR 0005).

Exactness against the allow-list is security test 2 (tests/security/test_2_role_snippet.py).
These cover the account name, the advice the snippet carries, and how the generator refuses
an allow-list it cannot express exactly. Each Platform's generator takes the allow-list as
a keyword, so a future entry can be tried here without changing the compiled-in list.
"""

from collections.abc import Callable

import pytest

from network_analyser import platforms
from network_analyser.cli import ExitCode, main
from network_analyser.platforms import AllowList, Exact, RoleError, Template
from network_analyser.platforms.ios_xe import role as ios_xe_role
from network_analyser.platforms.nxos import role as nxos_role
from network_analyser.records import Platform

EVERY_FORM = [
    pytest.param(platform, tacacs, id=f"{platform.name}-{'tacacs' if tacacs else 'local'}")
    for platform in Platform
    for tacacs in (False, True)
]


@pytest.mark.parametrize(("platform", "tacacs"), EVERY_FORM)
def test_username_fills_in_the_account_name(platform: Platform, *, tacacs: bool) -> None:
    text = platforms.role_snippet(platform, "svc.nexus_2", tacacs=tacacs)

    assert "account svc.nexus_2 on" in text
    assert "<username>" not in text


def test_without_a_username_a_placeholder_stands_for_it() -> None:
    text = platforms.role_snippet(Platform.NX_OS, None, tacacs=False)

    assert "  rule 4 permit command show user-account <username>\n" in text
    assert "!   username <username> password <password> role NA-READ\n" in text


@pytest.mark.parametrize(("platform", "tacacs"), EVERY_FORM)
def test_every_form_advises_a_dedicated_account_and_says_it_is_only_printed(
    platform: Platform, *, tacacs: bool
) -> None:
    text = platforms.role_snippet(platform, "netanalyser", tacacs=tacacs)

    assert "own dedicated account" in text
    assert "never configures a device" in text
    assert "There is no enable\n! step" in text
    assert text.isascii()
    assert all(len(line) <= 88 for line in text.splitlines())


@pytest.mark.parametrize("platform", list(Platform), ids=lambda p: p.name)
def test_the_tacacs_form_says_radius_cannot_authorise_commands(platform: Platform) -> None:
    text = platforms.role_snippet(platform, "netanalyser", tacacs=True)

    assert "RADIUS cannot authorise commands" in text
    assert 'Permit any command that is not listed\n! below" unticked' in text


def test_nx_os_tacacs_says_command_authorisation_makes_the_command_set_the_only_check() -> None:
    text = platforms.role_snippet(Platform.NX_OS, "netanalyser", tacacs=True)

    assert "switches the device's role checks off" in text
    assert "this command set becomes the only command check" in text


def test_ios_xe_tacacs_keeps_the_view_and_names_the_level_15_case() -> None:
    text = platforms.role_snippet(Platform.IOS_XE, "netanalyser", tacacs=True)

    assert "!   aaa authorization exec default group <your TACACS+ group> local\n" in text
    assert "makes the command set the only check" in text


def test_ios_xe_states_the_aaa_new_model_requirement_and_its_risk() -> None:
    text = platforms.role_snippet(Platform.IOS_XE, "netanalyser", tacacs=False)

    assert "The view needs aaa new-model" in text
    assert "never removing aaa new-model" in text
    assert "!   aaa authorization exec default local\n" in text


def test_secrets_are_typed_by_hand_never_part_of_the_pasted_lines() -> None:
    text = platforms.role_snippet(Platform.IOS_XE, "netanalyser", tacacs=False)

    assert "!    secret <view secret>\n" in text
    assert "!   username netanalyser view NA-READ algorithm-type scrypt secret <password>\n" in (
        text
    )
    pasted = [line for line in text.splitlines() if not line.startswith("!")]
    assert not [line for line in pasted if "secret" in line or "password" in line]


def test_the_ise_command_set_escapes_regular_expression_characters() -> None:
    text = platforms.role_snippet(Platform.NX_OS, "svc.nexus_2", tacacs=True)

    assert "!     PERMIT  show      ^user-account svc\\.nexus_2$\n" in text


@pytest.mark.parametrize(
    "username",
    ["", " ", "a b", "-a", ".a", "a" * 33, "a\nconfigure terminal", "a;reload", "user@corp"],
    ids=repr,
)
def test_a_username_that_does_not_fit_is_refused(username: str) -> None:
    problem = platforms.role_username_problem(username)

    assert problem is not None
    assert username.strip() == "" or username not in problem
    with pytest.raises(RoleError):
        platforms.role_snippet(Platform.IOS_XE, username, tacacs=False)


@pytest.mark.parametrize("username", ["netanalyser", "svc.nexus_2", "a", "A" * 32])
def test_a_plain_username_fits(username: str) -> None:
    assert platforms.role_username_problem(username) is None


VRF_TEMPLATE = Template("show ip arp vrf {vrf}", {"vrf": r"[A-Za-z0-9_-]{1,32}"})


@pytest.mark.parametrize(
    "generate", [ios_xe_role.role_snippet, nxos_role.role_snippet], ids=["IOS-XE", "NX-OS"]
)
def test_a_template_with_no_exact_role_form_is_refused_not_widened(
    generate: Callable[..., str],
) -> None:
    allow_list = AllowList((Exact("show version"), VRF_TEMPLATE))

    with pytest.raises(RoleError):
        generate("netanalyser", tacacs=False, allow_list=allow_list)


def test_nx_os_refuses_more_rules_than_a_role_holds() -> None:
    allow_list = AllowList(tuple(Exact(f"show version {n}") for n in range(257)))

    with pytest.raises(RoleError):
        nxos_role.role_snippet("netanalyser", tacacs=False, allow_list=allow_list)


def test_the_ios_xe_fallback_refuses_a_keyword_whose_default_level_is_unchecked() -> None:
    allow_list = AllowList((Exact("show version"), Exact("dir flash:")))

    with pytest.raises(RoleError):
        ios_xe_role.role_snippet("netanalyser", tacacs=False, allow_list=allow_list)


# -- The command ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "platform", "tacacs"),
    [
        (["role-snippet", "ios-xe", "--username", "netanalyser"], Platform.IOS_XE, False),
        (["role-snippet", "nx-os", "--username", "netanalyser", "--tacacs"], Platform.NX_OS, True),
    ],
    ids=["ios-xe", "nx-os --tacacs"],
)
def test_the_command_prints_the_role_and_contacts_nothing(
    argv: list[str], platform: Platform, *, tacacs: bool, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(argv)  # tests/conftest.py refuses every connection

    out = capsys.readouterr().out
    assert code == ExitCode.CLEAN
    first, _, rest = out.partition("\n")
    assert first.startswith("! Generated by network-analyser 0.")
    assert first.endswith(f" {' '.join(argv)}")
    assert rest == platforms.role_snippet(platform, "netanalyser", tacacs=tacacs)


def test_the_command_without_a_username_prints_the_placeholder(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["role-snippet", "nx-os"])

    assert code == ExitCode.CLEAN
    assert "show user-account <username>" in capsys.readouterr().out


def test_the_command_refuses_a_username_that_does_not_fit_without_echoing_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["role-snippet", "ios-xe", "--username", "bad name\x1b[2J"])

    captured = capsys.readouterr()
    assert code == ExitCode.REFUSED
    assert captured.out == ""
    assert "network-analyser role-snippet: refused: the username must be" in captured.err
    assert "bad name" not in captured.err
