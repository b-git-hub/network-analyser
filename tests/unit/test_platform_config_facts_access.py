"""The SSH, VTY, AAA and timeout config facts, read at capture time (#100).

Driven through `platforms.read_config_facts` with synthetic configs. A fact is a plain value
or `Unknown`; no config line, secret, hash or key is ever kept.
"""

import pytest

from network_analyser import platforms
from network_analyser.records import Platform
from network_analyser.records.config_facts import (
    AAA_ACCOUNTING,
    AAA_AUTHORIZATION,
    AAA_CENTRAL_LOGIN,
    AAA_LOGIN_FALLBACK_NONE,
    AAA_NEW_MODEL,
    EXEC_TIMEOUT_DISABLED_LINES,
    SSH_VERSION,
    TYPE_6_ENABLED,
    VTY_ACCESS_CLASS_MISSING_LINES,
    FactValue,
)
from network_analyser.records.unknown import Unknown
from tests.support import hardening_access_text

_ACCESS_NAMES = frozenset(
    {
        SSH_VERSION,
        VTY_ACCESS_CLASS_MISSING_LINES,
        AAA_LOGIN_FALLBACK_NONE,
        AAA_NEW_MODEL,
        AAA_CENTRAL_LOGIN,
        AAA_AUTHORIZATION,
        AAA_ACCOUNTING,
        EXEC_TIMEOUT_DISABLED_LINES,
        TYPE_6_ENABLED,
    }
)


def _facts(platform: Platform, text: str) -> dict[str, FactValue]:
    """Only this batch's facts, so a later batch's facts do not disturb these tests."""
    return {
        fact.name: fact.value
        for fact in platforms.read_config_facts(platform, text)
        if fact.name in _ACCESS_NAMES
    }


def test_ios_running_config_gives_every_access_fact() -> None:
    facts = _facts(Platform.IOS_XE, hardening_access_text.IOS_XE_ACCESS_CONFIG)

    assert facts == {
        SSH_VERSION: 1,
        VTY_ACCESS_CLASS_MISSING_LINES: ("line vty 5 15",),
        AAA_LOGIN_FALLBACK_NONE: 1,
        AAA_NEW_MODEL: True,
        AAA_CENTRAL_LOGIN: True,
        AAA_AUTHORIZATION: True,
        AAA_ACCOUNTING: True,
        EXEC_TIMEOUT_DISABLED_LINES: ("line con 0",),
        TYPE_6_ENABLED: True,
    }


def test_nxos_running_config_gives_its_access_facts() -> None:
    facts = _facts(Platform.NX_OS, hardening_access_text.NXOS_ACCESS_CONFIG)

    assert facts[VTY_ACCESS_CLASS_MISSING_LINES] == ()
    assert facts[AAA_LOGIN_FALLBACK_NONE] == 1
    assert facts[AAA_CENTRAL_LOGIN] is True
    assert facts[AAA_AUTHORIZATION] is True
    assert facts[AAA_ACCOUNTING] is True
    assert facts[EXEC_TIMEOUT_DISABLED_LINES] == ("line console",)
    # NX-OS has no `aaa new-model` or `ip ssh version` fact; AES type 6 is unconfirmed.
    assert AAA_NEW_MODEL not in facts
    assert SSH_VERSION not in facts
    assert isinstance(facts[TYPE_6_ENABLED], Unknown)
    assert "NX-OS" in facts[TYPE_6_ENABLED].reason


def test_ip_ssh_version_reads_its_value_and_zero_when_absent() -> None:
    assert _facts(Platform.IOS_XE, "ip ssh version 2\n")[SSH_VERSION] == 2
    assert _facts(Platform.IOS_XE, "ip ssh version 1\n")[SSH_VERSION] == 1
    assert _facts(Platform.IOS_XE, "hostname sw-a\n")[SSH_VERSION] == 0


def test_a_vty_block_needs_an_inbound_access_class() -> None:
    missing = _facts(
        Platform.IOS_XE,
        "line vty 0 4\n"
        " access-class 10 in\n"
        "line vty 5 15\n"
        " access-class 11 out\n"
        "line vty 16 20\n"
        " exec-timeout 10 0\n",
    )[VTY_ACCESS_CLASS_MISSING_LINES]

    assert missing == ("line vty 5 15", "line vty 16 20")


def test_console_access_class_does_not_cover_a_vty_block() -> None:
    missing = _facts(
        Platform.IOS_XE,
        "line con 0\n access-class 10 in\nline vty 0 4\n exec-timeout 10 0\n",
    )[VTY_ACCESS_CLASS_MISSING_LINES]

    assert missing == ("line vty 0 4",)


def test_a_config_with_no_vty_block_leaves_the_access_class_unknown() -> None:
    value = _facts(Platform.IOS_XE, "hostname sw-a\n")[VTY_ACCESS_CLASS_MISSING_LINES]

    assert isinstance(value, Unknown)
    assert "line vty" in value.reason


def test_aaa_login_fallback_none_counts_each_method_list_once() -> None:
    facts = _facts(
        Platform.IOS_XE,
        "aaa new-model\n"
        "aaa authentication login default group tacacs+ none\n"
        "aaa authentication login CONSOLE group radius none\n"
        "aaa authentication login VTY local\n"
        "aaa authorization commands 15 default group tacacs+\n",
    )

    assert facts[AAA_LOGIN_FALLBACK_NONE] == 2


def test_aaa_central_login_needs_a_server_group_not_just_local() -> None:
    central = _facts(Platform.IOS_XE, "aaa authentication login default group tacacs+ local\n")
    local_only = _facts(Platform.IOS_XE, "aaa authentication login default local\n")
    absent = _facts(Platform.IOS_XE, "hostname sw-a\n")

    assert central[AAA_CENTRAL_LOGIN] is True
    assert local_only[AAA_CENTRAL_LOGIN] is False
    assert absent[AAA_CENTRAL_LOGIN] is False


def test_aaa_authorization_and_accounting_read_any_configured_command() -> None:
    facts = _facts(
        Platform.IOS_XE,
        "aaa authorization exec default group tacacs+ local\n"
        "aaa accounting network default start-stop group tacacs+\n",
    )

    assert facts[AAA_AUTHORIZATION] is True
    assert facts[AAA_ACCOUNTING] is True


def test_exec_timeout_zero_is_read_for_console_and_vty_but_not_aux() -> None:
    facts = _facts(
        Platform.IOS_XE,
        "line con 0\n exec-timeout 0 0\n"
        "line vty 0 4\n exec-timeout 0\n"
        "line aux 0\n exec-timeout 0 1\n"
        "line vty 5 15\n exec-timeout 10 0\n",
    )

    assert facts[EXEC_TIMEOUT_DISABLED_LINES] == ("line con 0", "line vty 0 4")


def test_an_absent_exec_timeout_is_the_vendor_default_not_a_hit() -> None:
    facts = _facts(Platform.IOS_XE, "line vty 0 4\n transport input ssh\n")

    assert facts[EXEC_TIMEOUT_DISABLED_LINES] == ()


def test_type_6_is_enabled_only_by_the_aes_encryption_line() -> None:
    enabled = _facts(Platform.IOS_XE, "password encryption aes\n")
    service_only = _facts(Platform.IOS_XE, "service password-encryption\n")

    assert enabled[TYPE_6_ENABLED] is True
    assert service_only[TYPE_6_ENABLED] is False


@pytest.mark.parametrize(
    "config",
    [
        hardening_access_text.IOS_XE_ACCESS_CONFIG,
        hardening_access_text.NXOS_ACCESS_CONFIG,
    ],
)
def test_nothing_from_the_config_line_reaches_a_fact(config: str) -> None:
    shown = repr(platforms.read_config_facts(Platform.IOS_XE, config)) + repr(
        platforms.read_config_facts(Platform.NX_OS, config)
    )

    for canary in hardening_access_text.ACCESS_CANARIES:
        assert canary not in shown
