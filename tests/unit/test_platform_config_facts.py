"""Secret-free config facts, read from a running config at capture time (#96).

Driven through `platforms.read_config_facts` with synthetic configs
(tests/support/device_text). Every fact is a plain value or `Unknown`; no config line,
secret, hash or community string is ever kept.
"""

import pytest

from network_analyser import platforms
from network_analyser.records import Platform
from network_analyser.records.config_facts import (
    ENABLE_PASSWORD,
    ENABLE_SECRET,
    HTTP_SERVER,
    INSECURE_MODE,
    IP_SOURCE_ROUTE,
    LEGACY_SERVICES,
    SECRET_TYPE_0,
    SECRET_TYPE_4,
    SECRET_TYPE_5,
    SECRET_TYPE_6,
    SECRET_TYPE_7,
    SECRET_TYPE_8,
    SECRET_TYPE_9,
    SNMP_GLOBAL_ENFORCE_PRIV,
    SNMP_V1_V2C_COMMUNITIES,
    SNMP_V1_V2C_READ_WRITE_COMMUNITIES,
    SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME,
    SNMP_V1_V2C_READ_WRITE_NO_ACL,
    SNMP_V3_CONFIGURED,
    SNMP_V3_GROUPS_WITHOUT_PRIV,
    SNMP_V3_USERS,
    SNMP_V3_USERS_WITHOUT_PRIV,
    TELNET_LINES,
    FactValue,
)
from network_analyser.records.unknown import Unknown
from tests.support import device_text


def _facts(platform: Platform, text: str) -> dict[str, FactValue]:
    return {fact.name: fact.value for fact in platforms.read_config_facts(platform, text)}


def test_ios_xe_running_config_gives_every_hardening_fact() -> None:
    facts = _facts(Platform.IOS_XE, device_text.IOS_XE_HARDENING_CONFIG)

    assert facts == {
        TELNET_LINES: ("line vty 0 4",),
        SECRET_TYPE_0: 0,
        SECRET_TYPE_4: 0,
        SECRET_TYPE_5: 1,
        SECRET_TYPE_6: 0,
        SECRET_TYPE_7: 2,
        SECRET_TYPE_8: 0,
        SECRET_TYPE_9: 1,
        ENABLE_SECRET: True,
        ENABLE_PASSWORD: True,
        IP_SOURCE_ROUTE: True,
        LEGACY_SERVICES: ("PAD", "finger", "BOOTP", "rcmd", "FTP", "TFTP"),
        HTTP_SERVER: True,
        INSECURE_MODE: False,
        SNMP_V1_V2C_COMMUNITIES: 3,
        SNMP_V1_V2C_READ_WRITE_COMMUNITIES: 2,
        SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME: 1,
        SNMP_V1_V2C_READ_WRITE_NO_ACL: 1,
        SNMP_V3_CONFIGURED: True,
        SNMP_V3_USERS: 1,
        SNMP_V3_USERS_WITHOUT_PRIV: 1,
        SNMP_V3_GROUPS_WITHOUT_PRIV: 1,
    }


def test_nxos_running_config_gives_its_own_hardening_facts() -> None:
    facts = _facts(Platform.NX_OS, device_text.NXOS_HARDENING_CONFIG)

    assert facts == {
        TELNET_LINES: ("line vty",),
        SECRET_TYPE_0: 0,
        SECRET_TYPE_4: 0,
        SECRET_TYPE_5: 1,
        SECRET_TYPE_6: 0,
        SECRET_TYPE_7: 0,
        SECRET_TYPE_8: 0,
        SECRET_TYPE_9: 0,
        IP_SOURCE_ROUTE: False,
        LEGACY_SERVICES: ("FTP",),
        HTTP_SERVER: True,
        SNMP_V1_V2C_COMMUNITIES: 2,
        SNMP_V1_V2C_READ_WRITE_COMMUNITIES: 1,
        SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME: 1,
        SNMP_V1_V2C_READ_WRITE_NO_ACL: 1,
        SNMP_V3_CONFIGURED: True,
        SNMP_V3_USERS: 1,
        SNMP_V3_USERS_WITHOUT_PRIV: 1,
        SNMP_V3_GROUPS_WITHOUT_PRIV: 1,
        SNMP_GLOBAL_ENFORCE_PRIV: False,
    }


def test_a_vty_block_without_transport_input_permits_telnet_by_default() -> None:
    config = "hostname sw-a\nline vty 0 4\n access-class 10 in\n"

    assert _facts(Platform.IOS_XE, config)[TELNET_LINES] == ("line vty 0 4",)


def test_transport_input_none_and_ssh_do_not_permit_telnet() -> None:
    config = (
        "hostname sw-a\nline vty 0 4\n transport input ssh\nline vty 5 15\n transport input none\n"
    )

    assert _facts(Platform.IOS_XE, config)[TELNET_LINES] == ()


def test_nxos_telnet_needs_the_feature_as_well_as_a_vty_block() -> None:
    without = device_text.NXOS_HARDENING_CONFIG.replace("feature telnet\n", "")
    with_feature = device_text.NXOS_HARDENING_CONFIG

    assert _facts(Platform.NX_OS, without)[TELNET_LINES] == ()
    assert _facts(Platform.NX_OS, with_feature)[TELNET_LINES] == ("line vty",)


def test_a_config_with_no_vty_block_leaves_telnet_unknown_never_absent() -> None:
    value = _facts(Platform.IOS_XE, "hostname sw-a\n")[TELNET_LINES]

    assert isinstance(value, Unknown)
    assert "line vty" in value.reason


def test_secret_counts_cover_numbered_password_and_secret_lines_only() -> None:
    config = (
        "hostname sw-a\n"
        "service password-encryption\n"
        "username a password 7 HASH-ONE\n"
        "username b secret 5 HASH-TWO\n"
        "enable secret 9 HASH-THREE\n"
        "snmp-server community public RO\n"
    )

    facts = _facts(Platform.IOS_XE, config)

    assert facts[SECRET_TYPE_7] == 1
    assert facts[SECRET_TYPE_5] == 1
    assert facts[SECRET_TYPE_9] == 1
    assert facts[SECRET_TYPE_6] == 0


def test_nothing_from_the_config_line_reaches_a_fact() -> None:
    for platform, config in (
        (Platform.IOS_XE, device_text.IOS_XE_HARDENING_CONFIG),
        (Platform.NX_OS, device_text.NXOS_HARDENING_CONFIG),
    ):
        shown = repr(platforms.read_config_facts(platform, config))
        for canary in device_text.HARDENING_CANARIES:
            assert canary not in shown


@pytest.mark.parametrize("platform", [Platform.IOS_XE, Platform.NX_OS])
def test_no_source_route_line_reads_as_enabled_because_the_default_is_on(
    platform: Platform,
) -> None:
    assert _facts(platform, "hostname sw-a\n")[IP_SOURCE_ROUTE] is True


def test_the_no_source_route_form_reads_as_disabled() -> None:
    assert _facts(Platform.IOS_XE, "no ip source-route\n")[IP_SOURCE_ROUTE] is False


def test_insecure_mode_and_the_enable_lines_are_ios_facts() -> None:
    config = "system mode insecure\nenable secret 9 HASH\n"

    facts = _facts(Platform.IOS_XE, config)

    assert facts[INSECURE_MODE] is True
    assert facts[ENABLE_SECRET] is True
    # NX-OS has no enable secret, enable password or IOS-XE insecure mode.
    nxos = _facts(Platform.NX_OS, "")
    assert ENABLE_SECRET not in nxos
    assert ENABLE_PASSWORD not in nxos
    assert INSECURE_MODE not in nxos
