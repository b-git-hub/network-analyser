"""Secret-free config facts, read from a running config at capture time (#96).

Driven through `platforms.read_config_facts` with synthetic configs
(tests/support/device_text). Every fact is a plain value or `Unknown`; no config line,
secret, hash or community string is ever kept.
"""

import pytest

from network_analyser import platforms
from network_analyser.records import Platform
from network_analyser.records.analysis import SNMP_V3_USER_CRYPTO
from network_analyser.records.config_facts import (
    AAA_ACCOUNTING,
    AAA_AUTHORIZATION,
    AAA_CENTRAL_LOGIN,
    AAA_LOGIN_FALLBACK_NONE,
    AAA_NEW_MODEL,
    ENABLE_PASSWORD,
    ENABLE_SECRET,
    EXEC_TIMEOUT_DISABLED_LINES,
    FHRP_GROUPS,
    FHRP_GROUPS_WITHOUT_AUTHENTICATION,
    HTTP_SERVER,
    ICMP_REDIRECTS_L3_INTERFACES,
    ICMP_UNREACHABLES_L3_INTERFACES,
    INSECURE_MODE,
    IP_SOURCE_ROUTE,
    LEGACY_SERVICES,
    LOGIN_BLOCK_FOR,
    NTP_AUTHENTICATED,
    NTP_CONFIGURED,
    NTP_MD5_AUTHENTICATION,
    PASSWORD_STRENGTH_CHECK,
    PROXY_ARP_L3_INTERFACES,
    REMOTE_SYSLOG_SERVERS,
    ROUTING_AUTHENTICATION_MISSING,
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
    SSH_VERSION,
    TELNET_LINES,
    TYPE_6_ENABLED,
    VTY_ACCESS_CLASS_MISSING_LINES,
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
        SSH_VERSION: 0,
        VTY_ACCESS_CLASS_MISSING_LINES: ("line vty 0 4", "line vty 5 15"),
        AAA_LOGIN_FALLBACK_NONE: 0,
        AAA_NEW_MODEL: False,
        AAA_CENTRAL_LOGIN: False,
        AAA_AUTHORIZATION: False,
        AAA_ACCOUNTING: False,
        EXEC_TIMEOUT_DISABLED_LINES: (),
        TYPE_6_ENABLED: False,
        SNMP_V1_V2C_COMMUNITIES: 3,
        SNMP_V1_V2C_READ_WRITE_COMMUNITIES: 2,
        SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME: 1,
        SNMP_V1_V2C_READ_WRITE_NO_ACL: 1,
        SNMP_V3_CONFIGURED: True,
        SNMP_V3_USERS: 1,
        SNMP_V3_USERS_WITHOUT_PRIV: 1,
        SNMP_V3_GROUPS_WITHOUT_PRIV: 1,
        NTP_CONFIGURED: False,
        NTP_AUTHENTICATED: False,
        NTP_MD5_AUTHENTICATION: False,
        REMOTE_SYSLOG_SERVERS: 0,
        LOGIN_BLOCK_FOR: False,
        ROUTING_AUTHENTICATION_MISSING: (),
        FHRP_GROUPS: 0,
        FHRP_GROUPS_WITHOUT_AUTHENTICATION: 0,
        ICMP_REDIRECTS_L3_INTERFACES: 0,
        ICMP_UNREACHABLES_L3_INTERFACES: 0,
        PROXY_ARP_L3_INTERFACES: 0,
    }


def test_nxos_running_config_gives_its_own_hardening_facts() -> None:
    facts = _facts(Platform.NX_OS, device_text.NXOS_HARDENING_CONFIG)

    assert facts == {
        TELNET_LINES: ("line vty",),
        VTY_ACCESS_CLASS_MISSING_LINES: (),
        AAA_LOGIN_FALLBACK_NONE: 0,
        AAA_CENTRAL_LOGIN: False,
        AAA_AUTHORIZATION: False,
        AAA_ACCOUNTING: False,
        EXEC_TIMEOUT_DISABLED_LINES: (),
        TYPE_6_ENABLED: Unknown(
            "the NX-OS command that enables AES type 6 encryption is not confirmed"
        ),
        SECRET_TYPE_0: 0,
        SECRET_TYPE_4: 0,
        SECRET_TYPE_5: 1,
        SECRET_TYPE_6: 0,
        SECRET_TYPE_7: 0,
        SECRET_TYPE_8: 0,
        SECRET_TYPE_9: 0,
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
        SNMP_V3_USER_CRYPTO: ("MD5/none",),
        SNMP_GLOBAL_ENFORCE_PRIV: False,
        NTP_CONFIGURED: False,
        NTP_AUTHENTICATED: False,
        NTP_MD5_AUTHENTICATION: False,
        REMOTE_SYSLOG_SERVERS: 0,
        PASSWORD_STRENGTH_CHECK: True,
        ROUTING_AUTHENTICATION_MISSING: (),
        FHRP_GROUPS: 0,
        FHRP_GROUPS_WITHOUT_AUTHENTICATION: 0,
        ICMP_REDIRECTS_L3_INTERFACES: 0,
        ICMP_UNREACHABLES_L3_INTERFACES: 0,
        PROXY_ARP_L3_INTERFACES: 0,
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


def test_no_source_route_line_reads_as_enabled_because_the_ios_default_is_on() -> None:
    assert _facts(Platform.IOS_XE, "hostname sw-a\n")[IP_SOURCE_ROUTE] is True


def test_the_no_source_route_form_reads_as_disabled() -> None:
    assert _facts(Platform.IOS_XE, "no ip source-route\n")[IP_SOURCE_ROUTE] is False


@pytest.mark.parametrize("config", ["hostname nx-a\n", "hostname nx-a\nno ip source-route\n"])
def test_source_routing_is_not_an_nxos_fact(config: str) -> None:
    assert IP_SOURCE_ROUTE not in _facts(Platform.NX_OS, config)


def _nxos_users(*lines: str) -> FactValue:
    return _facts(Platform.NX_OS, "hostname nx-a\n" + "".join(f"{line}\n" for line in lines))[
        SNMP_V3_USER_CRYPTO
    ]


def test_nxos_snmpv3_user_crypto_is_one_auth_and_privacy_pair_per_user() -> None:
    users = _nxos_users(
        "snmp-server user u1 network-operator auth md5 0xCANARY-cfg-141-a priv 0xCANARY-cfg-141-b"
        " localizedkey",
        "snmp-server user u2 network-operator auth sha 0xCANARY-cfg-141-c priv aes-128"
        " 0xCANARY-cfg-141-d localizedkey",
        "snmp-server user u3 network-admin auth sha-256 0xCANARY-cfg-141-e priv aes-128"
        " 0xCANARY-cfg-141-f localizedkey",
        "snmp-server user u4 network-operator auth sha 0xCANARY-cfg-141-g localizedkey",
        "snmp-server user u5 network-operator",
    )

    assert users == ("MD5/DES", "SHA/AES128", "SHA-256/AES128", "SHA/none", "none/none")


def test_nxos_snmpv3_user_crypto_is_empty_when_no_user_is_configured() -> None:
    assert _nxos_users("snmp-server community public RO") == ()


def test_nxos_snmpv3_user_crypto_reads_the_position_not_a_key_that_spells_a_keyword() -> None:
    users = _nxos_users("snmp-server user u1 network-operator auth md5 priv aes-128 localizedkey")

    assert users == ("MD5/none",)


def test_nxos_snmpv3_user_crypto_is_unknown_when_a_line_is_not_understood() -> None:
    value = _nxos_users("snmp-server user u1 network-operator auth md6 0xCANARY-cfg-141-h")

    assert isinstance(value, Unknown)
    assert "CANARY" not in value.reason
    assert "md6" not in value.reason


def test_nxos_snmpv3_user_crypto_never_keeps_a_key_or_a_user_name() -> None:
    users = _nxos_users(
        "snmp-server user CANARY-cfg-141-name network-admin auth md5 0xCANARY-cfg-141-key"
        " priv 0xCANARY-cfg-141-key2 localizedkey"
    )

    assert "CANARY" not in repr(users)


def test_ios_has_no_snmpv3_user_crypto_fact() -> None:
    assert SNMP_V3_USER_CRYPTO not in _facts(Platform.IOS_XE, device_text.IOS_XE_HARDENING_CONFIG)


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
