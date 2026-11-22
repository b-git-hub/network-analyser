"""Config-fact accuracy fixes from the 0.2.0 / 0.3.0 review (#142).

Driven through `platforms.read_config_facts` with synthetic configs. Each fix has a fire case
(the insecure config is seen), a no-fire case (the look-alike is not), and the empty-config
case, where no fact is read at all so Analysis says "could not decide". Every secret in a
config is a `CANARY-...` value, and none may reach a fact.
"""

from network_analyser import platforms
from network_analyser.records import Platform
from network_analyser.records.config_facts import (
    SECRET_TYPE_0,
    SECRET_TYPE_5,
    SECRET_TYPE_6,
    SECRET_TYPE_7,
    SNMP_V1_V2C_COMMUNITIES,
    SNMP_V1_V2C_READ_WRITE_COMMUNITIES,
    SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME,
    SNMP_V1_V2C_READ_WRITE_NO_ACL,
    SNMP_V3_CONFIGURED,
    SNMP_V3_USERS,
    SNMP_V3_USERS_WITHOUT_PRIV,
    FactValue,
)

CANARY = "CANARY-cfg-142-a1b2"


def _facts(platform: Platform, text: str) -> dict[str, FactValue]:
    return {fact.name: fact.value for fact in platforms.read_config_facts(platform, text)}


def _ios(text: str) -> dict[str, FactValue]:
    return _facts(Platform.IOS_XE, text)


def _nxos(text: str) -> dict[str, FactValue]:
    return _facts(Platform.NX_OS, text)


def _assert_no_canary(platform: Platform, text: str) -> None:
    assert CANARY not in repr(platforms.read_config_facts(platform, text))


# -- Secrets: cleartext line passwords ---------------------------------------------------------


def test_a_cleartext_line_password_counts_as_type_0() -> None:
    config = f"line con 0\n password {CANARY}-con\nline vty 0 4\n password {CANARY}-vty\n login\n"

    assert _ios(config)[SECRET_TYPE_0] == 2
    _assert_no_canary(Platform.IOS_XE, config)


def test_a_typed_line_password_is_not_counted_as_cleartext() -> None:
    config = f"line vty 0 4\n password 7 {CANARY}-vty\n login\n"

    facts = _ios(config)

    assert facts[SECRET_TYPE_0] == 0
    assert facts[SECRET_TYPE_7] == 1


def test_an_explicit_type_0_line_password_counts_once() -> None:
    assert _ios(f"line vty 0 4\n password 0 {CANARY}-vty\n")[SECRET_TYPE_0] == 1


def test_a_password_outside_a_line_block_is_not_a_cleartext_line_password() -> None:
    config = f"line vty 0 4\n login local\nhostname sw-a\npassword-policy {CANARY}\n"

    assert _ios(config)[SECRET_TYPE_0] == 0


def test_no_line_password_at_all_counts_nothing() -> None:
    assert _ios("line vty 0 4\n login local\n transport input ssh\n")[SECRET_TYPE_0] == 0


# -- Secrets: privilege-level forms ------------------------------------------------------------


def test_enable_secret_and_password_with_a_privilege_level_are_counted() -> None:
    config = (
        f"enable secret level 15 5 {CANARY}-secret\n"
        f"enable password level 15 7 {CANARY}-password\n"
        f"enable secret level 10 0 {CANARY}-clear\n"
    )

    facts = _ios(config)

    assert facts[SECRET_TYPE_5] == 1
    assert facts[SECRET_TYPE_7] == 1
    assert facts[SECRET_TYPE_0] == 1
    _assert_no_canary(Platform.IOS_XE, config)


def test_the_plain_enable_forms_still_count_once() -> None:
    facts = _ios(f"enable secret 5 {CANARY}\nenable password 7 {CANARY}\n")

    assert facts[SECRET_TYPE_5] == 1
    assert facts[SECRET_TYPE_7] == 1


# -- Secrets: type 7 outside password and secret lines -----------------------------------------


def test_type_7_keys_outside_password_lines_are_counted() -> None:
    config = (
        "key chain KC\n"
        " key 1\n"
        f"  key-string 7 {CANARY}-chain\n"
        "interface Vlan10\n"
        f" ip ospf authentication-key 7 {CANARY}-ospf\n"
        f" ip ospf message-digest-key 1 md5 7 {CANARY}-digest\n"
        f"radius-server host 192.0.2.5 key 7 {CANARY}-radius\n"
        f"tacacs server tac-a\n key 7 {CANARY}-tacacs\n"
    )

    assert _ios(config)[SECRET_TYPE_7] == 5
    _assert_no_canary(Platform.IOS_XE, config)


def test_a_key_id_or_ntp_key_number_is_not_a_type_number() -> None:
    config = (
        "key chain KC\n"
        " key 7\n"
        f"  key-string {CANARY}-chain\n"
        f"ntp authentication-key 7 md5 {CANARY}-ntp\n"
        "ip ospf message-digest-key 7 md5\n"
    )

    facts = _ios(config)

    assert facts[SECRET_TYPE_7] == 0
    assert facts[SECRET_TYPE_6] == 0


def test_type_6_keys_outside_password_lines_are_counted_as_type_6() -> None:
    config = f"tacacs server tac-a\n key 6 {CANARY}-tacacs\n"

    assert _ios(config)[SECRET_TYPE_6] == 1


def test_nxos_type_7_keys_are_counted_too() -> None:
    config = f"tacacs-server key 7 {CANARY}-tacacs\nkey chain KC\n key 1\n  key-string 7 {CANARY}\n"

    assert _nxos(config)[SECRET_TYPE_7] == 2


def test_an_empty_config_reads_no_secret_fact_so_analysis_cannot_pass_it() -> None:
    assert platforms.read_config_facts(Platform.IOS_XE, "") == ()
    assert platforms.read_config_facts(Platform.NX_OS, "\n  \n") == ()


# -- SNMP: NX-OS communities and SNMPv3 users --------------------------------------------------


def test_an_nxos_network_admin_community_is_read_write_and_its_acl_line_is_attached() -> None:
    config = (
        f"snmp-server community {CANARY}-rw group network-admin\n"
        f"snmp-server community {CANARY}-rw use-ipv4acl ACL-A\n"
        f"snmp-server community {CANARY}-ro group network-operator\n"
        f"snmp-server community {CANARY}-ro use-acl ACL-B\n"
    )

    facts = _nxos(config)

    assert facts[SNMP_V1_V2C_COMMUNITIES] == 2
    assert facts[SNMP_V1_V2C_READ_WRITE_COMMUNITIES] == 1
    assert facts[SNMP_V1_V2C_READ_WRITE_NO_ACL] == 0
    assert facts[SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME] == 0
    _assert_no_canary(Platform.NX_OS, config)


def test_an_nxos_network_admin_community_with_no_acl_line_is_read_write_without_an_acl() -> None:
    facts = _nxos(f"snmp-server community {CANARY}-rw group network-admin\n")

    assert facts[SNMP_V1_V2C_COMMUNITIES] == 1
    assert facts[SNMP_V1_V2C_READ_WRITE_COMMUNITIES] == 1
    assert facts[SNMP_V1_V2C_READ_WRITE_NO_ACL] == 1


def test_an_nxos_default_named_read_write_community_is_counted() -> None:
    facts = _nxos("snmp-server community private group network-admin\n")

    assert facts[SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME] == 1


def test_an_nxos_read_only_group_community_is_not_read_write() -> None:
    facts = _nxos(f"snmp-server community {CANARY}-ro group network-operator\n")

    assert facts[SNMP_V1_V2C_COMMUNITIES] == 1
    assert facts[SNMP_V1_V2C_READ_WRITE_COMMUNITIES] == 0
    assert facts[SNMP_V1_V2C_READ_WRITE_NO_ACL] == 0


def test_ios_communities_are_still_counted_line_by_line() -> None:
    config = f"snmp-server community {CANARY}-ro RO\nsnmp-server community {CANARY}-rw RW 10\n"

    facts = _ios(config)

    assert facts[SNMP_V1_V2C_COMMUNITIES] == 2
    assert facts[SNMP_V1_V2C_READ_WRITE_COMMUNITIES] == 1
    assert facts[SNMP_V1_V2C_READ_WRITE_NO_ACL] == 0


def test_a_v2c_snmp_user_is_not_an_snmpv3_user() -> None:
    config = "snmp-server user alice grp v2c\nsnmp-server user carol grp v1 10\n"

    facts = _ios(config)

    assert facts[SNMP_V3_USERS] == 0
    assert facts[SNMP_V3_USERS_WITHOUT_PRIV] == 0
    assert facts[SNMP_V3_CONFIGURED] is False


def test_a_v3_snmp_user_is_counted_with_and_without_privacy() -> None:
    config = (
        f"snmp-server user alice grp v3 auth sha {CANARY}-a priv aes 128 {CANARY}-p\n"
        f"snmp-server user bob grp v3 auth sha {CANARY}-b\n"
    )

    facts = _ios(config)

    assert facts[SNMP_V3_USERS] == 2
    assert facts[SNMP_V3_USERS_WITHOUT_PRIV] == 1
    assert facts[SNMP_V3_CONFIGURED] is True
    _assert_no_canary(Platform.IOS_XE, config)
