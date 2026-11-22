"""Config-fact accuracy fixes from the 0.2.0 / 0.3.0 review (#142).

Driven through `platforms.read_config_facts` with synthetic configs. Each fix has a fire case
(the insecure config is seen), a no-fire case (the look-alike is not), and the empty-config
case, where no fact is read at all so Analysis says "could not decide". Every secret in a
config is a `CANARY-...` value, and none may reach a fact.
"""

from network_analyser import platforms
from network_analyser.records import Platform
from network_analyser.records.config_facts import (
    EXEC_TIMEOUT_DISABLED_LINES,
    FHRP_GROUPS,
    FHRP_GROUPS_WITHOUT_AUTHENTICATION,
    ICMP_REDIRECTS_L3_INTERFACES,
    ICMP_UNREACHABLES_L3_INTERFACES,
    NTP_AUTHENTICATED,
    NTP_CONFIGURED,
    NTP_MD5_AUTHENTICATION,
    PROXY_ARP_L3_INTERFACES,
    REMOTE_SYSLOG_SERVERS,
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


# -- NTP ---------------------------------------------------------------------------------------


def _ntp_config(*, authenticate: bool, trusted: str = "1", server_key: int = 1) -> str:
    return (
        f"ntp authentication-key 1 md5 {CANARY}-one\n"
        f"ntp authentication-key 2 sha256 {CANARY}-two\n"
        + ("ntp authenticate\n" if authenticate else "")
        + f"ntp trusted-key {trusted}\n"
        f"ntp server 192.0.2.10 key {server_key}\n"
    )


def test_ntp_keys_authenticate_nothing_without_ntp_authenticate() -> None:
    for platform in (Platform.IOS_XE, Platform.NX_OS):
        facts = _facts(platform, _ntp_config(authenticate=False))

        assert facts[NTP_CONFIGURED] is True
        assert facts[NTP_AUTHENTICATED] is False
        assert facts[NTP_MD5_AUTHENTICATION] is False


def test_ntp_with_ntp_authenticate_and_a_trusted_key_is_authenticated() -> None:
    for platform in (Platform.IOS_XE, Platform.NX_OS):
        facts = _facts(platform, _ntp_config(authenticate=True))

        assert facts[NTP_AUTHENTICATED] is True
        assert facts[NTP_MD5_AUTHENTICATION] is True


def test_a_trusted_key_range_trusts_every_key_in_it() -> None:
    inside = _facts(Platform.IOS_XE, _ntp_config(authenticate=True, trusted="1 - 3", server_key=2))
    outside = _facts(Platform.IOS_XE, _ntp_config(authenticate=True, trusted="1 - 3", server_key=4))

    assert inside[NTP_AUTHENTICATED] is True
    assert inside[NTP_MD5_AUTHENTICATION] is False
    assert outside[NTP_AUTHENTICATED] is False


def test_the_end_of_a_trusted_key_range_is_trusted() -> None:
    facts = _facts(Platform.IOS_XE, _ntp_config(authenticate=True, trusted="1 - 2", server_key=2))

    assert facts[NTP_AUTHENTICATED] is True


def test_no_ntp_secret_reaches_a_fact() -> None:
    _assert_no_canary(Platform.IOS_XE, _ntp_config(authenticate=True))


# -- Remote syslog -----------------------------------------------------------------------------


def test_logging_that_is_not_a_server_is_not_counted() -> None:
    config = (
        "logging on\n"
        "logging userinfo\n"
        "logging buffered 64000\n"
        "logging source-interface Vlan10\n"
        "logging server-arp\n"
        "archive\n"
        " log config\n"
        "  logging enable\n"
        "  logging size 1000\n"
        "  notify syslog contenttype plaintext\n"
    )

    assert _ios(config)[REMOTE_SYSLOG_SERVERS] == 0


def test_each_top_level_remote_syslog_form_is_counted() -> None:
    config = (
        "logging on\n"
        "logging host 192.0.2.20 transport tcp port 6514\n"
        "logging 192.0.2.21\n"
        "logging server 192.0.2.22 5 use-vrf management\n"
        "logging host\n"
    )

    assert _ios(config)[REMOTE_SYSLOG_SERVERS] == 3


def test_an_indented_logging_host_is_not_a_remote_server() -> None:
    config = "some-feature\n logging host 192.0.2.20\n"

    assert _ios(config)[REMOTE_SYSLOG_SERVERS] == 0


def test_a_hostname_syslog_server_is_counted() -> None:
    assert _ios("logging host syslog-a\n")[REMOTE_SYSLOG_SERVERS] == 1


# -- FHRP groups -------------------------------------------------------------------------------


def test_the_same_group_number_on_two_interfaces_is_two_groups() -> None:
    config = (
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        " standby 1 ip 192.0.2.254\n"
        f" standby 1 authentication md5 key-string {CANARY}-fhrp\n"
        "interface Vlan20\n"
        " ip address 198.51.100.1 255.255.255.0\n"
        " standby 1 ip 198.51.100.254\n"
    )

    facts = _ios(config)

    assert facts[FHRP_GROUPS] == 2
    assert facts[FHRP_GROUPS_WITHOUT_AUTHENTICATION] == 1
    _assert_no_canary(Platform.IOS_XE, config)


def test_the_same_nxos_hsrp_group_on_two_interfaces_is_two_groups() -> None:
    config = (
        "interface Vlan10\n"
        "  ip address 192.0.2.1/24\n"
        "  hsrp 1\n"
        "    ip 192.0.2.254\n"
        f"    authentication md5 key-string {CANARY}-fhrp\n"
        "interface Vlan20\n"
        "  ip address 198.51.100.1/24\n"
        "  hsrp 1\n"
        "    ip 198.51.100.254\n"
    )

    facts = _nxos(config)

    assert facts[FHRP_GROUPS] == 2
    assert facts[FHRP_GROUPS_WITHOUT_AUTHENTICATION] == 1


def test_groups_that_are_all_authenticated_are_not_flagged() -> None:
    config = (
        "interface Vlan10\n"
        " standby 1 ip 192.0.2.254\n"
        " standby 1 authentication md5 key-chain KC\n"
        "interface Vlan20\n"
        " standby 1 ip 198.51.100.254\n"
        " standby 1 authentication md5 key-chain KC\n"
    )

    facts = _ios(config)

    assert facts[FHRP_GROUPS] == 2
    assert facts[FHRP_GROUPS_WITHOUT_AUTHENTICATION] == 0


def test_one_interface_can_run_two_protocols_with_the_same_number() -> None:
    config = (
        "interface Vlan10\n standby 1 ip 192.0.2.254\n vrrp 1 ip 192.0.2.253\n"
        " vrrp 1 authentication text KC\n"
    )

    facts = _ios(config)

    assert facts[FHRP_GROUPS] == 2
    assert facts[FHRP_GROUPS_WITHOUT_AUTHENTICATION] == 1


# -- Exec timeout ------------------------------------------------------------------------------


def test_exec_timeout_with_seconds_is_not_disabled() -> None:
    config = "line con 0\n exec-timeout 0 30\nline vty 0 4\n exec-timeout 5 0\n"

    assert _ios(config)[EXEC_TIMEOUT_DISABLED_LINES] == ()


def test_exec_timeout_of_zero_minutes_and_zero_seconds_is_disabled() -> None:
    config = (
        "line con 0\n exec-timeout 0 0\nline vty 0 4\n exec-timeout 0\n"
        "line vty 5 15\n exec-timeout 0 1\n"
    )

    assert _ios(config)[EXEC_TIMEOUT_DISABLED_LINES] == ("line con 0", "line vty 0 4")


# -- ICMP counts -------------------------------------------------------------------------------


def test_icmp_counts_skip_shutdown_and_loopback_interfaces() -> None:
    config = (
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        "interface Vlan20\n"
        " ip address 198.51.100.1 255.255.255.0\n"
        " shutdown\n"
        "interface Loopback0\n"
        " ip address 203.0.113.1 255.255.255.255\n"
    )

    for facts in (_ios(config), _nxos(config)):
        assert facts[ICMP_REDIRECTS_L3_INTERFACES] == 1
        assert facts[ICMP_UNREACHABLES_L3_INTERFACES] == 1


def test_icmp_counts_still_count_a_live_interface_that_sets_nothing() -> None:
    config = "interface Vlan10\n ip address 192.0.2.1 255.255.255.0\n no ip unreachables\n"

    facts = _ios(config)

    assert facts[ICMP_REDIRECTS_L3_INTERFACES] == 1
    assert facts[ICMP_UNREACHABLES_L3_INTERFACES] == 0
    assert facts[PROXY_ARP_L3_INTERFACES] == 1
