"""Config facts for NTP, syslog, routing, FHRP and ICMP, read at capture time (#101).

Driven through `platforms.read_config_facts` with synthetic configs
(tests/support/device_text). Every fact is a plain value; no key, key-string, password or
quoted config line is ever kept.
"""

from network_analyser import platforms
from network_analyser.records import Platform
from network_analyser.records.config_facts import (
    FHRP_GROUPS,
    FHRP_GROUPS_WITHOUT_AUTHENTICATION,
    ICMP_REDIRECTS_L3_INTERFACES,
    ICMP_UNREACHABLES_L3_INTERFACES,
    LOGIN_BLOCK_FOR,
    NTP_AUTHENTICATED,
    NTP_CONFIGURED,
    NTP_MD5_AUTHENTICATION,
    PASSWORD_STRENGTH_CHECK,
    PROXY_ARP_L3_INTERFACES,
    REMOTE_SYSLOG_SERVERS,
    ROUTING_AUTHENTICATION_MISSING,
    FactValue,
)
from tests.support import device_text


def _facts(platform: Platform, text: str) -> dict[str, FactValue]:
    return {fact.name: fact.value for fact in platforms.read_config_facts(platform, text)}


def test_ios_running_config_gives_its_service_facts() -> None:
    facts = _facts(Platform.IOS_XE, device_text.IOS_XE_SERVICES_CONFIG)

    assert facts[NTP_CONFIGURED] is True
    assert facts[NTP_AUTHENTICATED] is True
    assert facts[NTP_MD5_AUTHENTICATION] is True
    assert facts[REMOTE_SYSLOG_SERVERS] == 1
    assert facts[LOGIN_BLOCK_FOR] is False
    assert facts[ROUTING_AUTHENTICATION_MISSING] == ("OSPF",)
    assert facts[FHRP_GROUPS] == 1
    assert facts[FHRP_GROUPS_WITHOUT_AUTHENTICATION] == 0
    assert facts[ICMP_REDIRECTS_L3_INTERFACES] == 1
    assert facts[ICMP_UNREACHABLES_L3_INTERFACES] == 1
    assert facts[PROXY_ARP_L3_INTERFACES] == 1


def test_nxos_running_config_gives_its_service_facts() -> None:
    facts = _facts(Platform.NX_OS, device_text.NXOS_SERVICES_CONFIG)

    assert facts[NTP_CONFIGURED] is True
    assert facts[NTP_AUTHENTICATED] is True
    assert facts[NTP_MD5_AUTHENTICATION] is False
    assert facts[REMOTE_SYSLOG_SERVERS] == 1
    assert facts[PASSWORD_STRENGTH_CHECK] is False
    assert facts[ROUTING_AUTHENTICATION_MISSING] == ("OSPF",)
    assert facts[FHRP_GROUPS] == 1
    assert facts[FHRP_GROUPS_WITHOUT_AUTHENTICATION] == 0
    assert facts[ICMP_REDIRECTS_L3_INTERFACES] == 2
    assert facts[ICMP_UNREACHABLES_L3_INTERFACES] == 2
    assert facts[PROXY_ARP_L3_INTERFACES] == 1


def test_ntp_with_a_server_but_no_key_is_unauthenticated() -> None:
    facts = _facts(Platform.IOS_XE, "ntp server 192.0.2.10\n")

    assert facts[NTP_CONFIGURED] is True
    assert facts[NTP_AUTHENTICATED] is False
    assert facts[NTP_MD5_AUTHENTICATION] is False


def test_ntp_needs_a_trusted_key_referenced_by_a_server() -> None:
    untrusted = (
        "ntp authentication-key 1 md5 CANARY-cfg-101-a1b2-ntp-md5\nntp server 192.0.2.10 key 1\n"
    )
    trusted = (
        "ntp authentication-key 1 md5 CANARY-cfg-101-a1b2-ntp-md5\n"
        "ntp trusted-key 1\n"
        "ntp server 192.0.2.10 key 1\n"
    )

    assert _facts(Platform.IOS_XE, untrusted)[NTP_AUTHENTICATED] is False
    assert _facts(Platform.IOS_XE, trusted)[NTP_AUTHENTICATED] is True


def test_ntp_sha_authentication_is_not_md5() -> None:
    config = (
        "ntp authentication-key 1 sha256 CANARY-cfg-101-a1b2-ntp-sha\n"
        "ntp trusted-key 1\n"
        "ntp server 192.0.2.10 key 1\n"
    )

    facts = _facts(Platform.IOS_XE, config)

    assert facts[NTP_AUTHENTICATED] is True
    assert facts[NTP_MD5_AUTHENTICATION] is False


def test_ntp_master_counts_as_configured_but_not_authenticated() -> None:
    facts = _facts(Platform.IOS_XE, "ntp master 3\n")

    assert facts[NTP_CONFIGURED] is True
    assert facts[NTP_AUTHENTICATED] is False


def test_local_logging_commands_are_not_remote_syslog_servers() -> None:
    config = (
        "logging buffered 64000\nlogging console\nlogging trap warnings\nlogging host 192.0.2.20\n"
    )

    assert _facts(Platform.IOS_XE, config)[REMOTE_SYSLOG_SERVERS] == 1


def test_no_remote_syslog_gives_zero() -> None:
    assert _facts(Platform.IOS_XE, "logging buffered 64000\n")[REMOTE_SYSLOG_SERVERS] == 0


def test_login_block_for_reads_as_brute_force_protection() -> None:
    config = "login block-for 60 attempts 3 within 60\nlogin delay 1\n"

    assert _facts(Platform.IOS_XE, config)[LOGIN_BLOCK_FOR] is True


def test_strength_check_is_on_by_default_and_off_only_with_the_no_form() -> None:
    assert _facts(Platform.NX_OS, "hostname nx-a\n")[PASSWORD_STRENGTH_CHECK] is True
    assert _facts(Platform.NX_OS, "password strength-check\n")[PASSWORD_STRENGTH_CHECK] is True
    assert _facts(Platform.NX_OS, "no password strength-check\n")[PASSWORD_STRENGTH_CHECK] is False


def test_routing_authentication_is_missing_per_protocol() -> None:
    config = (
        "router ospf 1\n area 0 authentication message-digest\n"
        " ip ospf message-digest-key 1 md5 CANARY-cfg-101-a1b2-ntp-md5\n"
        "router eigrp 10\n network 192.0.2.0\n"
        "router bgp 65000\n"
    )

    assert _facts(Platform.IOS_XE, config)[ROUTING_AUTHENTICATION_MISSING] == ("BGP", "EIGRP")


def test_ospf_area_or_interface_authentication_counts_as_authenticated() -> None:
    area = "router ospf 1\n area 0 authentication\n"
    interface = "router ospf 1\ninterface Vlan10\n ip ospf authentication message-digest\n"

    assert _facts(Platform.IOS_XE, area)[ROUTING_AUTHENTICATION_MISSING] == ()
    assert _facts(Platform.IOS_XE, interface)[ROUTING_AUTHENTICATION_MISSING] == ()


def test_bgp_neighbour_password_counts_as_authenticated() -> None:
    config = "router bgp 65000\n neighbor 192.0.2.3 password 7 CANARY-cfg-101-a1b2-bgp\n"

    assert _facts(Platform.IOS_XE, config)[ROUTING_AUTHENTICATION_MISSING] == ()


def test_fhrp_groups_count_and_their_authentication() -> None:
    config = (
        "interface Vlan10\n"
        " ip address 192.0.2.1 255.255.255.0\n"
        " standby 1 ip 192.0.2.254\n"
        " standby 1 authentication md5 key-string CANARY-cfg-101-a1b2-fhrp\n"
        " standby 2 ip 192.0.2.253\n"
    )

    facts = _facts(Platform.IOS_XE, config)

    assert facts[FHRP_GROUPS] == 2
    assert facts[FHRP_GROUPS_WITHOUT_AUTHENTICATION] == 1


def test_icmp_settings_default_on_for_ios_and_differ_for_nxos_proxy_arp() -> None:
    ios = "interface Vlan10\n ip address 192.0.2.1 255.255.255.0\n"
    nxos = "interface Vlan10\n ip address 192.0.2.1/24\n"

    ios_facts = _facts(Platform.IOS_XE, ios)
    nxos_facts = _facts(Platform.NX_OS, nxos)

    assert ios_facts[ICMP_REDIRECTS_L3_INTERFACES] == 1
    assert ios_facts[ICMP_UNREACHABLES_L3_INTERFACES] == 1
    assert ios_facts[PROXY_ARP_L3_INTERFACES] == 1
    assert nxos_facts[ICMP_REDIRECTS_L3_INTERFACES] == 1
    assert nxos_facts[ICMP_UNREACHABLES_L3_INTERFACES] == 1
    assert nxos_facts[PROXY_ARP_L3_INTERFACES] == 0


def test_only_layer_three_interfaces_count_for_icmp() -> None:
    config = "interface GigabitEthernet1/0/1\n switchport\n"

    facts = _facts(Platform.IOS_XE, config)

    assert facts[ICMP_REDIRECTS_L3_INTERFACES] == 0
    assert facts[ICMP_UNREACHABLES_L3_INTERFACES] == 0
    assert facts[PROXY_ARP_L3_INTERFACES] == 0


def test_no_key_or_password_from_the_config_reaches_a_fact() -> None:
    for platform, config in (
        (Platform.IOS_XE, device_text.IOS_XE_SERVICES_CONFIG),
        (Platform.NX_OS, device_text.NXOS_SERVICES_CONFIG),
    ):
        shown = repr(platforms.read_config_facts(platform, config))
        for canary in device_text.SERVICE_CANARIES:
            assert canary not in shown
