"""The NTP, syslog, routing, FHRP, ICMP and Platform Checks (#101; stories 59-66).

Driven through `analysis.analyse` with synthetic records and facts only. Each Check's fire,
no-fire, not-applicable and could-not-decide cases are here, with each feature gate, the
classic IOS / IOS-XE / NX-OS differences, and the canary proof that no key, key-string or
password reaches a Finding or `topology.json`.
"""

import json
from collections.abc import Mapping
from dataclasses import replace
from ipaddress import IPv4Address

from network_analyser import analysis, platforms, topology
from network_analyser.records import Platform
from network_analyser.records.analysis import AnalysisInput, ConfigFact, ConfigFacts
from network_analyser.records.collected import Interface, RoutingNeighbour, RoutingProtocol
from network_analyser.records.config_facts import (
    ENABLE_PASSWORD,
    ENABLE_SECRET,
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
    TELNET_LINES,
    FactValue,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.interface_names import interface_name
from network_analyser.records.topology import AnalysisResults, CheckType, Finding, FindingLevel
from network_analyser.records.unknown import Unknown
from tests.support import device_text
from tests.support.topology_records import port, visited

A = "192.0.2.1"
B = "192.0.2.2"
IOS_XE = "17.9.4a"
CLASSIC_IOS = "15.2(7)E7"
NXOS = "9.3(8)"
UP_L3 = (port("Vlan10", ips=["192.0.2.1/24"]),)


def _record(  # noqa: PLR0913 (a device's identity and collected data, by name)
    platform: Platform,
    release: str | Unknown,
    *,
    address: str = A,
    serial: str = "S1",
    hostname: str = "sw-a",
    interfaces: tuple[Interface, ...] | None = UP_L3,
    routing: tuple[RoutingNeighbour, ...] = (),
) -> DeviceRecord:
    built = visited(
        address,
        serial,
        hostname,
        platform=platform,
        interfaces=interfaces,
        routing=routing,
    )
    version = built.version
    assert version is not None
    return replace(built, version=replace(version, software_version=release))


def _safe_facts(platform: Platform, overrides: Mapping[str, FactValue]) -> tuple[ConfigFact, ...]:
    facts: dict[str, FactValue] = {
        TELNET_LINES: (),
        SECRET_TYPE_0: 0,
        SECRET_TYPE_4: 0,
        SECRET_TYPE_5: 0,
        SECRET_TYPE_6: 0,
        SECRET_TYPE_7: 0,
        SECRET_TYPE_8: 0,
        SECRET_TYPE_9: 0,
        IP_SOURCE_ROUTE: False,
        LEGACY_SERVICES: (),
        HTTP_SERVER: False,
        SNMP_V1_V2C_COMMUNITIES: 0,
        SNMP_V1_V2C_READ_WRITE_COMMUNITIES: 0,
        SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME: 0,
        SNMP_V1_V2C_READ_WRITE_NO_ACL: 0,
        SNMP_V3_CONFIGURED: False,
        SNMP_V3_USERS: 0,
        SNMP_V3_USERS_WITHOUT_PRIV: 0,
        SNMP_V3_GROUPS_WITHOUT_PRIV: 0,
        NTP_CONFIGURED: True,
        NTP_AUTHENTICATED: True,
        NTP_MD5_AUTHENTICATION: False,
        REMOTE_SYSLOG_SERVERS: 1,
        ROUTING_AUTHENTICATION_MISSING: (),
        FHRP_GROUPS: 0,
        FHRP_GROUPS_WITHOUT_AUTHENTICATION: 0,
        ICMP_REDIRECTS_L3_INTERFACES: 0,
        ICMP_UNREACHABLES_L3_INTERFACES: 0,
        PROXY_ARP_L3_INTERFACES: 0,
    }
    if platform is Platform.IOS_XE:
        facts.update(
            {
                ENABLE_SECRET: True,
                ENABLE_PASSWORD: False,
                INSECURE_MODE: False,
                LOGIN_BLOCK_FOR: True,
            }
        )
    else:
        facts.update({SNMP_GLOBAL_ENFORCE_PRIV: True, PASSWORD_STRENGTH_CHECK: True})
    facts.update(overrides)
    return tuple(ConfigFact(name, value) for name, value in facts.items())


def _analyse(
    platform: Platform = Platform.IOS_XE,
    release: str | Unknown = IOS_XE,
    facts: Mapping[str, FactValue] | None = None,
    *,
    peer: bool = False,
    interfaces: tuple[Interface, ...] | None = UP_L3,
) -> AnalysisResults:
    records = [
        _record(platform, release, interfaces=interfaces, routing=(_ospf(B),) if peer else ())
    ]
    if peer:
        records.append(_record(platform, release, address=B, serial="S2", hostname="sw-b"))
    built = topology.build(records)
    given = [ConfigFacts("dev-S1", _safe_facts(platform, facts or {}))]
    if peer:
        given.append(ConfigFacts("dev-S2", _safe_facts(platform, {})))
    return analysis.analyse(AnalysisInput(topology=built, config_facts=tuple(given)))


def _ospf(address: str, state: str = "FULL/DR") -> RoutingNeighbour:
    return RoutingNeighbour(
        RoutingProtocol.OSPF, "default", IPv4Address(address), interface_name("Vlan10"), state
    )


def _found(results: AnalysisResults, check_id: str) -> list[Finding]:
    return [finding for finding in results.findings if finding.check.id == check_id]


def _only(results: AnalysisResults, check_id: str) -> Finding:
    found = _found(results, check_id)
    assert len(found) == 1
    return found[0]


# -- Levels and type ---------------------------------------------------------------------------


def test_the_new_checks_carry_their_fixed_levels() -> None:
    results = _analyse(
        facts={
            NTP_CONFIGURED: False,
            REMOTE_SYSLOG_SERVERS: 0,
            LOGIN_BLOCK_FOR: False,
            ROUTING_AUTHENTICATION_MISSING: ("OSPF",),
            FHRP_GROUPS: 1,
            FHRP_GROUPS_WITHOUT_AUTHENTICATION: 1,
            ICMP_REDIRECTS_L3_INTERFACES: 1,
        },
        peer=True,
    )

    levels = {
        "hardening-ntp": FindingLevel.MEDIUM,
        "hardening-remote-syslog": FindingLevel.MEDIUM,
        "hardening-brute-force": FindingLevel.MEDIUM,
        "hardening-routing-authentication": FindingLevel.MEDIUM,
        "hardening-fhrp-authentication": FindingLevel.MEDIUM,
        "hardening-icmp": FindingLevel.LOW,
    }
    for check_id, level in levels.items():
        finding = _only(results, check_id)
        assert finding.level is level
        assert finding.check.type is CheckType.CONFIGURATION
        assert finding.check.name
        assert finding.source == "config"
        assert finding.devices == ("dev-S1",)
        assert finding.what_was_found == finding.summary


# -- NTP ---------------------------------------------------------------------------------------


def test_ntp_not_configured_is_medium() -> None:
    finding = _only(_analyse(facts={NTP_CONFIGURED: False}), "hardening-ntp")

    assert finding.level is FindingLevel.MEDIUM
    assert "not configured" in finding.what_was_found


def test_ntp_without_authentication_is_medium() -> None:
    finding = _only(
        _analyse(facts={NTP_AUTHENTICATED: False, NTP_MD5_AUTHENTICATION: False}),
        "hardening-ntp",
    )

    assert finding.level is FindingLevel.MEDIUM
    assert "without authentication" in finding.what_was_found


def test_ntp_with_md5_authentication_is_medium() -> None:
    finding = _only(
        _analyse(facts={NTP_AUTHENTICATED: True, NTP_MD5_AUTHENTICATION: True}),
        "hardening-ntp",
    )

    assert finding.level is FindingLevel.MEDIUM
    assert "MD5" in finding.what_was_found


def test_ntp_with_strong_authentication_raises_nothing() -> None:
    results = _analyse(facts={NTP_AUTHENTICATED: True, NTP_MD5_AUTHENTICATION: False})

    assert _found(results, "hardening-ntp") == []


def test_ntp_authentication_is_only_read_when_ntp_is_configured() -> None:
    finding = _only(
        _analyse(
            facts={
                NTP_CONFIGURED: False,
                NTP_AUTHENTICATED: Unknown("not collected"),
                NTP_MD5_AUTHENTICATION: Unknown("not collected"),
            }
        ),
        "hardening-ntp",
    )

    assert finding.level is FindingLevel.MEDIUM
    assert "not configured" in finding.what_was_found


def test_ntp_configured_but_unread_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={NTP_CONFIGURED: Unknown("config fact not collected: ntp_configured")}),
        "hardening-ntp",
    )

    assert finding.level is FindingLevel.LOW
    assert "Could not decide" in finding.what_was_found


def test_ntp_authentication_unread_is_a_low_could_not_decide() -> None:
    finding = _only(_analyse(facts={NTP_AUTHENTICATED: Unknown("not collected")}), "hardening-ntp")

    assert finding.level is FindingLevel.LOW
    assert "Could not decide" in finding.what_was_found


# -- Remote syslog -----------------------------------------------------------------------------


def test_no_remote_syslog_is_medium() -> None:
    finding = _only(_analyse(facts={REMOTE_SYSLOG_SERVERS: 0}), "hardening-remote-syslog")

    assert finding.level is FindingLevel.MEDIUM
    assert "No remote syslog server" in finding.what_was_found


def test_remote_syslog_servers_raise_nothing() -> None:
    results = _analyse(facts={REMOTE_SYSLOG_SERVERS: 2})

    assert _found(results, "hardening-remote-syslog") == []


def test_remote_syslog_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={REMOTE_SYSLOG_SERVERS: Unknown("not collected")}),
        "hardening-remote-syslog",
    )

    assert finding.level is FindingLevel.LOW


# -- NX-OS strength-check ----------------------------------------------------------------------


def test_strength_check_off_is_medium_on_nxos() -> None:
    finding = _only(
        _analyse(Platform.NX_OS, NXOS, {PASSWORD_STRENGTH_CHECK: False}),
        "hardening-strength-check",
    )

    assert finding.level is FindingLevel.MEDIUM
    assert "strength-check" in finding.what_was_found


def test_strength_check_on_raises_nothing() -> None:
    results = _analyse(Platform.NX_OS, NXOS, {PASSWORD_STRENGTH_CHECK: True})

    assert _found(results, "hardening-strength-check") == []


def test_strength_check_is_nxos_only() -> None:
    results = _analyse(Platform.IOS_XE, IOS_XE, {PASSWORD_STRENGTH_CHECK: False})

    assert _found(results, "hardening-strength-check") == []


def test_strength_check_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(Platform.NX_OS, NXOS, {PASSWORD_STRENGTH_CHECK: Unknown("not collected")}),
        "hardening-strength-check",
    )

    assert finding.level is FindingLevel.LOW


# -- Brute-force protection --------------------------------------------------------------------


def test_no_brute_force_protection_is_medium_on_ios_xe() -> None:
    finding = _only(_analyse(facts={LOGIN_BLOCK_FOR: False}), "hardening-brute-force")

    assert finding.level is FindingLevel.MEDIUM
    assert "brute-force" in finding.what_was_found.lower()


def test_no_brute_force_protection_is_medium_on_classic_ios_too() -> None:
    finding = _only(
        _analyse(Platform.IOS_XE, CLASSIC_IOS, {LOGIN_BLOCK_FOR: False}),
        "hardening-brute-force",
    )

    assert finding.level is FindingLevel.MEDIUM


def test_brute_force_protection_present_raises_nothing() -> None:
    results = _analyse(facts={LOGIN_BLOCK_FOR: True})

    assert _found(results, "hardening-brute-force") == []


def test_brute_force_protection_is_not_an_nxos_check() -> None:
    results = _analyse(Platform.NX_OS, NXOS, {LOGIN_BLOCK_FOR: False})

    assert _found(results, "hardening-brute-force") == []


def test_brute_force_protection_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={LOGIN_BLOCK_FOR: Unknown("not collected")}), "hardening-brute-force"
    )

    assert finding.level is FindingLevel.LOW


# -- Routing authentication --------------------------------------------------------------------


def test_routing_authentication_missing_fires_only_with_a_live_neighbour() -> None:
    finding = _only(
        _analyse(facts={ROUTING_AUTHENTICATION_MISSING: ("OSPF",)}, peer=True),
        "hardening-routing-authentication",
    )

    assert finding.level is FindingLevel.MEDIUM
    assert "OSPF" in finding.what_was_found
    assert "BGP" not in finding.what_was_found


def test_routing_authentication_missing_does_not_fire_without_a_live_neighbour() -> None:
    results = _analyse(facts={ROUTING_AUTHENTICATION_MISSING: ("OSPF",)})

    assert _found(results, "hardening-routing-authentication") == []


def test_a_live_neighbour_with_authentication_raises_nothing() -> None:
    results = _analyse(facts={ROUTING_AUTHENTICATION_MISSING: ()}, peer=True)

    assert _found(results, "hardening-routing-authentication") == []


def test_routing_authentication_gates_per_protocol() -> None:
    results = _analyse(facts={ROUTING_AUTHENTICATION_MISSING: ("BGP", "EIGRP")}, peer=True)

    assert _found(results, "hardening-routing-authentication") == []


def test_routing_authentication_unread_with_a_live_neighbour_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={ROUTING_AUTHENTICATION_MISSING: Unknown("not collected")}, peer=True),
        "hardening-routing-authentication",
    )

    assert finding.level is FindingLevel.LOW
    assert "Could not decide" in finding.what_was_found


def test_routing_authentication_unread_without_a_live_neighbour_raises_nothing() -> None:
    results = _analyse(facts={ROUTING_AUTHENTICATION_MISSING: Unknown("not collected")})

    assert _found(results, "hardening-routing-authentication") == []


# -- FHRP authentication -----------------------------------------------------------------------


def test_a_configured_fhrp_group_without_authentication_is_medium() -> None:
    finding = _only(
        _analyse(facts={FHRP_GROUPS: 2, FHRP_GROUPS_WITHOUT_AUTHENTICATION: 1}),
        "hardening-fhrp-authentication",
    )

    assert finding.level is FindingLevel.MEDIUM
    assert "1 of 2" in finding.what_was_found


def test_no_fhrp_group_raises_nothing() -> None:
    results = _analyse(facts={FHRP_GROUPS: 0, FHRP_GROUPS_WITHOUT_AUTHENTICATION: 0})

    assert _found(results, "hardening-fhrp-authentication") == []


def test_authenticated_fhrp_groups_raise_nothing() -> None:
    results = _analyse(facts={FHRP_GROUPS: 2, FHRP_GROUPS_WITHOUT_AUTHENTICATION: 0})

    assert _found(results, "hardening-fhrp-authentication") == []


def test_fhrp_groups_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={FHRP_GROUPS: Unknown("not collected")}),
        "hardening-fhrp-authentication",
    )

    assert finding.level is FindingLevel.LOW


# -- ICMP redirects, unreachables and proxy ARP ------------------------------------------------


def test_icmp_settings_enabled_on_an_up_l3_interface_are_low() -> None:
    finding = _only(
        _analyse(
            facts={
                ICMP_REDIRECTS_L3_INTERFACES: 2,
                ICMP_UNREACHABLES_L3_INTERFACES: 1,
                PROXY_ARP_L3_INTERFACES: 3,
            }
        ),
        "hardening-icmp",
    )

    assert finding.level is FindingLevel.LOW
    assert "ICMP redirects" in finding.what_was_found
    assert "ICMP unreachables" in finding.what_was_found
    assert "proxy ARP" in finding.what_was_found
    assert "2" in finding.what_was_found
    assert "3" in finding.what_was_found


def test_icmp_settings_all_disabled_raises_nothing() -> None:
    results = _analyse(
        facts={
            ICMP_REDIRECTS_L3_INTERFACES: 0,
            ICMP_UNREACHABLES_L3_INTERFACES: 0,
            PROXY_ARP_L3_INTERFACES: 0,
        }
    )

    assert _found(results, "hardening-icmp") == []


def test_icmp_checks_only_run_where_an_l3_interface_is_up() -> None:
    results = _analyse(
        facts={ICMP_REDIRECTS_L3_INTERFACES: 2},
        interfaces=(),
    )

    assert _found(results, "hardening-icmp") == []


def test_a_down_l3_interface_is_not_applicable() -> None:
    down = (port("Vlan10", ips=["192.0.2.1/24"], admin_up=False, line_up=False),)

    results = _analyse(facts={ICMP_REDIRECTS_L3_INTERFACES: 2}, interfaces=down)

    assert _found(results, "hardening-icmp") == []


def test_icmp_interface_state_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={ICMP_REDIRECTS_L3_INTERFACES: 1}, interfaces=None),
        "hardening-icmp",
    )

    assert finding.level is FindingLevel.LOW
    assert "Could not decide" in finding.what_was_found


def test_icmp_settings_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={ICMP_REDIRECTS_L3_INTERFACES: Unknown("not collected")}),
        "hardening-icmp",
    )

    assert finding.level is FindingLevel.LOW


# -- The canary: no key, key-string or password reaches a Finding or a document ----------------


def test_no_config_key_or_password_reaches_a_finding_or_topology_json() -> None:
    config = device_text.IOS_XE_SERVICES_CONFIG
    record = _record(Platform.IOS_XE, IOS_XE)
    facts = ConfigFacts("dev-S1", platforms.read_config_facts(Platform.IOS_XE, config))
    built = topology.build([replace(record, config_facts=facts.facts)])
    results = analysis.analyse(AnalysisInput(topology=built, config_facts=(facts,)))

    assert results.findings  # the planted weaknesses fired
    planted = [canary for canary in device_text.SERVICE_CANARIES if canary in config]
    assert len(planted) == 3  # the NTP key, the HSRP key-string and the BGP password
    texts = [
        part
        for finding in results.findings
        for part in (
            finding.id,
            finding.what_was_found,
            finding.what_to_do,
            finding.source,
            finding.summary,
            finding.check.id,
            finding.check.name,
        )
    ]
    document = topology.to_document(
        replace(built, findings=results.findings, analysis=results.summary)
    )
    shown = json.dumps(document) + "\n".join(texts) + repr(results)
    for canary in device_text.SERVICE_CANARIES:
        assert canary not in shown
