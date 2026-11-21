"""The first hardening Checks, decided from secret-free config facts (#96; stories 59-66).

Driven through `analysis.analyse` with synthetic records and facts only. Each Check's fire,
no-fire, not-applicable and could-not-decide cases are here, with the classic IOS / IOS-XE /
NX-OS differences and the canary proof that no secret or community string reaches a Finding.
"""

import json
from collections.abc import Mapping
from dataclasses import replace

from network_analyser import analysis, platforms, topology
from network_analyser.records import Platform
from network_analyser.records.analysis import AnalysisInput, ConfigFact, ConfigFacts
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
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import AnalysisResults, CheckType, Finding, FindingLevel
from network_analyser.records.unknown import Unknown
from tests.support import device_text
from tests.support.topology_records import visited

A = "192.0.2.1"
IOS_XE = "17.9.4a"
CLASSIC_IOS = "15.2(7)E7"
NXOS = "9.3(8)"


def _record(platform: Platform, release: str | Unknown) -> DeviceRecord:
    record = visited(A, "S1", "sw-a", platform=platform)
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, software_version=release))


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
    }
    if platform is Platform.IOS_XE:
        facts.update({ENABLE_SECRET: True, ENABLE_PASSWORD: False, INSECURE_MODE: False})
    else:
        facts[SNMP_GLOBAL_ENFORCE_PRIV] = True
    facts.update(overrides)
    return tuple(ConfigFact(name, value) for name, value in facts.items())


def _analyse(
    platform: Platform = Platform.IOS_XE,
    release: str | Unknown = IOS_XE,
    facts: Mapping[str, FactValue] | None = None,
) -> AnalysisResults:
    built = topology.build([_record(platform, release)])
    given = _safe_facts(platform, facts or {})
    return analysis.analyse(
        AnalysisInput(topology=built, config_facts=(ConfigFacts("dev-S1", given),))
    )


def _found(results: AnalysisResults, check_id: str) -> list[Finding]:
    return [finding for finding in results.findings if finding.check.id == check_id]


def _only(results: AnalysisResults, check_id: str) -> Finding:
    found = _found(results, check_id)
    assert len(found) == 1
    return found[0]


def test_every_hardening_check_runs_and_has_its_fixed_level() -> None:
    results = _analyse(
        facts={
            TELNET_LINES: ("line vty 0 4",),
            SECRET_TYPE_7: 1,
            ENABLE_PASSWORD: True,
            SNMP_V1_V2C_COMMUNITIES: 1,
            SNMP_V3_CONFIGURED: True,
            SNMP_V3_USERS: 1,
            SNMP_V3_USERS_WITHOUT_PRIV: 1,
            INSECURE_MODE: True,
            HTTP_SERVER: True,
            IP_SOURCE_ROUTE: True,
        }
    )

    levels = {
        "hardening-telnet": FindingLevel.HIGH,
        "hardening-weak-secret-types": FindingLevel.HIGH,
        "hardening-enable-secret": FindingLevel.HIGH,
        "hardening-snmp-v1-v2c": FindingLevel.HIGH,
        "hardening-snmp-v3-priv": FindingLevel.HIGH,
        "hardening-insecure-mode": FindingLevel.HIGH,
        "hardening-http-server": FindingLevel.HIGH,
        "hardening-legacy-services": FindingLevel.HIGH,
    }
    for check_id, level in levels.items():
        finding = _only(results, check_id)
        assert finding.level is level
        assert finding.check.type is CheckType.CONFIGURATION
        assert finding.check.name
        assert finding.source == "config"
        assert finding.devices == ("dev-S1",)
        assert finding.what_was_found == finding.summary


# -- Telnet ------------------------------------------------------------------------------------


def test_telnet_on_a_vty_block_is_high_and_names_the_block() -> None:
    finding = _only(
        _analyse(facts={TELNET_LINES: ("line vty 0 4", "line vty 5 15")}),
        "hardening-telnet",
    )

    assert finding.level is FindingLevel.HIGH
    assert "line vty 0 4" in finding.what_was_found
    assert "line vty 5 15" in finding.what_was_found
    assert "2" in finding.what_was_found
    assert finding.what_to_do


def test_telnet_not_permitted_raises_nothing() -> None:
    assert _found(_analyse(facts={TELNET_LINES: ()}), "hardening-telnet") == []


def test_telnet_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={TELNET_LINES: Unknown("no line vty block")}), "hardening-telnet"
    )

    assert finding.level is FindingLevel.LOW
    assert "Could not decide" in finding.what_was_found
    assert "no line vty block" in finding.what_was_found


# -- Weak secret types -------------------------------------------------------------------------


def test_weak_secret_types_fire_with_type_numbers_and_counts() -> None:
    finding = _only(
        _analyse(facts={SECRET_TYPE_0: 1, SECRET_TYPE_4: 2, SECRET_TYPE_7: 3}),
        "hardening-weak-secret-types",
    )

    assert finding.level is FindingLevel.HIGH
    assert "type 0 x1" in finding.what_was_found
    assert "type 4 x2" in finding.what_was_found
    assert "type 7 x3" in finding.what_was_found


def test_type_5_is_weak_on_classic_ios() -> None:
    finding = _only(
        _analyse(Platform.IOS_XE, CLASSIC_IOS, {SECRET_TYPE_5: 1}),
        "hardening-weak-secret-types",
    )

    assert finding.level is FindingLevel.HIGH
    assert "type 5 x1" in finding.what_was_found


def test_type_5_is_not_weak_on_ios_xe_or_nxos() -> None:
    ios_xe = _analyse(Platform.IOS_XE, IOS_XE, {SECRET_TYPE_5: 1})
    nxos = _analyse(Platform.NX_OS, NXOS, {SECRET_TYPE_5: 1})

    assert _found(ios_xe, "hardening-weak-secret-types") == []
    assert _found(nxos, "hardening-weak-secret-types") == []


def test_strong_secret_types_9_and_8_raise_nothing() -> None:
    results = _analyse(facts={SECRET_TYPE_8: 2, SECRET_TYPE_9: 1})

    assert _found(results, "hardening-weak-secret-types") == []


def test_a_weak_type_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={SECRET_TYPE_7: Unknown("config fact not collected: secret_type_7")}),
        "hardening-weak-secret-types",
    )

    assert finding.level is FindingLevel.LOW
    assert "secret_type_7" in finding.what_was_found


# -- Enable password or no enable secret -------------------------------------------------------


def test_no_enable_secret_is_high() -> None:
    finding = _only(_analyse(facts={ENABLE_SECRET: False}), "hardening-enable-secret")

    assert finding.level is FindingLevel.HIGH
    assert "No enable secret" in finding.what_was_found


def test_an_enable_password_is_high_even_with_an_enable_secret() -> None:
    finding = _only(
        _analyse(facts={ENABLE_SECRET: True, ENABLE_PASSWORD: True}), "hardening-enable-secret"
    )

    assert finding.level is FindingLevel.HIGH
    assert "Enable password" in finding.what_was_found


def test_an_enable_secret_without_an_enable_password_raises_nothing() -> None:
    assert _found(_analyse(), "hardening-enable-secret") == []


def test_the_enable_secret_check_does_not_apply_to_nxos() -> None:
    assert _found(_analyse(Platform.NX_OS, NXOS), "hardening-enable-secret") == []


def test_an_enable_secret_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={ENABLE_SECRET: Unknown("config fact not collected: enable_secret")}),
        "hardening-enable-secret",
    )

    assert finding.level is FindingLevel.LOW


# -- SNMPv1/v2c --------------------------------------------------------------------------------


def test_a_read_only_community_is_high() -> None:
    finding = _only(
        _analyse(
            facts={
                SNMP_V1_V2C_COMMUNITIES: 1,
                SNMP_V1_V2C_READ_WRITE_COMMUNITIES: 0,
            }
        ),
        "hardening-snmp-v1-v2c",
    )

    assert finding.level is FindingLevel.HIGH
    assert "1 community" in finding.what_was_found
    assert "read-write" in finding.what_was_found


def test_a_read_write_default_named_community_is_critical() -> None:
    finding = _only(
        _analyse(
            facts={
                SNMP_V1_V2C_COMMUNITIES: 2,
                SNMP_V1_V2C_READ_WRITE_COMMUNITIES: 1,
                SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME: 1,
            }
        ),
        "hardening-snmp-v1-v2c",
    )

    assert finding.level is FindingLevel.CRITICAL
    assert "default name" in finding.what_was_found


def test_a_read_write_community_with_no_acl_is_critical() -> None:
    finding = _only(
        _analyse(
            facts={
                SNMP_V1_V2C_COMMUNITIES: 2,
                SNMP_V1_V2C_READ_WRITE_COMMUNITIES: 1,
                SNMP_V1_V2C_READ_WRITE_NO_ACL: 1,
            }
        ),
        "hardening-snmp-v1-v2c",
    )

    assert finding.level is FindingLevel.CRITICAL
    assert "ACL" in finding.what_was_found


def test_a_read_write_community_with_a_name_and_an_acl_is_high() -> None:
    finding = _only(
        _analyse(
            facts={
                SNMP_V1_V2C_COMMUNITIES: 1,
                SNMP_V1_V2C_READ_WRITE_COMMUNITIES: 1,
                SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME: 0,
                SNMP_V1_V2C_READ_WRITE_NO_ACL: 0,
            }
        ),
        "hardening-snmp-v1-v2c",
    )

    assert finding.level is FindingLevel.HIGH


def test_no_snmp_community_raises_nothing() -> None:
    results = _analyse(facts={SNMP_V1_V2C_COMMUNITIES: 0})

    assert _found(results, "hardening-snmp-v1-v2c") == []


def test_snmp_communities_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={SNMP_V1_V2C_COMMUNITIES: Unknown("not collected")}),
        "hardening-snmp-v1-v2c",
    )

    assert finding.level is FindingLevel.LOW


# -- SNMPv3 without privacy --------------------------------------------------------------------


def test_snmpv3_user_without_priv_is_high() -> None:
    finding = _only(
        _analyse(
            facts={
                SNMP_V3_CONFIGURED: True,
                SNMP_V3_USERS: 2,
                SNMP_V3_USERS_WITHOUT_PRIV: 1,
            }
        ),
        "hardening-snmp-v3-priv",
    )

    assert finding.level is FindingLevel.HIGH
    assert "1 of 2 users" in finding.what_was_found


def test_snmpv3_group_without_priv_is_high() -> None:
    finding = _only(
        _analyse(facts={SNMP_V3_CONFIGURED: True, SNMP_V3_GROUPS_WITHOUT_PRIV: 1}),
        "hardening-snmp-v3-priv",
    )

    assert finding.level is FindingLevel.HIGH


def test_snmpv3_checks_run_only_where_snmpv3_is_configured() -> None:
    results = _analyse(facts={SNMP_V3_CONFIGURED: False, SNMP_V3_USERS_WITHOUT_PRIV: 0})

    assert _found(results, "hardening-snmp-v3-priv") == []


def test_a_configured_snmpv3_that_is_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={SNMP_V3_CONFIGURED: Unknown("not collected")}),
        "hardening-snmp-v3-priv",
    )

    assert finding.level is FindingLevel.LOW


def test_nxos_without_global_privacy_enforcement_is_high() -> None:
    finding = _only(
        _analyse(
            Platform.NX_OS,
            NXOS,
            {SNMP_V3_CONFIGURED: True, SNMP_GLOBAL_ENFORCE_PRIV: False},
        ),
        "hardening-snmp-v3-priv",
    )

    assert finding.level is FindingLevel.HIGH
    assert "global privacy enforcement" in finding.what_was_found


def test_nxos_with_global_privacy_enforcement_and_priv_groups_raises_nothing() -> None:
    results = _analyse(
        Platform.NX_OS,
        NXOS,
        {
            SNMP_V3_CONFIGURED: True,
            SNMP_V3_GROUPS_WITHOUT_PRIV: 0,
            SNMP_GLOBAL_ENFORCE_PRIV: True,
        },
    )

    assert _found(results, "hardening-snmp-v3-priv") == []


# -- Insecure mode -----------------------------------------------------------------------------


def test_insecure_mode_is_high_on_ios_xe() -> None:
    finding = _only(_analyse(facts={INSECURE_MODE: True}), "hardening-insecure-mode")

    assert finding.level is FindingLevel.HIGH
    assert "system mode insecure" in finding.what_was_found


def test_insecure_mode_is_not_a_classic_ios_or_nxos_check() -> None:
    classic = _analyse(Platform.IOS_XE, CLASSIC_IOS, {INSECURE_MODE: True})
    nxos = _analyse(Platform.NX_OS, NXOS)

    assert _found(classic, "hardening-insecure-mode") == []
    assert _found(nxos, "hardening-insecure-mode") == []


def test_an_unread_insecure_mode_on_an_unknown_release_could_not_decide() -> None:
    finding = _only(
        _analyse(Platform.IOS_XE, Unknown("show version not read"), {INSECURE_MODE: False}),
        "hardening-insecure-mode",
    )

    assert finding.level is FindingLevel.LOW


# -- Plain HTTP server -------------------------------------------------------------------------


def test_the_plain_http_server_is_high() -> None:
    finding = _only(_analyse(facts={HTTP_SERVER: True}), "hardening-http-server")

    assert finding.level is FindingLevel.HIGH
    assert "ip http server" in finding.what_was_found


def test_no_plain_http_server_raises_nothing() -> None:
    assert _found(_analyse(facts={HTTP_SERVER: False}), "hardening-http-server") == []


def test_an_http_server_fact_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={HTTP_SERVER: Unknown("not collected")}), "hardening-http-server"
    )

    assert finding.level is FindingLevel.LOW


# -- Legacy services ---------------------------------------------------------------------------


def test_source_routing_on_by_default_is_high() -> None:
    finding = _only(_analyse(facts={IP_SOURCE_ROUTE: True}), "hardening-legacy-services")

    assert finding.level is FindingLevel.HIGH
    assert "ip source-route" in finding.what_was_found


def test_legacy_services_are_named_by_keyword_and_count() -> None:
    finding = _only(
        _analyse(facts={LEGACY_SERVICES: ("PAD", "FTP", "TFTP")}),
        "hardening-legacy-services",
    )

    assert finding.level is FindingLevel.HIGH
    assert "3" in finding.what_was_found
    assert "PAD" in finding.what_was_found
    assert "FTP" in finding.what_was_found


def test_no_legacy_service_raises_nothing() -> None:
    results = _analyse(facts={IP_SOURCE_ROUTE: False, LEGACY_SERVICES: ()})

    assert _found(results, "hardening-legacy-services") == []


def test_a_legacy_services_fact_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={LEGACY_SERVICES: Unknown("not collected")}),
        "hardening-legacy-services",
    )

    assert finding.level is FindingLevel.LOW


# -- The canary: no secret or community string reaches a Finding or a document -----------------


def test_no_config_secret_or_community_string_reaches_a_finding_or_topology_json() -> None:
    config = device_text.IOS_XE_HARDENING_CONFIG
    record = _record(Platform.IOS_XE, IOS_XE)
    facts = ConfigFacts("dev-S1", platforms.read_config_facts(Platform.IOS_XE, config))
    built = topology.build([replace(record, config_facts=facts.facts)])
    results = analysis.analyse(AnalysisInput(topology=built, config_facts=(facts,)))

    assert results.findings  # the planted weaknesses fired
    planted = [canary for canary in device_text.HARDENING_CANARIES if canary in config]
    assert len(planted) == 6  # the IOS config's hashes, passwords and community strings
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
    for canary in device_text.HARDENING_CANARIES:
        assert canary not in shown
