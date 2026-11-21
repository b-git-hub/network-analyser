"""The SSH, VTY, AAA and timeout hardening Checks (#100; stories 59-66).

Driven through `analysis.analyse` with synthetic records and facts. Each Check's fire,
no-fire, not-applicable and could-not-decide cases are here, including the classic IOS /
IOS-XE differences and the canary proof that no secret reaches a Finding.
"""

import json
from collections.abc import Mapping
from dataclasses import replace

from network_analyser import analysis, platforms, topology
from network_analyser.records import Platform
from network_analyser.records.analysis import AnalysisInput, ConfigFact, ConfigFacts
from network_analyser.records.config_facts import (
    AAA_ACCOUNTING,
    AAA_AUTHORIZATION,
    AAA_CENTRAL_LOGIN,
    AAA_LOGIN_FALLBACK_NONE,
    AAA_NEW_MODEL,
    ENABLE_PASSWORD,
    ENABLE_SECRET,
    EXEC_TIMEOUT_DISABLED_LINES,
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
    SSH_VERSION,
    TELNET_LINES,
    TYPE_6_ENABLED,
    VTY_ACCESS_CLASS_MISSING_LINES,
    FactValue,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import AnalysisResults, CheckType, Finding, FindingLevel
from network_analyser.records.unknown import Unknown
from tests.support import hardening_access_text
from tests.support.topology_records import visited

A = "192.0.2.1"
IOS_XE = "17.9.4a"
LATE_IOS_XE = "17.12.1"
CLASSIC_IOS = "15.2(7)E7"
NXOS = "9.3(8)"


def _record(platform: Platform, release: str | Unknown) -> DeviceRecord:
    record = visited(A, "S1", "sw-a", platform=platform)
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, software_version=release))


def _safe_facts(platform: Platform, overrides: Mapping[str, FactValue]) -> tuple[ConfigFact, ...]:
    """A clean device for this batch and #96's, so only the planted hit fires."""
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
        VTY_ACCESS_CLASS_MISSING_LINES: (),
        AAA_LOGIN_FALLBACK_NONE: 0,
        AAA_CENTRAL_LOGIN: True,
        AAA_AUTHORIZATION: True,
        AAA_ACCOUNTING: True,
        EXEC_TIMEOUT_DISABLED_LINES: (),
        TYPE_6_ENABLED: True,
    }
    if platform is Platform.IOS_XE:
        facts.update(
            {
                ENABLE_SECRET: True,
                ENABLE_PASSWORD: False,
                INSECURE_MODE: False,
                SSH_VERSION: 2,
                AAA_NEW_MODEL: True,
            }
        )
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


def test_every_access_check_runs_and_has_its_fixed_level() -> None:
    results = _analyse(
        Platform.IOS_XE,
        CLASSIC_IOS,
        {
            SSH_VERSION: 0,
            VTY_ACCESS_CLASS_MISSING_LINES: ("line vty 0 4",),
            AAA_LOGIN_FALLBACK_NONE: 1,
            AAA_NEW_MODEL: False,
            AAA_CENTRAL_LOGIN: False,
            AAA_AUTHORIZATION: False,
            AAA_ACCOUNTING: False,
            EXEC_TIMEOUT_DISABLED_LINES: ("line con 0",),
            TYPE_6_ENABLED: False,
        },
    )

    levels = {
        "hardening-ssh-v2": FindingLevel.HIGH,
        "hardening-vty-access-class": FindingLevel.HIGH,
        "hardening-aaa-fallback": FindingLevel.HIGH,
        "hardening-aaa-central": FindingLevel.MEDIUM,
        "hardening-exec-timeout": FindingLevel.MEDIUM,
        "hardening-type-6": FindingLevel.MEDIUM,
    }
    for check_id, level in levels.items():
        finding = _only(results, check_id)
        assert finding.level is level
        assert finding.check.type is CheckType.CONFIGURATION
        assert finding.check.name
        assert finding.source == "config"
        assert finding.devices == ("dev-S1",)
        assert finding.what_was_found == finding.summary
        assert finding.what_to_do


# -- SSHv2 not enforced ------------------------------------------------------------------------


def test_ssh_v1_on_classic_ios_is_high() -> None:
    finding = _only(_analyse(Platform.IOS_XE, CLASSIC_IOS, {SSH_VERSION: 0}), "hardening-ssh-v2")

    assert finding.level is FindingLevel.HIGH
    assert "SSHv2 is not enforced" in finding.what_was_found
    assert "SSH 1.99" in finding.what_was_found


def test_ssh_v1_on_ios_xe_before_17_10_is_high() -> None:
    finding = _only(_analyse(Platform.IOS_XE, IOS_XE, {SSH_VERSION: 0}), "hardening-ssh-v2")

    assert finding.level is FindingLevel.HIGH


def test_ssh_v1_explicitly_configured_is_high_on_a_late_release() -> None:
    finding = _only(_analyse(Platform.IOS_XE, LATE_IOS_XE, {SSH_VERSION: 1}), "hardening-ssh-v2")

    assert finding.level is FindingLevel.HIGH
    assert "version 1" in finding.what_was_found


def test_ssh_v2_enforced_raises_nothing() -> None:
    assert _found(_analyse(facts={SSH_VERSION: 2}), "hardening-ssh-v2") == []


def test_a_late_ios_xe_release_without_the_line_could_not_decide() -> None:
    finding = _only(_analyse(Platform.IOS_XE, LATE_IOS_XE, {SSH_VERSION: 0}), "hardening-ssh-v2")

    assert finding.level is FindingLevel.LOW
    assert "Could not decide" in finding.what_was_found
    assert "17.10" in finding.what_was_found


def test_an_unknown_release_without_the_line_could_not_decide() -> None:
    finding = _only(
        _analyse(Platform.IOS_XE, Unknown("show version not read"), {SSH_VERSION: 0}),
        "hardening-ssh-v2",
    )

    assert finding.level is FindingLevel.LOW


def test_the_ssh_check_does_not_apply_to_nxos() -> None:
    results = _analyse(Platform.NX_OS, NXOS)

    assert _found(results, "hardening-ssh-v2") == []


def test_an_ssh_version_fact_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={SSH_VERSION: Unknown("config fact not collected: ssh_version")}),
        "hardening-ssh-v2",
    )

    assert finding.level is FindingLevel.LOW


# -- No VTY access-class -----------------------------------------------------------------------


def test_a_vty_block_without_an_inbound_access_class_is_high() -> None:
    finding = _only(
        _analyse(
            facts={
                VTY_ACCESS_CLASS_MISSING_LINES: ("line vty 0 4", "line vty 5 15"),
            }
        ),
        "hardening-vty-access-class",
    )

    assert finding.level is FindingLevel.HIGH
    assert "2" in finding.what_was_found
    assert "line vty 0 4" in finding.what_was_found
    assert "line vty 5 15" in finding.what_was_found


def test_every_vty_block_with_an_access_class_raises_nothing() -> None:
    assert (
        _found(_analyse(facts={VTY_ACCESS_CLASS_MISSING_LINES: ()}), "hardening-vty-access-class")
        == []
    )


def test_a_vty_access_class_fact_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={VTY_ACCESS_CLASS_MISSING_LINES: Unknown("not collected")}),
        "hardening-vty-access-class",
    )

    assert finding.level is FindingLevel.LOW


def test_an_nxos_vty_block_without_an_access_class_is_high() -> None:
    finding = _only(
        _analyse(
            Platform.NX_OS,
            NXOS,
            {VTY_ACCESS_CLASS_MISSING_LINES: ("line vty",)},
        ),
        "hardening-vty-access-class",
    )

    assert finding.level is FindingLevel.HIGH


# -- AAA fallback to none ----------------------------------------------------------------------


def test_aaa_login_fallback_to_none_is_high() -> None:
    finding = _only(_analyse(facts={AAA_LOGIN_FALLBACK_NONE: 2}), "hardening-aaa-fallback")

    assert finding.level is FindingLevel.HIGH
    assert "2 method lists" in finding.what_was_found
    assert "none" in finding.what_was_found


def test_no_aaa_login_fallback_to_none_raises_nothing() -> None:
    assert _found(_analyse(facts={AAA_LOGIN_FALLBACK_NONE: 0}), "hardening-aaa-fallback") == []


def test_an_aaa_fallback_count_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={AAA_LOGIN_FALLBACK_NONE: Unknown("not collected")}),
        "hardening-aaa-fallback",
    )

    assert finding.level is FindingLevel.LOW


def test_the_aaa_fallback_check_runs_on_nxos() -> None:
    finding = _only(
        _analyse(Platform.NX_OS, NXOS, {AAA_LOGIN_FALLBACK_NONE: 1}),
        "hardening-aaa-fallback",
    )

    assert finding.level is FindingLevel.HIGH


# -- No central AAA, authorisation or accounting -----------------------------------------------


def test_complete_central_aaa_raises_nothing() -> None:
    assert _found(_analyse(), "hardening-aaa-central") == []


def test_no_central_aaa_on_ios_names_all_four_missing_items() -> None:
    finding = _only(
        _analyse(
            facts={
                AAA_NEW_MODEL: False,
                AAA_CENTRAL_LOGIN: False,
                AAA_AUTHORIZATION: False,
                AAA_ACCOUNTING: False,
            }
        ),
        "hardening-aaa-central",
    )

    assert finding.level is FindingLevel.MEDIUM
    assert "4 of 4" in finding.what_was_found
    assert "aaa new-model" in finding.what_was_found
    assert "authorisation" in finding.what_was_found
    assert "accounting" in finding.what_was_found


def test_one_missing_central_aaa_item_is_medium_and_named() -> None:
    finding = _only(_analyse(facts={AAA_ACCOUNTING: False}), "hardening-aaa-central")

    assert finding.level is FindingLevel.MEDIUM
    assert "1 of 4" in finding.what_was_found
    assert "accounting" in finding.what_was_found


def test_nxos_central_aaa_does_not_need_aaa_new_model() -> None:
    complete = _analyse(Platform.NX_OS, NXOS)
    missing = _only(
        _analyse(
            Platform.NX_OS,
            NXOS,
            {
                AAA_CENTRAL_LOGIN: False,
                AAA_AUTHORIZATION: False,
                AAA_ACCOUNTING: False,
            },
        ),
        "hardening-aaa-central",
    )

    assert _found(complete, "hardening-aaa-central") == []
    assert missing.level is FindingLevel.MEDIUM
    assert "3 of 3" in missing.what_was_found
    assert "aaa new-model" not in missing.what_was_found


def test_a_central_aaa_fact_not_read_with_nothing_missing_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={AAA_AUTHORIZATION: Unknown("not collected")}), "hardening-aaa-central"
    )

    assert finding.level is FindingLevel.LOW


def test_a_known_missing_central_aaa_item_fires_even_when_another_was_not_read() -> None:
    finding = _only(
        _analyse(
            facts={
                AAA_AUTHORIZATION: Unknown("not collected"),
                AAA_ACCOUNTING: False,
            }
        ),
        "hardening-aaa-central",
    )

    assert finding.level is FindingLevel.MEDIUM
    assert "accounting" in finding.what_was_found


# -- Exec timeout ------------------------------------------------------------------------------


def test_a_disabled_exec_timeout_is_medium_and_names_the_blocks() -> None:
    finding = _only(
        _analyse(facts={EXEC_TIMEOUT_DISABLED_LINES: ("line con 0", "line vty 0 4")}),
        "hardening-exec-timeout",
    )

    assert finding.level is FindingLevel.MEDIUM
    assert "2" in finding.what_was_found
    assert "line con 0" in finding.what_was_found
    assert "line vty 0 4" in finding.what_was_found


def test_the_vendor_default_timeout_raises_nothing() -> None:
    assert _found(_analyse(facts={EXEC_TIMEOUT_DISABLED_LINES: ()}), "hardening-exec-timeout") == []


def test_an_exec_timeout_fact_not_read_is_a_low_could_not_decide() -> None:
    finding = _only(
        _analyse(facts={EXEC_TIMEOUT_DISABLED_LINES: Unknown("not collected")}),
        "hardening-exec-timeout",
    )

    assert finding.level is FindingLevel.LOW


def test_the_exec_timeout_check_runs_on_nxos() -> None:
    finding = _only(
        _analyse(
            Platform.NX_OS,
            NXOS,
            {EXEC_TIMEOUT_DISABLED_LINES: ("line console",)},
        ),
        "hardening-exec-timeout",
    )

    assert finding.level is FindingLevel.MEDIUM


# -- Type 6 not enabled ------------------------------------------------------------------------


def test_type_6_not_enabled_is_medium() -> None:
    finding = _only(_analyse(facts={TYPE_6_ENABLED: False}), "hardening-type-6")

    assert finding.level is FindingLevel.MEDIUM
    assert "type 6" in finding.what_was_found


def test_type_6_enabled_raises_nothing() -> None:
    assert _found(_analyse(facts={TYPE_6_ENABLED: True}), "hardening-type-6") == []


def test_an_nxos_type_6_fact_that_was_not_read_could_not_decide() -> None:
    finding = _only(
        _analyse(
            Platform.NX_OS,
            NXOS,
            {TYPE_6_ENABLED: Unknown("the NX-OS AES command is not confirmed")},
        ),
        "hardening-type-6",
    )

    assert finding.level is FindingLevel.LOW
    assert "Could not decide" in finding.what_was_found


# -- The canary: no secret or key reaches a Finding or topology.json ----------------------------


def test_no_access_secret_or_key_reaches_a_finding_or_topology_json() -> None:
    config = hardening_access_text.IOS_XE_ACCESS_CONFIG
    record = _record(Platform.IOS_XE, IOS_XE)
    facts = ConfigFacts("dev-S1", platforms.read_config_facts(Platform.IOS_XE, config))
    built = topology.build([replace(record, config_facts=facts.facts)])
    results = analysis.analyse(AnalysisInput(topology=built, config_facts=(facts,)))

    assert results.findings  # the planted weaknesses fired
    planted = hardening_access_text.IOS_XE_ACCESS_CONFIG + hardening_access_text.NXOS_ACCESS_CONFIG
    for canary in hardening_access_text.ACCESS_CANARIES:
        assert canary in planted
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
    for canary in hardening_access_text.ACCESS_CANARIES:
        assert canary not in shown
