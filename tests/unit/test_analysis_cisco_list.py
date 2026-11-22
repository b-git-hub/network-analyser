"""Cisco's own insecure-configuration list, mapped to our Checks (#102, story 67).

Driven through `analysis.analyse` with synthetic `show system insecure configuration` entries.
A matching entry marks our Finding `also_flagged_by_cisco`; an unmatched one is a Finding in
Cisco's own words at Cisco's own level, under the dedicated `config-cisco-insecure-list` id.
Below 17.18.2, or on NX-OS, the command is absent and the Check is not run (story 68).
"""

import pytest

from network_analyser.analysis.checks import CHECKS
from network_analyser.analysis.cisco_list import RULES
from network_analyser.records.collected import InsecureConfigurationItem, SnmpUser
from network_analyser.records.config_facts import (
    ENABLE_PASSWORD,
    ENABLE_SECRET,
    HTTP_SERVER,
    SECRET_TYPE_7,
    TELNET_LINES,
    FactValue,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.platform import Platform
from network_analyser.records.topology import FindingLevel
from network_analyser.records.unknown import Unknown
from tests.support.analysis_records import analysed, facts, found, run_of
from tests.support.topology_records import visited

A = "192.0.2.1"
CISCO = "config-cisco-insecure-list"
SNMP = "config-snmpv3-user-crypto"
ROLE = "config-device-role-out-of-date"
FTP = InsecureConfigurationItem(
    module="FTP",
    command="ip ftp source-interface GigabitEthernet0/0",
    reason="No encryption is configured",
    severity="HIGH",
)
WEAK_SNMP = InsecureConfigurationItem(
    module="SNMP",
    command="snmp-server user <STRING> NA-RO auth md5 <STRING>",
    reason="Legacy protocol poses data confidentiality risks",
    severity="HIGH",
)
TELNET = InsecureConfigurationItem(
    module="Telnet",
    command="line vty 0 4 transport input telnet",
    reason="Cleartext protocol poses data confidentiality risks",
    severity="HIGH",
)
HTTP = InsecureConfigurationItem(
    module="HTTP",
    command="ip http server",
    reason="Cleartext protocol poses data confidentiality risks",
    severity="HIGH",
)


def _device(*items: InsecureConfigurationItem, **shown: object) -> DeviceRecord:
    return visited(A, "S1", "sw-a", insecure=[*items], **shown)  # type: ignore[arg-type]  # test input


def _item(
    severity: str | Unknown = "HIGH", command: str = "ip ftp source-interface Gi0/0"
) -> InsecureConfigurationItem:
    return InsecureConfigurationItem("FTP", command, "Cisco says so", severity)


def test_an_item_matching_our_check_marks_it_also_flagged_by_cisco() -> None:
    device = _device(WEAK_SNMP, snmp_users=[SnmpUser("legacy", "MD5", "DES", "NA-RO")])

    results = analysed(device)

    snmp = found(results, SNMP)
    assert len(snmp) == 1
    assert snmp[0].also_flagged_by_cisco is True
    assert found(results, CISCO) == []


def test_an_unmatched_item_is_reported_in_ciscos_own_words_at_its_level() -> None:
    results = analysed(_device(FTP))

    (finding,) = found(results, CISCO)

    assert finding.level is FindingLevel.HIGH
    assert finding.check.name == "Cisco insecure-list items"
    assert finding.check.type.value == "Configuration"
    assert finding.source == "Cisco insecure configuration"
    assert finding.devices == ("dev-S1",)
    assert "Cisco flags FTP: ip ftp source-interface <value>." in finding.what_was_found
    assert "Reason: No encryption is configured." in finding.what_was_found
    assert finding.what_was_found == finding.summary


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        ("CRITICAL", FindingLevel.CRITICAL),
        ("HIGH", FindingLevel.HIGH),
        ("MEDIUM", FindingLevel.MEDIUM),
        ("LOW", FindingLevel.LOW),
        ("medium", FindingLevel.MEDIUM),
    ],
)
def test_a_cisco_item_keeps_ciscos_own_level(severity: str, level: FindingLevel) -> None:
    (finding,) = found(analysed(_device(_item(severity))), CISCO)

    assert finding.level is level


def test_a_severity_that_cannot_be_read_is_low_and_says_so() -> None:
    (finding,) = found(analysed(_device(_item(Unknown("severity not reported")))), CISCO)

    assert finding.level is FindingLevel.LOW
    assert "Cisco's severity was not read" in finding.what_was_found


def test_no_insecure_configurations_raise_nothing() -> None:
    results = analysed(_device())

    assert found(results, CISCO) == []
    assert run_of(results, CISCO).ran is True


def test_an_unmatched_item_whose_mapped_check_did_not_fire_is_still_reported() -> None:
    healthy = _device(WEAK_SNMP, snmp_users=[SnmpUser("modern", "SHA-256", "AES256", "NA-RO")])

    results = analysed(healthy)

    assert found(results, SNMP) == []
    (finding,) = found(results, CISCO)
    assert "Cisco flags SNMP" in finding.what_was_found


def test_the_same_item_twice_is_one_finding() -> None:
    results = analysed(_device(FTP, FTP))

    assert len(found(results, CISCO)) == 1


def test_below_17_18_2_the_check_is_absent_not_run() -> None:
    device = visited(A, "S1", "sw-a")  # insecure_configuration is None below the gate

    results = analysed(device)

    assert found(results, CISCO) == []
    run = run_of(results, CISCO)
    assert run.ran is False
    assert [skip.reason for skip in run.skipped] == [
        "IOS-XE 17.18.2 or later is required for show system insecure configuration"
    ]


def test_nxos_has_no_cisco_list_and_the_check_is_not_run() -> None:
    device = visited(A, "S1", "sw-a", platform=Platform.NX_OS)

    results = analysed(device)

    assert found(results, CISCO) == []
    assert run_of(results, CISCO).ran is False
    assert run_of(results, CISCO).skipped[0].reason == (
        "this Platform has no Cisco insecure-configuration list"
    )


def test_a_refused_cisco_list_command_skips_the_check_and_raises_one_role_finding() -> None:
    device = visited(
        A, "S1", "sw-a", insecure=Unknown("show system insecure configuration: denied")
    )

    results = analysed(device)

    assert found(results, CISCO) == []
    run = run_of(results, CISCO)
    assert run.ran is False
    assert run.skipped[0].reason == "show system insecure configuration: denied"
    (role,) = found(results, ROLE)
    assert "Cisco insecure-list items" in role.what_was_found


def test_a_cisco_list_that_cannot_be_read_is_could_not_decide() -> None:
    device = visited(
        A, "S1", "sw-a", insecure=Unknown("show system insecure configuration: not understood")
    )

    results = analysed(device)

    (finding,) = found(results, CISCO)
    assert finding.level is FindingLevel.LOW
    assert "Could not decide:" in finding.what_was_found
    assert run_of(results, CISCO).skipped == ()


def test_ciscos_command_keeps_its_placeholder_and_never_a_configured_value() -> None:
    community = InsecureConfigurationItem(
        "SNMP", "snmp-server community <STRING> RO", "Legacy protocol", "HIGH"
    )

    (finding,) = found(analysed(_device(community)), CISCO)

    assert "snmp-server community <STRING> <value>" in finding.what_was_found


@pytest.mark.parametrize(
    ("item", "check_id", "values"),
    [
        (TELNET, "hardening-telnet", {TELNET_LINES: ("line vty 0 4",)}),
        (HTTP, "hardening-http-server", {HTTP_SERVER: True}),
    ],
    ids=["telnet", "http-server"],
)
def test_an_item_matching_a_shipped_check_marks_it_and_adds_no_second_row(
    item: InsecureConfigurationItem, check_id: str, values: dict[str, FactValue]
) -> None:
    """The 0.2.0/0.3.0 bug: the mapping named ids no Check ships, so the item showed twice."""
    results = analysed(_device(item), facts=facts("dev-S1", **values))

    (finding,) = found(results, check_id)
    assert finding.also_flagged_by_cisco is True
    assert found(results, CISCO) == []


def test_an_item_whose_mapped_check_only_could_not_decide_is_still_reported() -> None:
    """A "could not decide" Finding flags nothing, so Cisco's own words must still be shown."""
    results = analysed(_device(TELNET))

    (telnet,) = found(results, "hardening-telnet")
    assert telnet.also_flagged_by_cisco is False
    (finding,) = found(results, CISCO)
    assert "Cisco flags Telnet" in finding.what_was_found


def test_an_item_can_match_two_checks_at_once() -> None:
    item = InsecureConfigurationItem(
        module="Password",
        command="enable password <STRING>",
        reason="Reversible secret",
        severity="HIGH",
    )

    results = analysed(
        _device(item),
        facts=facts(
            "dev-S1",
            **{ENABLE_PASSWORD: True, ENABLE_SECRET: True, SECRET_TYPE_7: 1},
        ),
    )

    (enable,) = found(results, "hardening-enable-secret")
    (weak,) = found(results, "hardening-weak-secret-types")
    assert enable.also_flagged_by_cisco is True
    assert weak.also_flagged_by_cisco is True
    assert found(results, CISCO) == []


def test_every_mapped_check_id_is_a_shipped_check() -> None:
    """The mapping may only name Checks that exist: a stale id silently stops matching (#140)."""
    shipped = {definition.check.id for definition in CHECKS}
    mapped = {check_id for rule in RULES for check_id in rule.check_ids}

    assert mapped <= shipped, f"mapped Check ids no Check ships: {sorted(mapped - shipped)}"


@pytest.mark.parametrize(
    "command",
    [
        "snmp-server community CANARY-community RO",
        "ip ftp password CANARY-ftp-password",
        "username netops password 7 CANARY-type-7-hash",
    ],
)
def test_a_value_in_ciscos_command_line_never_reaches_a_finding(command: str) -> None:
    """Cisco may echo a configured value; only keywords survive (stories 66, 81, 116)."""
    item = InsecureConfigurationItem("FTP", command, "Cisco says so", "HIGH")

    (finding,) = found(analysed(_device(item)), CISCO)

    shown = (
        f"{finding.id} {finding.what_was_found} {finding.what_to_do} "
        f"{finding.source} {finding.summary}"
    )
    assert "CANARY" not in shown
    assert "<value>" in finding.what_was_found


def test_the_snmp_community_entry_maps_to_the_snmp_v1_v2c_check() -> None:
    (rule,) = [
        rule
        for rule in RULES
        if "hardening-snmp-v1-v2c" in rule.check_ids and "community" in rule.words
    ]

    assert "snmp" in rule.modules
