"""Hardening Check accuracy fixes from the 0.2.0 / 0.3.0 review (#142).

Driven through `analysis.analyse` with synthetic records and facts only: the SSHv2 Check
reads `show ip ssh` for the version in force, and every Check whose config fact can go
unread says "could not decide" rather than passing the device.
"""

from dataclasses import replace

import pytest

from network_analyser.records.collected import SshSettings
from network_analyser.records.config_facts import (
    AAA_LOGIN_FALLBACK_NONE,
    EXEC_TIMEOUT_DISABLED_LINES,
    FHRP_GROUPS,
    NTP_CONFIGURED,
    REMOTE_SYSLOG_SERVERS,
    SECRET_TYPE_5,
    SNMP_V1_V2C_COMMUNITIES,
    SSH_VERSION,
    FactValue,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import Finding, FindingLevel
from network_analyser.records.unknown import Unknown
from tests.support.analysis_records import analysed, facts, found
from tests.support.topology_records import port, visited

A = "192.0.2.1"
SSH_CHECK = "hardening-ssh-v2"
LATE = "17.12.1"
EARLY = "17.9.4a"
CLASSIC = "15.2(7)E7"


def _device(release: str, ssh: SshSettings | Unknown | None = None) -> DeviceRecord:
    record = visited(A, "S1", "sw-a", ssh=ssh, interfaces=(port("Vlan10", ips=["192.0.2.1/24"]),))
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, software_version=release))


def _ssh(version: str | Unknown) -> SshSettings:
    return SshSettings(enabled=True, version=version, key_bits=2048)


def _only(record: DeviceRecord, ssh_version: int) -> Finding | None:
    results = analysed(record, facts=facts("dev-S1", **{SSH_VERSION: ssh_version}))
    findings = found(results, SSH_CHECK)
    assert len(findings) <= 1
    return findings[0] if findings else None


# -- SSHv2 reads show ip ssh --------------------------------------------------------------------


def test_a_late_release_whose_show_ip_ssh_says_version_2_passes() -> None:
    assert _only(_device(LATE, _ssh("2.0")), 0) is None


def test_a_late_release_whose_show_ip_ssh_says_1_99_is_high() -> None:
    finding = _only(_device(LATE, _ssh("1.99")), 0)

    assert finding is not None
    assert finding.level is FindingLevel.HIGH
    assert "show ip ssh" in finding.what_was_found
    assert "1.99" not in finding.what_was_found


def test_an_early_release_whose_show_ip_ssh_says_version_2_passes() -> None:
    assert _only(_device(EARLY, _ssh("2.0")), 0) is None


def test_a_classic_ios_whose_show_ip_ssh_says_1_99_is_high() -> None:
    finding = _only(_device(CLASSIC, _ssh("1.99")), 0)

    assert finding is not None
    assert finding.level is FindingLevel.HIGH


def test_a_late_release_with_an_unreported_version_could_not_decide() -> None:
    for ssh in (_ssh(Unknown("SSH version not reported by show ip ssh")), None, Unknown("denied")):
        finding = _only(_device(LATE, ssh), 0)

        assert finding is not None
        assert finding.level is FindingLevel.LOW
        assert finding.what_was_found.startswith("Could not decide:")


def test_a_late_release_with_a_version_it_cannot_read_could_not_decide() -> None:
    finding = _only(_device(LATE, _ssh("CANARY-cfg-142-ssh")), 0)

    assert finding is not None
    assert finding.level is FindingLevel.LOW
    assert "CANARY" not in finding.what_was_found


def test_an_early_release_without_show_output_is_still_high() -> None:
    finding = _only(_device(EARLY), 0)

    assert finding is not None
    assert finding.level is FindingLevel.HIGH


def test_the_configured_version_wins_over_show_ip_ssh() -> None:
    assert _only(_device(LATE, _ssh("1.99")), 2) is None
    finding = _only(_device(LATE, _ssh("2.0")), 1)
    assert finding is not None
    assert finding.level is FindingLevel.HIGH


# -- A fact that was not read is "could not decide", never a pass ------------------------------


@pytest.mark.parametrize(
    ("check_id", "fact"),
    [
        ("hardening-weak-secret-types", SECRET_TYPE_5),
        ("hardening-snmp-v1-v2c", SNMP_V1_V2C_COMMUNITIES),
        ("hardening-ntp", NTP_CONFIGURED),
        ("hardening-remote-syslog", REMOTE_SYSLOG_SERVERS),
        ("hardening-fhrp-authentication", FHRP_GROUPS),
        ("hardening-exec-timeout", EXEC_TIMEOUT_DISABLED_LINES),
        ("hardening-aaa-fallback", AAA_LOGIN_FALLBACK_NONE),
        ("hardening-ssh-v2", SSH_VERSION),
    ],
)
def test_an_unread_config_fact_makes_its_check_could_not_decide(check_id: str, fact: str) -> None:
    unread: dict[str, FactValue] = {fact: Unknown(f"config fact not collected: {fact}")}
    if check_id == "hardening-weak-secret-types":
        unread = {"secret_type_0": 0, "secret_type_4": 0, "secret_type_7": 0, **unread}
    results = analysed(_device(EARLY), facts=facts("dev-S1", **unread))

    findings = found(results, check_id)

    assert len(findings) == 1
    assert findings[0].level is FindingLevel.LOW
    assert findings[0].what_was_found.startswith("Could not decide:")
