"""The five show-output hardening Checks, at Analysis's public seam (#102, story 60).

Driven through `analysis.analyse` with synthetic `Collected` records and config facts only:
no device, no network, no captured output. Each Check is proved to fire, not to fire, not to
apply where its feature is not in use, and to raise story 6's Low "could not decide" Finding
when the output was read but cannot decide. A refused command is a skip for that device, with
its reason recorded, never a pass (story 80).
"""

from collections.abc import Callable
from typing import Any

import pytest

from network_analyser.records.analysis import (
    NTP_CONFIGURED,
    SNMP_V3_USER_CRYPTO,
    ConfigFacts,
)
from network_analyser.records.collected import (
    ControlPlanePolicy,
    NtpAssociation,
    SnmpUser,
    SshSettings,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.platform import Platform
from network_analyser.records.topology import AnalysisResults, Finding, FindingLevel
from network_analyser.records.unknown import Unknown
from tests.support.analysis_records import analysed, facts, found, run_of
from tests.support.topology_records import (
    COPP,
    GUEST_SHELL,
    NTP,
    SNMP_USERS,
    SSH,
    visited,
)

A = "192.0.2.1"
B = "192.0.2.2"
SNMP = "config-snmpv3-user-crypto"
NTP_SYNC = "config-ntp-synchronised"
COPP_CHECK = "config-copp-applied"
SSH_CHECK = "config-ssh-key-size"
GUEST = "config-guest-shell"
ROLE = "config-device-role-out-of-date"


def _device(**shown: Any) -> DeviceRecord:  # noqa: ANN401 (a test's own input)
    """`sw-a`, with the show output the test gives it and nothing else."""
    return visited(A, "S1", "sw-a", **shown)


def _user(
    auth: str | Unknown = "SHA-256",
    privacy: str | Unknown = "AES256",
    name: str = "netops",
) -> SnmpUser:
    return SnmpUser(name, auth, privacy, "NA-RO")


def _ntp(synchronised: list[bool]) -> tuple[NtpAssociation, ...]:
    from ipaddress import IPv4Address  # noqa: PLC0415 (one test helper only)

    return tuple(
        NtpAssociation(IPv4Address(f"192.0.2.{index + 10}"), 2, state)
        for index, state in enumerate(synchronised)
    )


def _only(results: AnalysisResults, check_id: str) -> Finding:
    findings = found(results, check_id)
    assert len(findings) == 1, findings
    return findings[0]


# -- SNMPv3 users on MD5/DES/3DES -------------------------------------------------------------


def test_md5_or_des_snmpv3_users_are_high_and_name_no_user() -> None:
    device = _device(snmp_users=[_user("MD5", "AES256", "legacy-user"), _user("SHA-256", "DES")])

    finding = _only(analysed(device), SNMP)

    assert finding.level is FindingLevel.HIGH
    assert finding.check.name == "SNMPv3 users on MD5/DES/3DES"
    assert finding.check.type.value == "Configuration"
    assert finding.source == "config"
    assert "SNMPv3 users on MD5, DES or 3DES: 2" in finding.what_was_found
    assert "MD5 authentication on 1" in finding.what_was_found
    assert "DES privacy on 1" in finding.what_was_found
    assert "legacy-user" not in finding.what_was_found
    assert finding.what_was_found == finding.summary
    assert finding.devices == ("dev-S1",)


def test_sha256_and_aes_snmpv3_users_raise_nothing() -> None:
    device = _device(snmp_users=[_user("SHA-256", "AES256"), _user("SHA-512", "AES256")])

    assert found(analysed(device), SNMP) == []


def test_snmpv3_users_do_not_apply_when_snmpv3_has_no_users() -> None:
    device = _device(snmp_users=())

    results = analysed(device)

    assert found(results, SNMP) == []
    assert run_of(results, SNMP).skipped == ()


def test_a_protocol_the_output_does_not_report_is_could_not_decide_not_a_pass() -> None:
    device = _device(snmp_users=[_user(Unknown("authentication protocol not reported"))])

    finding = _only(analysed(device), SNMP)

    assert finding.level is FindingLevel.LOW
    assert finding.what_was_found.startswith("Could not decide:")


def test_a_refused_snmp_user_command_skips_the_check_with_a_reason() -> None:
    device = _device(snmp_users=Unknown(f"{SNMP_USERS}: denied"))

    results = analysed(device)

    assert found(results, SNMP) == []
    run = run_of(results, SNMP)
    assert run.ran is False
    assert run.reason == "skipped on every Visited Device"
    assert [(skip.device, skip.reason) for skip in run.skipped] == [
        ("dev-S1", f"{SNMP_USERS}: denied")
    ]
    assert len(found(results, ROLE)) == 1


def test_nxos_snmpv3_users_come_from_the_config_fact() -> None:
    device = visited(A, "S1", "sw-a", platform=Platform.NX_OS)

    finding = _only(
        analysed(device, facts=facts("dev-S1", **{SNMP_V3_USER_CRYPTO: ("MD5/DES",)})),
        SNMP,
    )

    assert finding.level is FindingLevel.HIGH
    assert "SNMPv3 users on MD5, DES or 3DES: 1" in finding.what_was_found


def test_nxos_with_no_snmpv3_users_does_not_apply() -> None:
    device = visited(A, "S1", "sw-a", platform=Platform.NX_OS)

    results = analysed(device, facts=facts("dev-S1", **{SNMP_V3_USER_CRYPTO: ()}))

    assert found(results, SNMP) == []
    assert run_of(results, SNMP).skipped == ()


def test_nxos_without_the_config_fact_is_skipped_never_passed() -> None:
    device = visited(A, "S1", "sw-a", platform=Platform.NX_OS)

    results = analysed(device)

    assert found(results, SNMP) == []
    run = run_of(results, SNMP)
    assert run.ran is False
    assert [skip.device for skip in run.skipped] == ["dev-S1"]


def test_nxos_with_a_malformed_config_fact_is_could_not_decide() -> None:
    device = visited(A, "S1", "sw-a", platform=Platform.NX_OS)

    finding = _only(
        analysed(device, facts=facts("dev-S1", **{SNMP_V3_USER_CRYPTO: ("MD5",)})),
        SNMP,
    )

    assert finding.level is FindingLevel.LOW
    assert finding.what_was_found.startswith("Could not decide:")


# -- NTP not synchronised ---------------------------------------------------------------------


def test_configured_ntp_with_no_selected_peer_is_medium() -> None:
    device = _device(ntp=_ntp([False, False]))

    finding = _only(analysed(device, facts=facts("dev-S1", **{NTP_CONFIGURED: True})), NTP_SYNC)

    assert finding.level is FindingLevel.MEDIUM
    assert finding.check.name == "NTP not synchronised"
    assert "2 peers, none selected" in finding.what_was_found


def test_configured_ntp_with_no_peers_at_all_is_not_synchronised() -> None:
    device = _device(ntp=())

    finding = _only(analysed(device, facts=facts("dev-S1", **{NTP_CONFIGURED: True})), NTP_SYNC)

    assert finding.level is FindingLevel.MEDIUM
    assert "no peer is selected" in finding.what_was_found


def test_a_selected_ntp_peer_raises_nothing() -> None:
    device = _device(ntp=_ntp([False, True]))

    assert found(analysed(device, facts=facts("dev-S1", **{NTP_CONFIGURED: True})), NTP_SYNC) == []


def test_ntp_sync_does_not_apply_when_ntp_is_not_configured() -> None:
    device = _device(ntp=Unknown(f"{NTP}: denied"))

    results = analysed(device, facts=facts("dev-S1", **{NTP_CONFIGURED: False}))

    assert found(results, NTP_SYNC) == []
    assert run_of(results, NTP_SYNC).skipped == ()


def test_ntp_with_an_unknown_gate_and_no_peers_is_could_not_decide() -> None:
    device = _device(ntp=())

    finding = _only(analysed(device), NTP_SYNC)

    assert finding.level is FindingLevel.LOW
    assert "NTP is not shown as configured" in finding.what_was_found


def test_a_refused_ntp_command_skips_the_check_with_a_reason() -> None:
    device = _device(ntp=Unknown(f"{NTP}: denied"))

    results = analysed(device)

    assert found(results, NTP_SYNC) == []
    run = run_of(results, NTP_SYNC)
    assert [(skip.device, skip.reason) for skip in run.skipped] == [("dev-S1", f"{NTP}: denied")]
    assert len(found(results, ROLE)) == 1


def test_an_unreadable_ntp_reply_is_could_not_decide() -> None:
    device = _device(ntp=Unknown(f"{NTP}: not understood"))

    finding = _only(analysed(device, facts=facts("dev-S1", **{NTP_CONFIGURED: True})), NTP_SYNC)

    assert finding.level is FindingLevel.LOW
    assert f"{NTP}: not understood" in finding.what_was_found


# -- CoPP not applied -------------------------------------------------------------------------


def test_no_control_plane_policy_is_medium() -> None:
    device = _device(copp=ControlPlanePolicy(()))

    finding = _only(analysed(device), COPP_CHECK)

    assert finding.level is FindingLevel.MEDIUM
    assert finding.check.name == "CoPP not applied"
    assert "No control-plane service policy is applied" in finding.what_was_found


def test_an_applied_control_plane_policy_raises_nothing() -> None:
    device = _device(copp=ControlPlanePolicy(("NA-COPP",)))

    assert found(analysed(device), COPP_CHECK) == []


def test_copp_that_was_never_collected_is_skipped_never_passed() -> None:
    device = _device()

    results = analysed(device)

    assert found(results, COPP_CHECK) == []
    run = run_of(results, COPP_CHECK)
    assert run.ran is False
    assert run.skipped[0].reason == "the command's output was not collected"


def test_a_refused_copp_command_skips_the_check_with_a_reason() -> None:
    device = _device(copp=Unknown(f"{COPP}: denied"))

    results = analysed(device)

    assert found(results, COPP_CHECK) == []
    assert run_of(results, COPP_CHECK).skipped[0].reason == f"{COPP}: denied"


# -- SSH key under 2048 bits ------------------------------------------------------------------


def test_a_1024_bit_ssh_key_is_medium_and_names_the_size_not_the_key() -> None:
    device = _device(ssh=SshSettings(enabled=True, version="2.0", key_bits=1024))

    findings = found(analysed(device), SSH_CHECK)

    (finding,) = findings
    assert finding.level is FindingLevel.MEDIUM
    assert finding.check.name == "SSH key under 2048 bits"
    assert "1024 bits" in finding.what_was_found
    assert "AAAAB3" not in finding.what_was_found


def test_a_2048_bit_or_larger_ssh_key_raises_nothing() -> None:
    for bits in (2048, 3072, 4096):
        device = _device(ssh=SshSettings(enabled=True, version="2.0", key_bits=bits))
        assert found(analysed(device), SSH_CHECK) == [], bits


def test_an_ssh_key_size_the_release_does_not_print_is_could_not_decide() -> None:
    device = _device(
        ssh=SshSettings(
            enabled=True,
            version="1.99",
            key_bits=Unknown("RSA modulus not printed by show ip ssh"),
        )
    )

    finding = _only(analysed(device), SSH_CHECK)

    assert finding.level is FindingLevel.LOW
    assert "RSA modulus not printed" in finding.what_was_found


def test_ssh_key_size_does_not_apply_when_the_ssh_server_is_disabled() -> None:
    device = _device(ssh=SshSettings(enabled=False, version=Unknown("not reported"), key_bits=1024))

    assert found(analysed(device), SSH_CHECK) == []


def test_a_refused_ssh_command_skips_the_check_with_a_reason() -> None:
    device = _device(ssh=Unknown(f"{SSH}: denied"))

    results = analysed(device)

    assert found(results, SSH_CHECK) == []
    assert run_of(results, SSH_CHECK).skipped[0].reason == f"{SSH}: denied"


# -- Guest Shell present (NX-OS) --------------------------------------------------------------


def test_a_present_guest_shell_on_nxos_is_medium() -> None:
    device = visited(A, "S1", "sw-a", platform=Platform.NX_OS, guest_shell=True)

    finding = _only(analysed(device), GUEST)

    assert finding.level is FindingLevel.MEDIUM
    assert finding.check.name == "Guest Shell present"
    assert "Guest Shell is present" in finding.what_was_found


def test_an_absent_guest_shell_raises_nothing() -> None:
    device = visited(A, "S1", "sw-a", platform=Platform.NX_OS, guest_shell=False)

    assert found(analysed(device), GUEST) == []


def test_guest_shell_does_not_apply_on_ios() -> None:
    device = _device()

    results = analysed(device)

    assert found(results, GUEST) == []
    assert run_of(results, GUEST).skipped == ()


def test_a_refused_guest_shell_command_on_nxos_skips_the_check() -> None:
    device = visited(
        A, "S1", "sw-a", platform=Platform.NX_OS, guest_shell=Unknown(f"{GUEST_SHELL}: denied")
    )

    results = analysed(device)

    assert found(results, GUEST) == []
    assert run_of(results, GUEST).skipped[0].reason == f"{GUEST_SHELL}: denied"
    assert len(found(results, ROLE)) == 1


# -- Every Check's level is the spec's fixed one ----------------------------------------------


@pytest.mark.parametrize(
    ("check_id", "accounted", "level"),
    [
        (SNMP, "_snmp", FindingLevel.HIGH),
        (NTP_SYNC, "_ntp", FindingLevel.MEDIUM),
        (COPP_CHECK, "_copp", FindingLevel.MEDIUM),
        (SSH_CHECK, "_ssh", FindingLevel.MEDIUM),
        (GUEST, "_guest", FindingLevel.MEDIUM),
    ],
)
def test_every_show_output_check_carries_its_fixed_level(
    check_id: str, accounted: str, level: FindingLevel
) -> None:
    device, config = _FIRING[accounted]()

    finding = _only(analysed(device, facts=config), check_id)

    assert finding.level is level


def _firing_snmp() -> tuple[DeviceRecord, tuple[ConfigFacts, ...]]:
    return _device(snmp_users=[_user("MD5", "DES")]), ()


def _firing_ntp() -> tuple[DeviceRecord, tuple[ConfigFacts, ...]]:
    return _device(ntp=_ntp([False])), (facts("dev-S1", **{NTP_CONFIGURED: True}),)


def _firing_copp() -> tuple[DeviceRecord, tuple[ConfigFacts, ...]]:
    return _device(copp=ControlPlanePolicy(())), ()


def _firing_ssh() -> tuple[DeviceRecord, tuple[ConfigFacts, ...]]:
    return _device(ssh=SshSettings(enabled=True, version="2.0", key_bits=1024)), ()


def _firing_guest() -> tuple[DeviceRecord, tuple[ConfigFacts, ...]]:
    return visited(A, "S1", "sw-a", platform=Platform.NX_OS, guest_shell=True), ()


_FIRING: dict[str, Callable[[], tuple[DeviceRecord, tuple[ConfigFacts, ...]]]] = {
    "_snmp": _firing_snmp,
    "_ntp": _firing_ntp,
    "_copp": _firing_copp,
    "_ssh": _firing_ssh,
    "_guest": _firing_guest,
}


# -- One skip per device, even with several refused commands ----------------------------------


def test_two_devices_one_refused_and_one_read_keep_the_check_ran() -> None:
    refused = _device(copp=Unknown(f"{COPP}: denied"))
    read = visited(B, "S2", "sw-b", copp=ControlPlanePolicy(("NA-COPP",)))

    results = analysed(refused, read)

    run = run_of(results, COPP_CHECK)
    assert run.ran is True
    assert [skip.device for skip in run.skipped] == ["dev-S1"]
    assert run.reason is None


def test_no_visited_device_still_runs_every_check() -> None:
    results = analysed()

    assert all(run.ran for run in results.checks)
    assert all(run.skipped == () for run in results.checks)


# -- No secret or hash in any Finding's text --------------------------------------------------


def test_no_finding_echoes_a_planted_secret_from_the_show_output() -> None:
    canary = "CANARY-pw-102a"
    device = _device(
        snmp_users=[SnmpUser(canary, "MD5", "DES", canary)],
        copp=ControlPlanePolicy((canary,)),
        ntp=_ntp([False]),
        ssh=SshSettings(enabled=True, version="2.0", key_bits=1024),
        guest_shell=True,
    )

    results = analysed(device, facts=facts("dev-S1", **{NTP_CONFIGURED: True}))

    assert canary not in " ".join(
        f"{finding.what_was_found} {finding.what_to_do} {finding.summary}"
        for finding in results.findings
    )
