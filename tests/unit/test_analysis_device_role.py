"""The one Medium "Device Role is out of date" Finding per device, on both Platforms (#102).

Driven through `analysis.analyse` with the collected records #97 and #98 produce: a refused
command is `Unknown("<command>: denied")`, which `topology.build` lists in `skipped`. Analysis
must raise exactly one Finding per device however many commands were refused, name the Checks
that could not run and point at `role-snippet`, and record each dependent Check as skipped for
that device, never passed (story 80).
"""

from typing import Any

import pytest

from network_analyser.records.collected import ControlPlanePolicy, SshSettings
from network_analyser.records.device import DeviceRecord
from network_analyser.records.platform import Platform
from network_analyser.records.topology import FindingLevel
from network_analyser.records.unknown import Unknown
from tests.support.analysis_records import analysed, found, run_of
from tests.support.topology_records import (
    COPP,
    GUEST_SHELL,
    INVENTORY,
    NTP,
    SNMP_USERS,
    SSH,
    visited,
)

A = "192.0.2.1"
B = "192.0.2.2"
ROLE = "config-device-role-out-of-date"
POINTER = "Re-apply the Device Role printed by role-snippet."


def _denied(command: str) -> Unknown:
    return Unknown(f"{command}: denied")


def _ios(**refused: Any) -> DeviceRecord:  # noqa: ANN401 (a test's own input)
    return visited(A, "S1", "sw-a", **refused)


def _nxos(**refused: Any) -> DeviceRecord:  # noqa: ANN401 (a test's own input)
    return visited(A, "S1", "sw-a", platform=Platform.NX_OS, **refused)


def test_ios_two_refused_commands_are_one_medium_finding_naming_both_checks() -> None:
    results = analysed(_ios(ntp=_denied(NTP), copp=_denied(COPP)))

    (finding,) = found(results, ROLE)

    assert finding.level is FindingLevel.MEDIUM
    assert finding.check.name == "Device Role out of date"
    assert finding.check.type.value == "Configuration"
    assert finding.source == "device reports"
    assert finding.devices == ("dev-S1",)
    assert finding.what_was_found == (
        "Device Role is out of date: 2 Checks could not run "
        "(NTP not synchronised, CoPP not applied). " + POINTER
    )
    assert finding.summary == finding.what_was_found
    assert finding.what_to_do == POINTER


def test_one_refused_command_names_one_check_in_the_singular() -> None:
    results = analysed(_ios(ssh=_denied(SSH)))

    (finding,) = found(results, ROLE)

    assert finding.what_was_found == (
        f"Device Role is out of date: 1 Check could not run (SSH key under 2048 bits). {POINTER}"
    )


def test_nxos_all_five_refused_commands_are_still_one_finding() -> None:
    results = analysed(
        _nxos(
            inventory=_denied(INVENTORY),
            ntp=_denied(NTP),
            copp=_denied(COPP),
            ssh=_denied(SSH),
            guest_shell=_denied(GUEST_SHELL),
        )
    )

    (finding,) = found(results, ROLE)

    assert finding.level is FindingLevel.MEDIUM
    assert finding.what_was_found == (
        "Device Role is out of date: 5 Checks could not run "
        "(Hardware EoX, NTP not synchronised, CoPP not applied, SSH key under 2048 bits, "
        "Guest Shell present). " + POINTER
    )


def test_the_same_device_gets_one_role_finding_at_a_stable_id() -> None:
    first = analysed(_ios(ntp=_denied(NTP), copp=_denied(COPP)))
    again = analysed(_ios(copp=_denied(COPP), ntp=_denied(NTP)))

    (one,) = found(first, ROLE)
    (two,) = found(again, ROLE)

    assert one.id == two.id
    assert one.id.startswith("finding-")


def test_dependent_checks_are_skipped_for_the_device_with_a_reason() -> None:
    results = analysed(_ios(ntp=_denied(NTP), copp=_denied(COPP)))

    ntp = run_of(results, "config-ntp-synchronised")
    copp = run_of(results, "config-copp-applied")
    assert ntp.ran is False
    assert ntp.reason == "skipped on every Visited Device"
    assert [(skip.device, skip.reason) for skip in ntp.skipped] == [("dev-S1", f"{NTP}: denied")]
    assert [(skip.device, skip.reason) for skip in copp.skipped] == [("dev-S1", f"{COPP}: denied")]
    assert run_of(results, ROLE).ran is True


def test_a_denied_v1_command_no_check_reads_is_not_a_device_role_problem() -> None:
    results = analysed(_ios(fhrp=_denied("show standby brief")))

    assert found(results, ROLE) == []


def test_a_reply_that_is_not_understood_is_not_a_device_role_problem() -> None:
    results = analysed(
        _ios(
            copp=Unknown(f"{COPP}: not understood"),
            ntp=(),
            ssh=SshSettings(enabled=True, version="2.0", key_bits=2048),
        )
    )

    assert found(results, ROLE) == []
    (decided,) = found(results, "config-copp-applied")
    assert decided.level is FindingLevel.LOW
    assert decided.what_was_found.startswith("Could not decide:")


def test_each_device_gets_its_own_finding_and_only_its_own_skips() -> None:
    refused = _ios(ntp=_denied(NTP))
    sound = visited(
        B,
        "S2",
        "sw-b",
        ntp=(),
        copp=ControlPlanePolicy(("NA-COPP",)),
        ssh=SshSettings(enabled=True, version="2.0", key_bits=2048),
    )

    results = analysed(refused, sound)

    findings = found(results, ROLE)
    assert [finding.devices for finding in findings] == [("dev-S1",)]
    run = run_of(results, "config-ntp-synchronised")
    assert run.ran is True
    assert [skip.device for skip in run.skipped] == ["dev-S1"]


def test_an_ios_and_an_nxos_device_each_raise_one_finding() -> None:
    ios = _ios(ntp=_denied(NTP))
    nxos = visited(
        B,
        "S2",
        "sw-b",
        platform=Platform.NX_OS,
        guest_shell=_denied(GUEST_SHELL),
    )

    results = analysed(ios, nxos)

    assert [finding.devices for finding in found(results, ROLE)] == [("dev-S1",), ("dev-S2",)]


def test_a_device_with_every_new_command_refused_still_has_no_check_passing() -> None:
    results = analysed(
        _ios(
            snmp_users=_denied(SNMP_USERS),
            ntp=_denied(NTP),
            copp=_denied(COPP),
            ssh=_denied(SSH),
        )
    )

    for check_id in (
        "config-snmpv3-user-crypto",
        "config-ntp-synchronised",
        "config-copp-applied",
        "config-ssh-key-size",
    ):
        run = run_of(results, check_id)
        assert run.skipped, check_id
        assert run.ran is False, check_id


@pytest.mark.parametrize("command", ["show standby brief", "show vlan brief"])
def test_a_denied_command_that_no_show_output_check_reads_is_ignored(command: str) -> None:
    device = visited(A, "S1", "sw-a", fhrp=Unknown(f"{command}: denied"))

    assert found(analysed(device), ROLE) == []
