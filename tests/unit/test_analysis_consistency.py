"""The consistency Checks, at Seam 1: synthetic device records in, plain Findings out (#99).

Driven through `analysis.analyse` only. A stack or StackWise Virtual pair, a vPC pair, a
Catalyst 9000 in bundle mode and an IOS-XE Standard-Support Train are all facts the Run
already collected, so these Checks need no new command and no Cisco lookup.

The Standard- and Extended-Support Train list is the one researched on #76 from Cisco's
Catalyst 9200-9600 release guidance (C9K-REL, as of September 2026): Extended Support is
17.12, 17.15 and 17.18; Standard Support is 17.13, 17.14, 17.16 and 17.17. A Train the
research does not classify is never guessed at.
"""

from dataclasses import replace

import pytest

from network_analyser import analysis, topology
from network_analyser.records.analysis import AnalysisInput, CiscoAnswers
from network_analyser.records.collected import Reading, StackMember
from network_analyser.records.device import DeviceRecord
from network_analyser.records.platform import Platform
from network_analyser.records.topology import (
    AnalysisResults,
    CheckRun,
    CheckType,
    Finding,
    FindingLevel,
)
from network_analyser.records.unknown import Unknown
from tests.support.topology_records import visited, vpc

A = "192.0.2.1"
B = "192.0.2.2"
C9K = "C9300-48P"
C8300 = "C8300-1N1S-4T2X"
SHOW_VERSION = "show version"


def _device(  # noqa: PLR0913 (a device's facts, by name)
    address: str,
    serial: str,
    hostname: str,
    *,
    model: str | Unknown = C9K,
    release: str | Unknown = "17.12.1",
    platform: Platform = Platform.IOS_XE,
    stack: tuple[StackMember, ...] | None = None,
    vpc_domain: tuple[int, str, str] | None = None,
) -> DeviceRecord:
    """Return a Visited Device, with a stack or a vPC domain when one is given."""
    state = (
        None if vpc_domain is None else vpc(vpc_domain[0], "Po10", (vpc_domain[1], vpc_domain[2]))
    )
    record = visited(address, serial, hostname, platform=platform, vpc_state=state)
    version = record.version
    assert version is not None
    record = replace(record, version=replace(version, model=model, software_version=release))
    if stack is not None:
        collected = record.collected
        assert collected is not None
        record = replace(
            record,
            collected=replace(collected, stack_members=Reading((SHOW_VERSION,), stack)),
        )
    return record


def _results(*records: DeviceRecord, answers: CiscoAnswers | None = None) -> AnalysisResults:
    return analysis.analyse(
        AnalysisInput(topology=topology.build(records), answers=answers or CiscoAnswers())
    )


def _findings(results: AnalysisResults, check_id: str) -> list[Finding]:
    return [finding for finding in results.findings if finding.check.id == check_id]


def _run(results: AnalysisResults, check_id: str) -> CheckRun:
    return next(run for run in results.checks if run.check.id == check_id)


# -- Stack and StackWise Virtual members ------------------------------------------------------


def test_stack_members_on_different_releases_raise_one_medium_finding() -> None:
    members = (
        StackMember(1, "TEST0000A01", C9K, "17.9.4a", "INSTALL"),
        StackMember(2, "TEST0000A02", C9K, "17.12.1", "INSTALL"),
    )

    (finding,) = _findings(
        _results(_device(A, "S1", "sw-a", stack=members)), "consistency-stack-mismatch"
    )

    assert finding.level is FindingLevel.MEDIUM
    assert finding.check.name == "Stack or StackWise Virtual members on different releases or modes"
    assert finding.check.type is CheckType.CONSISTENCY
    assert finding.check.soft is False
    assert finding.devices == ("dev-S1",)
    assert "member 1" in finding.what_was_found
    assert "member 2" in finding.what_was_found
    assert "17.9.4a" in finding.what_was_found
    assert "17.12.1" in finding.what_was_found
    assert finding.what_to_do
    assert finding.source == "device reports"
    assert finding.kind is None
    assert finding.items == ()
    assert finding.what_was_found == finding.summary


def test_stack_members_on_different_modes_raise_one_medium_finding() -> None:
    members = (
        StackMember(1, "TEST0000A01", C9K, "17.12.1", "INSTALL"),
        StackMember(2, "TEST0000A02", C9K, "17.12.1", "BUNDLE"),
    )

    (finding,) = _findings(
        _results(_device(A, "S1", "sw-a", stack=members)), "consistency-stack-mismatch"
    )

    assert finding.level is FindingLevel.MEDIUM
    assert "INSTALL" in finding.what_was_found
    assert "BUNDLE" in finding.what_was_found


def test_stack_members_on_one_release_and_mode_raise_nothing() -> None:
    members = (
        StackMember(1, "TEST0000A01", C9K, "17.12.1", "INSTALL"),
        StackMember(2, "TEST0000A02", C9K, "17.12.1", "INSTALL"),
    )

    results = _results(_device(A, "S1", "sw-a", stack=members))

    assert _findings(results, "consistency-stack-mismatch") == []


def test_releases_that_differ_only_in_leading_zeros_are_one_release() -> None:
    members = (
        StackMember(1, "TEST0000A01", C9K, "17.09.04a", "INSTALL"),
        StackMember(2, "TEST0000A02", C9K, "17.9.4a", "INSTALL"),
    )

    results = _results(_device(A, "S1", "sw-a", stack=members))

    assert _findings(results, "consistency-stack-mismatch") == []


def test_an_unknown_stack_release_or_mode_is_never_guessed() -> None:
    members = (
        StackMember(1, "TEST0000A01", C9K, Unknown("not in show version"), "INSTALL"),
        StackMember(2, "TEST0000A02", C9K, "17.12.1", Unknown("not in show version")),
    )

    results = _results(_device(A, "S1", "sw-a", stack=members))

    assert _findings(results, "consistency-stack-mismatch") == []


def test_a_lone_switch_is_not_a_stack_mismatch() -> None:
    results = _results(
        _device(A, "S1", "sw-a", stack=(StackMember(1, "TEST0000A01", C9K, "17.9.4a"),))
    )

    assert _findings(results, "consistency-stack-mismatch") == []


def test_a_device_with_an_unread_member_table_raises_nothing() -> None:
    results = _results(_device(A, "S1", "sw-a"))

    assert _findings(results, "consistency-stack-mismatch") == []


def test_two_stacked_devices_each_get_their_own_finding() -> None:
    first = (
        StackMember(1, "TEST0000A01", C9K, "17.9.4a", "INSTALL"),
        StackMember(2, "TEST0000A02", C9K, "17.12.1", "INSTALL"),
    )
    second = (
        StackMember(1, "TEST0000B01", C9K, "17.12.1", "INSTALL"),
        StackMember(2, "TEST0000B02", C9K, "17.12.2", "INSTALL"),
    )

    findings = _findings(
        _results(_device(A, "S1", "sw-a", stack=first), _device(B, "S2", "sw-b", stack=second)),
        "consistency-stack-mismatch",
    )

    assert sorted(finding.devices for finding in findings) == [("dev-S1",), ("dev-S2",)]
    assert len({finding.id for finding in findings}) == 2


# -- vPC peers --------------------------------------------------------------------------------


def test_vpc_peers_on_different_releases_raise_one_medium_finding() -> None:
    results = _results(
        _device(
            A,
            "N1",
            "nx-a",
            model="N9K-C93180YC-FX",
            release="9.3(10)",
            platform=Platform.NX_OS,
            vpc_domain=(10, A, B),
        ),
        _device(
            B,
            "N2",
            "nx-b",
            model="N9K-C93180YC-FX",
            release="10.2(5)",
            platform=Platform.NX_OS,
            vpc_domain=(10, B, A),
        ),
    )

    (finding,) = _findings(results, "consistency-vpc-mismatch")

    assert finding.level is FindingLevel.MEDIUM
    assert finding.check.type is CheckType.CONSISTENCY
    assert finding.devices == ("dev-N1", "dev-N2")
    assert "nx-a" in finding.what_was_found
    assert "nx-b" in finding.what_was_found
    assert "9.3(10)" in finding.what_was_found
    assert "10.2(5)" in finding.what_was_found
    assert finding.what_to_do
    assert finding.source == "device reports"


def test_vpc_peers_on_the_same_release_raise_nothing() -> None:
    results = _results(
        _device(
            A,
            "N1",
            "nx-a",
            model="N9K-C93180YC-FX",
            release="10.2(5)",
            platform=Platform.NX_OS,
            vpc_domain=(10, A, B),
        ),
        _device(
            B,
            "N2",
            "nx-b",
            model="N9K-C93180YC-FX",
            release="10.2(5)",
            platform=Platform.NX_OS,
            vpc_domain=(10, B, A),
        ),
    )

    assert _findings(results, "consistency-vpc-mismatch") == []


def test_vpc_peers_in_different_domains_are_not_a_pair() -> None:
    results = _results(
        _device(
            A,
            "N1",
            "nx-a",
            model="N9K-C93180YC-FX",
            release="9.3(10)",
            platform=Platform.NX_OS,
            vpc_domain=(10, A, B),
        ),
        _device(
            B,
            "N2",
            "nx-b",
            model="N9K-C93180YC-FX",
            release="10.2(5)",
            platform=Platform.NX_OS,
            vpc_domain=(20, B, A),
        ),
    )

    assert _findings(results, "consistency-vpc-mismatch") == []


def test_a_vpc_peer_with_an_unknown_release_is_never_guessed() -> None:
    results = _results(
        _device(
            A,
            "N1",
            "nx-a",
            model="N9K-C93180YC-FX",
            release=Unknown("show version not read"),
            platform=Platform.NX_OS,
            vpc_domain=(10, A, B),
        ),
        _device(
            B,
            "N2",
            "nx-b",
            model="N9K-C93180YC-FX",
            release="10.2(5)",
            platform=Platform.NX_OS,
            vpc_domain=(10, B, A),
        ),
    )

    assert _findings(results, "consistency-vpc-mismatch") == []


def test_a_device_without_vpc_raises_nothing() -> None:
    results = _results(
        _device(A, "N1", "nx-a", model="N9K-C93180YC-FX", platform=Platform.NX_OS),
        _device(B, "N2", "nx-b", model="N9K-C93180YC-FX", platform=Platform.NX_OS),
    )

    assert _findings(results, "consistency-vpc-mismatch") == []


# -- Catalyst 9000 in bundle mode -------------------------------------------------------------


def test_a_catalyst_9000_in_bundle_mode_raises_low() -> None:
    members = (StackMember(1, "TEST0000A01", C9K, "17.12.1", "BUNDLE"),)

    (finding,) = _findings(
        _results(_device(A, "S1", "sw-a", stack=members)), "consistency-bundle-mode"
    )

    assert finding.level is FindingLevel.LOW
    assert finding.check.type is CheckType.CONSISTENCY
    assert finding.devices == ("dev-S1",)
    assert C9K in finding.what_was_found
    assert "bundle" in finding.what_was_found.lower()
    assert finding.what_to_do
    assert finding.source == "device reports"


def test_a_catalyst_9000_in_install_mode_raises_nothing() -> None:
    members = (StackMember(1, "TEST0000A01", C9K, "17.12.1", "INSTALL"),)

    results = _results(_device(A, "S1", "sw-a", stack=members))

    assert _findings(results, "consistency-bundle-mode") == []


def test_bundle_mode_on_another_model_is_not_this_check() -> None:
    members = (StackMember(1, "TEST0000B01", C8300, "17.12.1", "BUNDLE"),)

    results = _results(_device(A, "S1", "sw-a", model=C8300, stack=members))

    assert _findings(results, "consistency-bundle-mode") == []


def test_a_catalyst_9000_whose_mode_was_not_read_raises_nothing() -> None:
    members = (StackMember(1, "TEST0000A01", C9K, "17.12.1", Unknown("not in show version")),)

    results = _results(_device(A, "S1", "sw-a", stack=members))

    assert _findings(results, "consistency-bundle-mode") == []


# -- Standard-Support Train -------------------------------------------------------------------


@pytest.mark.parametrize("release", ["17.13.1", "17.14.2", "17.16.1", "17.17.3"])
def test_ios_xe_on_a_standard_support_train_raises_low(release: str) -> None:
    (finding,) = _findings(
        _results(_device(A, "S1", "sw-a", release=release)),
        "consistency-standard-support-train",
    )

    assert finding.level is FindingLevel.LOW
    assert finding.check.type is CheckType.CONSISTENCY
    assert finding.devices == ("dev-S1",)
    assert "sw-a" in finding.what_was_found
    assert release in finding.what_was_found
    assert "Standard-Support" in finding.what_was_found
    assert "Extended-Support" in finding.what_to_do
    assert finding.source == "device reports"


@pytest.mark.parametrize("release", ["17.12.4", "17.15.1", "17.18.4"])
def test_ios_xe_on_an_extended_support_train_raises_nothing(release: str) -> None:
    results = _results(_device(A, "S1", "sw-a", release=release))

    assert _findings(results, "consistency-standard-support-train") == []


def test_an_ios_xe_device_that_is_not_a_catalyst_9000_is_still_this_check() -> None:
    (finding,) = _findings(
        _results(_device(A, "S1", "sw-a", model=C8300, release="17.13.1")),
        "consistency-standard-support-train",
    )

    assert finding.level is FindingLevel.LOW


def test_nx_os_is_not_this_check() -> None:
    results = _results(
        _device(
            A,
            "N1",
            "nx-a",
            model="N9K-C93180YC-FX",
            release="10.2(5)",
            platform=Platform.NX_OS,
        )
    )

    assert _findings(results, "consistency-standard-support-train") == []
    assert _run(results, "consistency-standard-support-train").ran is True


def test_a_classic_ios_train_is_outside_this_check() -> None:
    results = _results(_device(A, "S1", "sw-a", model="WS-C2960X-48FPD-L", release="15.2(7)E4"))

    assert _findings(results, "consistency-standard-support-train") == []
    assert _run(results, "consistency-standard-support-train").ran is True


def test_a_train_the_research_does_not_classify_skips_the_check_instead_of_guessing() -> None:
    results = _results(_device(A, "S1", "sw-a", release="17.9.4a"))

    assert _findings(results, "consistency-standard-support-train") == []
    run = _run(results, "consistency-standard-support-train")
    assert run.ran is False
    assert run.reason is not None
    assert "17.9" in run.reason


def test_a_mixed_estate_still_flags_the_classified_device() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.9.4a"),
        _device(B, "S2", "sw-b", release="17.13.1"),
    )

    (finding,) = _findings(results, "consistency-standard-support-train")

    assert finding.devices == ("dev-S2",)
    assert _run(results, "consistency-standard-support-train").ran is True


def test_an_unknown_release_is_never_guessed() -> None:
    results = _results(_device(A, "S1", "sw-a", release=Unknown("show version not read")))

    assert _findings(results, "consistency-standard-support-train") == []
    assert _run(results, "consistency-standard-support-train").ran is True


def test_each_standard_support_device_gets_its_own_finding() -> None:
    findings = _findings(
        _results(
            _device(A, "S1", "sw-a", release="17.13.1"),
            _device(B, "S2", "sw-b", release="17.16.2"),
        ),
        "consistency-standard-support-train",
    )

    assert sorted(finding.devices for finding in findings) == [("dev-S1",), ("dev-S2",)]


# -- Story 10: no Cisco lookup is needed ------------------------------------------------------


def test_consistency_findings_are_raised_when_cisco_lookups_are_off_or_unavailable() -> None:
    members = (
        StackMember(1, "TEST0000A01", C9K, "17.9.4a", "INSTALL"),
        StackMember(2, "TEST0000A02", C9K, "17.12.1", "INSTALL"),
    )
    results = _results(
        _device(A, "S1", "sw-a", release="17.13.1", stack=members),
        answers=CiscoAnswers.unavailable("Cisco openVuln could not be reached"),
    )

    assert _findings(results, "consistency-stack-mismatch") != []
    assert _findings(results, "consistency-standard-support-train") != []
