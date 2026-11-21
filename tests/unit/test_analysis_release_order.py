"""Release order and Trains at Seam 1: synthetic Cisco answers in, plain advice out (#123).

Driven through `analysis.analyse` only. A release order is what the operator sees when the
Upgrade Target and an Advisory Finding's "first fixed in Train" line pick a release, and a
Train is what those lines name; a consistency Finding lists releases in the same order.
Every release string is public Cisco numbering and every answer is hand-written synthetic data.
"""

from dataclasses import replace

import pytest

from network_analyser import analysis, topology
from network_analyser.records.analysis import (
    AdvisoryAnswer,
    AnalysisInput,
    CiscoAnswers,
    FixedRelease,
    OsType,
    ReleaseAdvisories,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.platform import Platform
from network_analyser.records.topology import (
    AdvisoryDetail,
    AnalysisResults,
    CiscoDetailKind,
    Finding,
    FindingLevel,
)
from tests.support.topology_records import visited

A = "192.0.2.1"
B = "192.0.2.2"
C = "192.0.2.3"
MODEL = "C9300-48P"
CLASSIC_MODEL = "WS-C2960X-48FPD-L"
NEXUS_MODEL = "N9K-C93180YC-FX"
ADVISORY = "cisco-sa-order-0001"


def _device(  # noqa: PLR0913 (every device field the Check reads, by name)
    address: str,
    serial: str,
    hostname: str,
    *,
    platform: Platform = Platform.IOS_XE,
    model: str = MODEL,
    release: str = "17.12.1",
) -> DeviceRecord:
    record = visited(address, serial, hostname, platform=platform)
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, model=model, software_version=release))


def _advisory(*releases: str, train: str) -> AdvisoryAnswer:
    return AdvisoryAnswer(
        detail=AdvisoryDetail(
            kind=CiscoDetailKind.ADVISORY,
            id=ADVISORY,
            title="Example Advisory",
            sir=FindingLevel.HIGH,
            cvss="8.1",
            cves=("CVE-2026-0001",),
            published="2026-11-01",
            updated="2026-11-02",
            first_fixed=None,
        ),
        first_fixed=tuple(FixedRelease(train, release) for release in releases),
    )


def _answer(
    os_type: OsType,
    release: str,
    advisory: AdvisoryAnswer,
    *,
    hardware_family: str | None = None,
) -> ReleaseAdvisories:
    return ReleaseAdvisories(
        os_type=os_type,
        release=release,
        advisories=(advisory,),
        hardware_family=hardware_family,
    )


def _results(*records: DeviceRecord, answers: tuple[ReleaseAdvisories, ...]) -> AnalysisResults:
    return analysis.analyse(
        AnalysisInput(
            topology=topology.build(records),
            answers=CiscoAnswers(advisories=answers),
        )
    )


def _advisory_finding(results: AnalysisResults) -> Finding:
    (finding,) = [
        finding for finding in results.findings if finding.check.id == f"advisory-{ADVISORY}"
    ]
    return finding


def _findings(results: AnalysisResults, check_id: str) -> list[Finding]:
    return [finding for finding in results.findings if finding.check.id == check_id]


def _dotted_train(release: str) -> str:
    return ".".join(release.split(".")[:2])


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("17.12.7", "17.12.7a"),
        ("17.12.7a", "17.12.7b"),
        ("17.12.7b", "17.12.8"),
        ("26.1.2", "26.1.2s1"),
        ("26.1.2s1", "26.1.3"),
    ],
)
def test_ios_xe_releases_order_a_suffix_after_its_plain_release(lower: str, higher: str) -> None:
    train = _dotted_train(lower)
    running = f"{train}.1"
    results = _results(
        _device(A, "S1", "sw-a", release=running),
        answers=(
            _answer(
                OsType.IOS_XE,
                running,
                _advisory(lower, higher, train=train),
            ),
        ),
    )

    (advice,) = results.advice
    finding = _advisory_finding(results)
    assert advice.upgrade_target == higher
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.first_fixed == higher
    assert f"First fixed in Train {train}: {higher}." in finding.what_was_found


@pytest.mark.parametrize(
    ("lower", "higher"),
    [("10.6(3)", "10.6(3s)"), ("10.6(3s)", "10.6(4)")],
)
def test_nx_os_releases_order_a_lettered_build_after_its_plain_release(
    lower: str, higher: str
) -> None:
    running = "10.6(2)"
    results = _results(
        _device(
            A,
            "N1",
            "nx-a",
            platform=Platform.NX_OS,
            model=NEXUS_MODEL,
            release=running,
        ),
        answers=(
            _answer(
                OsType.NX_OS,
                running,
                _advisory(lower, higher, train="10.6"),
                hardware_family="NEXUS9000",
            ),
        ),
    )

    finding = _advisory_finding(results)
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.first_fixed == higher
    assert f"First fixed in Train 10.6: {higher}." in finding.what_was_found


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("15.2(7)E4", "15.2(7)E5"),
        ("15.2(7)E5", "15.2(7)E10"),
        ("12.2(55)SE7", "12.2(55)SE10"),
    ],
)
def test_classic_ios_order_is_unchanged(lower: str, higher: str) -> None:
    train = "15.2E" if lower.startswith("15.2") else "12.2SE"
    running = "15.2(7)E4" if train == "15.2E" else "12.2(55)SE7"
    results = _results(
        _device(A, "S1", "sw-a", model=CLASSIC_MODEL, release=running),
        answers=(
            _answer(
                OsType.IOS,
                running,
                _advisory(lower, higher, train=train),
            ),
        ),
    )

    (advice,) = results.advice
    finding = _advisory_finding(results)
    assert advice.upgrade_target == higher
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.first_fixed == higher


def test_an_ios_xe_device_fixed_in_17_12_7a_and_17_12_8_targets_17_12_8() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.12.4"),
        answers=(
            _answer(
                OsType.IOS_XE,
                "17.12.4",
                _advisory("17.12.7a", "17.12.8", train="17.12"),
            ),
        ),
    )

    (advice,) = results.advice
    assert advice.upgrade_target == "17.12.8"
    finding = _advisory_finding(results)
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.first_fixed == "17.12.8"


@pytest.mark.parametrize(
    "case",
    [
        (Platform.IOS_XE, MODEL, "17.12.4", OsType.IOS_XE, "17.12", "17.12.5", "17.12"),
        (
            Platform.NX_OS,
            NEXUS_MODEL,
            "10.4(3)",
            OsType.NX_OS,
            "10.4",
            "10.4(8)",
            "10.4",
        ),
        (
            Platform.IOS_XE,
            CLASSIC_MODEL,
            "15.2(7)E4",
            OsType.IOS,
            "15.2E",
            "15.2(7)E9",
            "15.2E",
        ),
        (
            Platform.NX_OS,
            NEXUS_MODEL,
            "7.0(3)I7(9)",
            OsType.NX_OS,
            "7.0(3)I7",
            "7.0(3)I7(10)",
            "7.0(3)I7",
        ),
    ],
)
def test_each_release_gets_the_train_cisco_names(
    case: tuple[Platform, str, str, OsType, str, str, str],
) -> None:
    platform, model, release, os_type, fix_train, fix, train = case
    results = _results(
        _device(A, "N1", "nx-a", platform=platform, model=model, release=release),
        answers=(
            _answer(
                os_type,
                release,
                _advisory(fix, train=fix_train),
                hardware_family="NEXUS9000" if platform is Platform.NX_OS else None,
            ),
        ),
    )

    finding = _advisory_finding(results)
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.first_fixed == fix
    assert f"First fixed in Train {train}: {fix}." in finding.what_was_found


def test_a_consistency_result_lists_releases_in_release_order() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.9.10"),
        _device(B, "S2", "sw-b", release="17.9.5"),
        _device(C, "S3", "sw-c", release="17.9.4a"),
        answers=(),
    )

    (finding,) = _findings(results, "consistency-model-drift")

    assert "17.9.4a on sw-c; 17.9.5 on sw-b; 17.9.10 on sw-a" in finding.what_was_found
