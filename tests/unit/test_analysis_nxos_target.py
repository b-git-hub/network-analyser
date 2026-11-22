"""The NX-OS Upgrade Target at Seam 1: the reply's per-series first fixes (#126).

Driven through `analysis.analyse` only. Synthetic Cisco answers go in; the operator's advice
comes out: each Advisory's fixes taken from the `platforms[]` entry for the device's Nexus
series, the per-Advisory rule from #124 applied to them, and `not available` whenever the
series cannot be pinned to exactly one entry. Every release string is public Cisco numbering,
every platform name is Cisco's own, and every answer is hand-written synthetic data.
"""

from dataclasses import replace

import pytest

from network_analyser import analysis, topology
from network_analyser.records.analysis import (
    AdvisoryAnswer,
    AdvisoryPlatform,
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
from network_analyser.records.unknown import Unknown
from tests.support.analysis_records import collected_of
from tests.support.topology_records import chassis_inventory, visited

A = "192.0.2.1"
MODEL = "C93180YC-FX"
CHASSIS = "N9K-C93180YC-FX"
RUNNING = "10.4(3)"
TRAIN = "10.4"
SERIES = "NEXUS9000"
NEXUS3000 = "Cisco Nexus 3000 Series Switches"
NEXUS5000 = "Cisco Nexus 5000 Series Switches"
NEXUS7000 = "Cisco Nexus 7000 Series Switches"
NEXUS9000 = "Cisco Nexus 9000 Series Switches"
FIRST = "cisco-sa-nxos-0001"
SECOND = "cisco-sa-nxos-0002"
THIRD = "cisco-sa-nxos-0003"


def _device(*, chassis: str | Unknown = CHASSIS, release: str = RUNNING) -> DeviceRecord:
    inventory = chassis_inventory(chassis) if isinstance(chassis, str) else chassis
    record = visited(A, "S1", "sw-a", platform=Platform.NX_OS, inventory=inventory)
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, model=MODEL, software_version=release))


def _fix(release: str, train: str = TRAIN) -> FixedRelease:
    return FixedRelease(train, release)


def _platform(name: str | None, *fixes: FixedRelease) -> AdvisoryPlatform:
    return AdvisoryPlatform(name, fixes)


def _advisory(
    ident: str, *platforms: AdvisoryPlatform, sir: FindingLevel = FindingLevel.HIGH
) -> AdvisoryAnswer:
    return AdvisoryAnswer(
        detail=AdvisoryDetail(
            kind=CiscoDetailKind.ADVISORY,
            id=ident,
            title="Example Advisory",
            sir=sir,
            cvss="8.1",
            cves=("CVE-2026-0001",),
            published="2026-11-01",
            updated="2026-11-02",
            first_fixed=None,
        ),
        platforms=platforms,
    )


def _results(
    *advisories: AdvisoryAnswer,
    chassis: str | Unknown = CHASSIS,
    release: str = RUNNING,
    family: str | None = SERIES,
) -> AnalysisResults:
    record = _device(chassis=chassis, release=release)
    return analysis.analyse(
        AnalysisInput(
            topology=topology.build((record,)),
            collected=collected_of(record),
            answers=CiscoAnswers(
                advisories=(
                    ReleaseAdvisories(
                        OsType.NX_OS,
                        release,
                        advisories,
                        hardware_family=family,
                    ),
                )
            ),
        )
    )


def _finding(results: AnalysisResults, ident: str) -> Finding:
    (finding,) = [
        finding for finding in results.findings if finding.check.id == f"advisory-{ident}"
    ]
    return finding


def _first_fixed(finding: Finding) -> str | None:
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    return finding.cisco_detail.first_fixed


def test_the_nexus_series_entry_gives_the_device_only_its_own_fixes() -> None:
    results = _results(
        _advisory(
            FIRST,
            _platform(NEXUS9000, _fix("10.4(5)")),
            _platform(NEXUS3000, _fix("10.4(8)")),
            _platform(None, _fix("10.4(9)")),
        )
    )

    (advice,) = results.advice
    assert (advice.upgrade_target, advice.not_cleared) == ("10.4(5)", 0)
    finding = _finding(results, FIRST)
    assert _first_fixed(finding) == "10.4(5)"
    assert "First fixed in Train 10.4: 10.4(5)." in finding.what_was_found
    assert "10.4(8)" not in finding.what_was_found
    assert "10.4(9)" not in finding.what_was_found


def test_an_unnamed_platform_entry_is_ignored() -> None:
    results = _results(
        _advisory(
            FIRST,
            _platform(None, _fix("10.4(9)")),
            _platform(NEXUS9000, _fix("10.4(5)")),
        )
    )

    (advice,) = results.advice
    assert advice.upgrade_target == "10.4(5)"
    assert _first_fixed(_finding(results, FIRST)) == "10.4(5)"


@pytest.mark.parametrize(
    ("chassis", "family", "series"),
    [
        ("N3K-C3064PQ-10GE", "NEXUS3000", NEXUS3000),
        ("N5K-C5548UP", "NEXUS5000", NEXUS5000),
        ("N7K-C7010", "NEXUS7000", NEXUS7000),
        ("N9K-C93180YC-FX", "NEXUS9000", NEXUS9000),
    ],
)
def test_each_nexus_series_matches_ciscos_platform_name(
    chassis: str, family: str, series: str
) -> None:
    results = _results(
        _advisory(FIRST, _platform(series, _fix("10.4(5)"))), chassis=chassis, family=family
    )

    (advice,) = results.advice
    assert advice.upgrade_target == "10.4(5)"


def test_no_series_worked_out_from_the_chassis_pid_is_not_available() -> None:
    results = _results(
        _advisory(FIRST, _platform(NEXUS9000, _fix("10.4(5)"))),
        chassis=Unknown("show inventory | json: denied"),
        family=None,
    )

    (advice,) = results.advice
    assert advice.upgrade_target == "not available"
    assert _first_fixed(_finding(results, FIRST)) is None


def test_no_matching_platform_entry_is_not_available() -> None:
    results = _results(_advisory(FIRST, _platform(NEXUS3000, _fix("10.4(5)"))))

    (advice,) = results.advice
    assert advice.upgrade_target == "not available"


def test_two_matching_platform_entries_are_not_available() -> None:
    results = _results(
        _advisory(
            FIRST,
            _platform(NEXUS9000, _fix("10.4(5)")),
            _platform(NEXUS9000, _fix("10.4(8)")),
        )
    )

    (advice,) = results.advice
    assert advice.upgrade_target == "not available"


def test_each_nxos_advisory_contributes_its_lowest_fix_above_the_running_release() -> None:
    results = _results(
        _advisory(
            FIRST,
            _platform(NEXUS9000, _fix("10.4(5)"), _fix("10.4(8)")),
        ),
        _advisory(
            SECOND,
            _platform(NEXUS9000, _fix("10.4(8)")),
        ),
        _advisory(
            THIRD,
            _platform(NEXUS9000, _fix("10.4(5)"), _fix("10.4(6)")),
        ),
    )

    (advice,) = results.advice
    assert (advice.upgrade_target, advice.not_cleared) == ("10.4(8)", 0)
    assert _first_fixed(_finding(results, FIRST)) == "10.4(5)"
    assert _first_fixed(_finding(results, SECOND)) == "10.4(8)"
    assert _first_fixed(_finding(results, THIRD)) == "10.4(5)"


def test_not_cleared_counts_nxos_advisories_with_no_fix_in_the_train() -> None:
    results = _results(
        _advisory(FIRST, _platform(NEXUS9000, _fix("10.4(8)"))),
        _advisory(
            SECOND,
            _platform(NEXUS9000, _fix("10.4(2)"), _fix("10.4(3)")),
        ),
        _advisory(
            THIRD,
            _platform(NEXUS9000, _fix("10.6(1)", train="10.6")),
        ),
    )

    (advice,) = results.advice
    assert (advice.upgrade_target, advice.not_cleared) == ("10.4(8)", 2)
    assert _first_fixed(_finding(results, SECOND)) is None
    assert "No fix in Train 10.4." in _finding(results, SECOND).what_was_found
    assert _first_fixed(_finding(results, THIRD)) is None


def test_every_nxos_advisory_unfixed_reads_no_fix_in_the_train() -> None:
    results = _results(
        _advisory(FIRST, _platform(NEXUS9000, _fix("10.4(2)"))),
        _advisory(SECOND, _platform(NEXUS9000, _fix("10.6(1)", train="10.6"))),
    )

    (advice,) = results.advice
    assert (advice.upgrade_target, advice.not_cleared) == ("no fix in Train 10.4", 2)
    assert all(
        "No fix in Train 10.4." in finding.what_was_found
        for finding in (_finding(results, FIRST), _finding(results, SECOND))
    )


def test_an_nxos_target_clearing_every_advisory_has_no_tag() -> None:
    results = _results(_advisory(FIRST, _platform(NEXUS9000, _fix("10.4(5)"))))

    (advice,) = results.advice
    assert (advice.upgrade_target, advice.not_cleared) == ("10.4(5)", 0)
    assert "Upgrade to 10.4(5) or later." in _finding(results, FIRST).what_to_do
