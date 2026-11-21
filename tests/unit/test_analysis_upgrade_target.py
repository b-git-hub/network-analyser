"""The Upgrade Target at Seam 1: the first fix that clears each Advisory (#124).

Driven through `analysis.analyse` only. Synthetic Cisco answers go in; the operator's advice
comes out: each Advisory's first fix above the running release in the device's Train, the
highest of those as the device's target, and how many Advisories it leaves open. Every release
string is public Cisco numbering, and every answer is hand-written synthetic data.
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
MODEL = "C9300-48P"
RUNNING = "17.12.4"
TRAIN = "17.12"
FIRST = "cisco-sa-target-0001"
SECOND = "cisco-sa-target-0002"
THIRD = "cisco-sa-target-0003"


def _device(release: str = RUNNING) -> DeviceRecord:
    record = visited(A, "S1", "sw-a", platform=Platform.IOS_XE)
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, model=MODEL, software_version=release))


def _advisory(
    ident: str, *fixes: FixedRelease, sir: FindingLevel = FindingLevel.HIGH
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
        first_fixed=fixes,
    )


def _results(
    *advisories: AdvisoryAnswer, release: str = RUNNING, device: DeviceRecord | None = None
) -> AnalysisResults:
    return analysis.analyse(
        AnalysisInput(
            topology=topology.build((device or _device(release),)),
            answers=CiscoAnswers(
                advisories=(ReleaseAdvisories(OsType.IOS_XE, release, advisories),)
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


def test_an_advisory_takes_the_lowest_fix_above_the_running_release_in_its_train() -> None:
    results = _results(
        _advisory(
            FIRST,
            FixedRelease("17.12", "17.12.5"),
            FixedRelease("17.12", "17.12.6"),
            FixedRelease("17.15", "17.15.1"),
        )
    )

    (advice,) = results.advice
    assert (advice.upgrade_target, advice.not_cleared) == ("17.12.5", 0)
    finding = _finding(results, FIRST)
    assert _first_fixed(finding) == "17.12.5"
    assert "First fixed in Train 17.12: 17.12.5." in finding.what_was_found
    assert "Upgrade to 17.12.5 or later." in finding.what_to_do


def test_fixes_at_or_below_the_running_release_are_no_fix_in_the_train() -> None:
    results = _results(
        _advisory(
            FIRST,
            FixedRelease("17.12", "17.12.3"),
            FixedRelease("17.12", "17.12.4"),
        )
    )

    (advice,) = results.advice
    assert (advice.upgrade_target, advice.not_cleared) == ("no fix in Train 17.12", 1)
    finding = _finding(results, FIRST)
    assert _first_fixed(finding) is None
    assert "No fix in Train 17.12." in finding.what_was_found


def test_a_lettered_release_above_the_running_release_is_the_first_fix() -> None:
    results = _results(
        _advisory(
            FIRST,
            FixedRelease("17.12", "17.12.7a"),
            FixedRelease("17.12", "17.12.8"),
        ),
        release="17.12.7",
    )

    (advice,) = results.advice
    assert advice.upgrade_target == "17.12.7a"
    assert _first_fixed(_finding(results, FIRST)) == "17.12.7a"


@pytest.mark.parametrize(("first", "second"), [("17.12.5", "17.12.7"), ("17.12.7", "17.12.5")])
def test_the_highest_per_advisory_fix_wins_across_advisories(first: str, second: str) -> None:
    results = _results(
        _advisory(FIRST, FixedRelease(TRAIN, first)),
        _advisory(SECOND, FixedRelease(TRAIN, second)),
    )

    (advice,) = results.advice
    assert (advice.upgrade_target, advice.not_cleared) == ("17.12.7", 0)


def test_a_partial_target_names_the_highest_fix_and_counts_what_it_leaves_open() -> None:
    results = _results(
        _advisory(FIRST, FixedRelease(TRAIN, "17.12.7")),
        _advisory(SECOND, FixedRelease(TRAIN, "17.12.8")),
        _advisory(THIRD, FixedRelease("17.15", "17.15.2")),
    )

    (advice,) = results.advice
    assert (advice.upgrade_target, advice.not_cleared) == ("17.12.8", 1)
    assert advice.train == TRAIN
    assert _first_fixed(_finding(results, FIRST)) == "17.12.7"
    assert _first_fixed(_finding(results, SECOND)) == "17.12.8"
    assert _first_fixed(_finding(results, THIRD)) is None
    assert "First fixed in Train 17.12: 17.12.7." in _finding(results, FIRST).what_was_found
    assert "No fix in Train 17.12." in _finding(results, THIRD).what_was_found
    assert "17.15.2" not in advice.upgrade_target


def test_every_advisory_unfixed_reads_no_fix_in_the_train() -> None:
    results = _results(
        _advisory(FIRST, FixedRelease("17.15", "17.15.2")),
        _advisory(SECOND),
    )

    (advice,) = results.advice
    assert (advice.upgrade_target, advice.not_cleared) == ("no fix in Train 17.12", 2)
    assert advice.train == TRAIN


def test_no_critical_or_high_advisories_reads_no_advisories() -> None:
    results = _results(
        _advisory(FIRST, FixedRelease(TRAIN, "17.12.5"), sir=FindingLevel.MEDIUM),
        _advisory(SECOND, FixedRelease(TRAIN, "17.12.6"), sir=FindingLevel.LOW),
    )

    (advice,) = results.advice
    assert (advice.upgrade_target, advice.not_cleared) == ("no Critical/High Advisories", 0)
