"""The Latest Release and the Suggested Release against odd compatible lists (#138).

Driven through `analysis.analyse` only. Cisco's lists are not always shaped the way a device
prints its release: an entry can carry a codename, classic IOS can come dotted, numbers can be
zero padded. Every answer is hand-written synthetic data in shapes the replies are documented
to take; no real Cisco reply is here.
"""

from dataclasses import replace

from network_analyser import analysis, topology
from network_analyser.records.analysis import (
    AnalysisInput,
    CiscoAnswers,
    CompatibleRelease,
    CompatibleReleases,
    SourceUnavailable,
    SuggestedReleases,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.platform import Platform
from network_analyser.records.topology import (
    NOT_AVAILABLE,
    AnalysisResults,
    CheckType,
    Finding,
)
from tests.support.analysis_records import collected_of
from tests.support.topology_records import chassis_inventory, visited

A = "192.0.2.1"
MODEL = "C9300-48P"
CLASSIC_MODEL = "WS-C2960X-48FPD-L"
NEXUS_MODEL = "N9K-C93180YC-FX"
NEWER = "running release is newer than Cisco's list"
_NOT_ASKED = SourceUnavailable("not asked in this test")


def _device(
    release: str,
    *,
    platform: Platform = Platform.IOS_XE,
    model: str = MODEL,
) -> DeviceRecord:
    nexus = platform is Platform.NX_OS
    record = visited(
        A, "S1", "sw-a", platform=platform, inventory=chassis_inventory(model) if nexus else None
    )
    version = record.version
    assert version is not None
    shown = model.removeprefix("N9K-") if nexus else model
    return replace(record, version=replace(version, model=shown, software_version=release))


def _compatible(pid: str, *releases: tuple[str, str | None]) -> CompatibleReleases:
    return CompatibleReleases(
        pid, releases=tuple(CompatibleRelease(release, code) for release, code in releases)
    )


def _advice(record: DeviceRecord, compatible: CompatibleReleases) -> tuple[str, str]:
    results = analysis.analyse(
        AnalysisInput(
            topology=topology.build((record,)),
            collected=collected_of(record),
            answers=CiscoAnswers(compatible=(compatible,)),
        )
    )
    (advice,) = results.advice
    return advice.latest_release_in_train, advice.latest_release


def _suggested_findings(record: DeviceRecord, *releases: str) -> list[Finding]:
    results: AnalysisResults = analysis.analyse(
        AnalysisInput(
            topology=topology.build((record,)),
            collected=collected_of(record),
            answers=CiscoAnswers(
                advisories=_NOT_ASKED,
                eox=_NOT_ASKED,
                suggestions=(SuggestedReleases(pid=MODEL, releases=releases),),
            ),
        )
    )
    return [
        finding
        for finding in results.findings
        if finding.check.type is CheckType.LIFECYCLE
        and finding.check.id == "lifecycle-suggested-release"
    ]


def test_a_list_entry_that_does_not_start_with_a_number_is_never_the_latest() -> None:
    compatible = _compatible(
        MODEL,
        ("17.12.8", "MD"),
        ("26.2.1", "ED"),
        ("Dublin-17.12.4", "MD"),
        ("abc", "MD"),
        ("IOS XE 17.12.4", "MD"),
    )

    in_train, overall = _advice(_device("17.12.4"), compatible)

    assert (in_train, overall) == ("17.12.8", "26.2.1")


def test_a_list_of_only_odd_entries_is_not_available() -> None:
    compatible = _compatible(MODEL, ("Dublin-17.12.4", "MD"), ("abc", None))

    assert _advice(_device("17.12.4"), compatible) == (NOT_AVAILABLE, NOT_AVAILABLE)


def test_a_list_entry_no_family_can_hold_is_never_the_latest() -> None:
    compatible = _compatible(
        NEXUS_MODEL, ("10.4(8)", "MD"), ("17.12.4", "MD"), ("9.3(1.2.3)", None)
    )
    record = _device("10.3(4a)", platform=Platform.NX_OS, model=NEXUS_MODEL)

    assert _advice(record, compatible) == (NOT_AVAILABLE, "10.4(8)")


def test_dotted_classic_ios_releases_are_read_as_classic_ios() -> None:
    compatible = _compatible(
        CLASSIC_MODEL,
        ("15.2.7E4", "MD"),
        ("15.2.7E2", "MD"),
        ("15.2.4E10", None),
    )

    in_train, overall = _advice(_device("15.2(7)E2", model=CLASSIC_MODEL), compatible)

    assert in_train == "15.2(7)E4"
    assert overall == "15.2(7)E4"


def test_a_device_on_the_newest_dotted_classic_release_is_not_shown_an_older_one() -> None:
    compatible = _compatible(CLASSIC_MODEL, ("15.2.7E2", "MD"), ("15.2.7E3", "MD"))

    in_train, overall = _advice(_device("15.2(7)E4", model=CLASSIC_MODEL), compatible)

    assert in_train == NEWER
    assert overall == NEWER


def test_a_zero_padded_list_gives_the_same_result_as_the_plain_one() -> None:
    plain = _compatible(MODEL, ("17.9.5", "MD"), ("17.9.4a", "MD"), ("17.12.1", "ED"))
    padded = _compatible(MODEL, ("17.09.05", "MD"), ("17.09.04a", "MD"), ("17.12.01", "ED"))
    record = _device("17.9.1")

    assert _advice(record, padded) == _advice(record, plain) == ("17.9.5", "17.12.1")


def test_a_zero_padded_dotted_classic_release_is_read_too() -> None:
    compatible = _compatible(CLASSIC_MODEL, ("15.02.07E4", "MD"))

    assert _advice(_device("15.2(7)E2", model=CLASSIC_MODEL), compatible) == (
        "15.2(7)E4",
        "15.2(7)E4",
    )


def test_an_aci_mode_device_never_reads_newer_than_a_standalone_list() -> None:
    compatible = _compatible(NEXUS_MODEL, ("10.3(4a)", "MD"), ("10.4(8)", "ED"))
    record = _device("14.2(4i)", platform=Platform.NX_OS, model=NEXUS_MODEL)

    in_train, overall = _advice(record, compatible)

    assert NEWER not in (in_train, overall)
    assert in_train == NOT_AVAILABLE


def test_a_codename_on_a_suggested_release_still_matches_the_running_release() -> None:
    record = _device("17.12.4")

    assert _suggested_findings(record, "Dublin-17.12.4", "17.9.10") == []
    assert _suggested_findings(record, "IOS XE 17.12.04") == []


def test_a_suggested_dotted_classic_release_matches_the_running_release() -> None:
    record = _device("15.2(7)E4", model=MODEL)

    assert _suggested_findings(record, "15.2.7E4") == []


def test_a_different_suggested_release_is_still_a_finding() -> None:
    record = _device("17.12.4")

    (finding,) = _suggested_findings(record, "Dublin-17.12.5", "17.12.4a")

    assert "17.12.4" in finding.what_was_found
