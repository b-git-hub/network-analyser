"""Lettered and special running releases are checked like any other release (#137).

Driven through `analysis.analyse`, `platforms.read_version` and `advisories.is_safe_release`.
Stories 14-19 of spec #122 and story 45 of spec #92 treat `26.1.2s1`, `10.6(3s)` and
`15.1(4)M12a` as ordinary releases; the earlier tests used them only as fix values. Every
release is public Cisco numbering, every answer is hand-written, and the show version text
is synthetic.
"""

from dataclasses import replace

import pytest

from network_analyser import analysis, platforms, topology
from network_analyser.advisories import is_safe_release
from network_analyser.records.analysis import (
    AdvisoryAnswer,
    AdvisoryPlatform,
    AnalysisInput,
    CiscoAnswers,
    CompatibleRelease,
    CompatibleReleases,
    FixedRelease,
    OsType,
    ReleaseAdvisories,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.platform import Platform
from network_analyser.records.topology import (
    AdvisoryDetail,
    AdvisoryOutcomeKind,
    AnalysisResults,
    CheckType,
    CiscoDetailKind,
    FindingLevel,
)
from network_analyser.records.unknown import Unknown
from tests.support.topology_records import visited

XE_MODEL = "C9300-48P"
CLASSIC_MODEL = "WS-C2960X-48FPD-L"
NEXUS_MODEL = "N9K-C93180YC-FX"
NEXUS_PLATFORM = "Cisco Nexus 9000 Series Switches"
ADVISORY = "cisco-sa-lettered-0001"

# (platform, model, running release, family, Train, first fix in the Train)
LETTERED = [
    (Platform.IOS_XE, XE_MODEL, "26.1.2s1", OsType.IOS_XE, "26.1", "26.1.3"),
    (Platform.IOS_XE, XE_MODEL, "17.12.7a", OsType.IOS_XE, "17.12", "17.12.8"),
    (Platform.IOS_XE, CLASSIC_MODEL, "15.1(4)M12a", OsType.IOS, "15.1M", "15.1(4)M13"),
    (Platform.NX_OS, NEXUS_MODEL, "10.6(3s)", OsType.NX_OS, "10.6", "10.6(4)"),
    (Platform.NX_OS, NEXUS_MODEL, "10.3(4a)", OsType.NX_OS, "10.3", "10.3(5)"),
    (Platform.NX_OS, NEXUS_MODEL, "9.3(1z)", OsType.NX_OS, "9.3", "9.3(2)"),
    (Platform.NX_OS, NEXUS_MODEL, "7.0(3)I4(8b)", OsType.NX_OS, "7.0(3)I4", "7.0(3)I4(9)"),
    (Platform.NX_OS, NEXUS_MODEL, "5.2(1)N1(9a)", OsType.NX_OS, "5.2(1)N1", "5.2(1)N1(10)"),
]


def _device(platform: Platform, model: str, release: str, serial: str = "S1") -> DeviceRecord:
    record = visited("192.0.2.1", serial, "sw-a", platform=platform)
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, model=model, software_version=release))


def _advisory(train: str, fix: str, *, series: str | None) -> AdvisoryAnswer:
    fixes = (FixedRelease(train, fix),)
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
        first_fixed=fixes,
        platforms=(AdvisoryPlatform(series, fixes),) if series is not None else (),
    )


def _analyse(
    device: DeviceRecord,
    answers: tuple[ReleaseAdvisories, ...] = (),
    compatible: tuple[CompatibleReleases, ...] = (),
) -> AnalysisResults:
    return analysis.analyse(
        AnalysisInput(
            topology=topology.build((device,)),
            answers=CiscoAnswers(advisories=answers, compatible=compatible),
        )
    )


def _question_release(device: DeviceRecord) -> tuple[OsType, str, str | None]:
    questions = analysis.lookup_questions(AnalysisInput(topology=topology.build((device,))))
    (question,) = questions.releases
    return question.os_type, question.release, question.hardware_family


@pytest.mark.parametrize("case", LETTERED)
def test_a_lettered_or_special_running_release_gets_its_advisories_and_target(
    case: tuple[Platform, str, str, OsType, str, str],
) -> None:
    platform, model, running, os_type, train, fix = case
    device = _device(platform, model, running)
    nexus = platform is Platform.NX_OS
    asked_os, asked_release, family = _question_release(device)
    assert (asked_os, asked_release) == (os_type, running)
    results = _analyse(
        device,
        answers=(
            ReleaseAdvisories(
                os_type=asked_os,
                release=asked_release,
                advisories=(_advisory(train, fix, series=NEXUS_PLATFORM if nexus else None),),
                hardware_family=family,
            ),
        ),
        compatible=(
            CompatibleReleases(
                pid=model,
                releases=(CompatibleRelease(fix, "MD"), CompatibleRelease("26.9.9", "ED")),
            ),
        ),
    )

    assert not [f for f in results.findings if f.check.id == "advisory-could-not-check"]
    (finding,) = [f for f in results.findings if f.check.type is CheckType.ADVISORY]
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.first_fixed == fix
    (advice,) = results.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.MATCHES
    assert advice.upgrade_target == fix
    assert advice.latest_release_in_train == fix


@pytest.mark.parametrize(
    ("running", "train"),
    [
        ("6.0(2)U6(10)", "6.0(2)U6"),
        ("6.0(2)A8(11)", "6.0(2)A8"),
        ("5.2(1)N1(9)", "5.2(1)N1"),
        ("7.0(3)F3(4)", "7.0(3)F3"),
        ("7.0(3)I7(9)", "7.0(3)I7"),
    ],
)
def test_nx_os_letter_trains_are_not_lumped_into_one_train(running: str, train: str) -> None:
    same_line = f"{train}(12)"
    other_line = f"{running.split('(', maxsplit=1)[0]}(9)Z9(99)"
    device = _device(Platform.NX_OS, NEXUS_MODEL, running)
    listed = (CompatibleRelease(other_line, "MD"), CompatibleRelease(same_line, "MD"))

    results = _analyse(device, compatible=(CompatibleReleases(pid=NEXUS_MODEL, releases=listed),))

    (advice,) = results.advice
    assert advice.latest_release_in_train == same_line


def test_a_release_below_the_family_table_still_reads_could_not_check() -> None:
    device = _device(Platform.NX_OS, NEXUS_MODEL, "14.2(4i)")

    results = _analyse(device)

    (advice,) = results.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.COULD_NOT_CHECK
    assert advice.advisory_outcome.reason == "NX-OS in ACI mode is not matched"


@pytest.mark.parametrize(
    ("shown", "release"),
    [
        ("7.0(3)I7(9) [build 7.0(3)I7(8.18)]", "7.0(3)I7(9)"),
        ("9.3(10) [build 9.3(10.1)]", "9.3(10)"),
        ("10.4(3) [Feature Release]", "10.4(3)"),
        ("10.2(5) [Maintenance Release]", "10.2(5)"),
        ("10.2(5) [Maintenance Release] [build 10.2(5.2)]", "10.2(5)"),
    ],
)
def test_the_nx_os_bracketed_suffix_is_dropped_when_show_version_is_read(
    shown: str, release: str
) -> None:
    text = (
        "Cisco Nexus Operating System (NX-OS) Software\n"
        "Software\n"
        f"  NXOS: version {shown}\n"
        "  NXOS image file is: bootflash:///nxos.bin\n"
        "Hardware\n"
        "  cisco Nexus9000 C9300v Chassis\n"
        "  Processor Board ID TEST0000N01\n"
        "  Device name: nx-a\n"
    )

    facts = platforms.read_version(Platform.NX_OS, text)

    assert facts.software_version == release


@pytest.mark.parametrize("shown", ["9.3(10) [build", "9.3(10) junk", "9.3(10)\x1b[2J [x]"])
def test_a_version_with_other_text_after_it_is_still_unknown(shown: str) -> None:
    text = f"Software\n  NXOS: version {shown}\n  Device name: nx-a\n"

    facts = platforms.read_version(Platform.NX_OS, text)

    assert isinstance(facts.software_version, Unknown)


@pytest.mark.parametrize(
    "release",
    [running for _, _, running, _, _, _ in LETTERED]
    + [fix for _, _, _, _, _, fix in LETTERED]
    + ["7.0(3)I7(9)", "6.0(2)U6(10)", "15.2(7)E4", "17.9.4a"],
)
def test_every_release_the_family_table_holds_may_be_sent_to_cisco(release: str) -> None:
    assert is_safe_release(release)
