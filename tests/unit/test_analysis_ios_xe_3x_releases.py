"""IOS-XE 3.x releases are in the family table, whatever their zero padding (#151).

Driven through `platforms.read_version`, `analysis.lookup_questions`, `analysis.analyse` and
`advisories.is_safe_release`. A Catalyst 3850 on IOS XE 3.x prints the same release on its
`Cisco IOS XE Software` line and its IOS line, zero padded as `03.06.08E`, so that spelling
reaches Analysis as it is. The tool strips the padding to `3.6.8E` and keeps the upper-case
Train letter, which is the shape this ticket accepts until #164's probe settles what Cisco's
APIs name (item 5). Every release is public Cisco numbering, every answer is hand-written and
the `show version` text is synthetic.
"""

from dataclasses import replace

import pytest

from network_analyser import analysis, platforms, topology
from network_analyser.advisories import is_safe_release
from network_analyser.records.analysis import (
    AdvisoryAnswer,
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
from tests.support.analysis_records import collected_of
from tests.support.topology_records import visited

MODEL = "WS-C3850-24T"
ADVISORY = "cisco-sa-iosxe-3x-0001"

# What a Catalyst 3850 on IOS XE 3.x answers to `show version`: the same release twice, zero
# padded, with no `Router operating mode:` line.
SHOW_VERSION = """\
Cisco IOS XE Software, Version 03.06.08E
Cisco IOS Software, IOS-XE Software (CAT3K_CAA-UNIVERSALK9-M), Version 03.06.08E, \
RELEASE SOFTWARE (fc2)
Copyright (c) 1986-2015 by Cisco Systems, Inc.

ROM: IOS-XE ROMMON

sw-a uptime is 3 weeks, 1 day, 2 hours, 5 minutes
System returned to ROM by reload
System image file is "flash:packages.conf"

cisco WS-C3850-24T (MIPS) processor (revision V02) with 2097152K/2048K bytes of memory.
Processor board ID TEST0000C01
"""


def _device(release: str) -> DeviceRecord:
    record = visited("192.0.2.1", "TEST0000C01", "sw-a")
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, model=MODEL, software_version=release))


def _question(device: DeviceRecord) -> tuple[OsType, str]:
    questions = analysis.lookup_questions(
        AnalysisInput(topology=topology.build((device,)), collected=collected_of(device))
    )
    (question,) = questions.releases
    return question.os_type, question.release


def _advisory(train: str, fix: str) -> AdvisoryAnswer:
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
        first_fixed=(FixedRelease(train, fix),),
    )


def _analyse(
    device: DeviceRecord,
    answers: tuple[ReleaseAdvisories, ...] = (),
    compatible: tuple[CompatibleReleases, ...] = (),
) -> AnalysisResults:
    return analysis.analyse(
        AnalysisInput(
            topology=topology.build((device,)),
            collected=collected_of(device),
            answers=CiscoAnswers(advisories=answers, compatible=compatible),
        )
    )


def test_a_3x_show_version_reads_as_an_ios_xe_device_with_its_printed_release() -> None:
    assert platforms.identify(SHOW_VERSION) is Platform.IOS_XE

    facts = platforms.read_version(Platform.IOS_XE, SHOW_VERSION)

    assert facts.software_version == "03.06.08E"
    assert facts.model == MODEL


@pytest.mark.parametrize(
    ("shown", "asked"), [("03.06.08E", "3.6.8E"), ("3.6.8E", "3.6.8E"), ("3.16.4aS", "3.16.4aS")]
)
def test_a_3x_device_asks_about_its_ios_xe_release_without_zero_padding(
    shown: str, asked: str
) -> None:
    assert _question(_device(shown)) == (OsType.IOS_XE, asked)


@pytest.mark.parametrize("shown", ["03.06.08E", "3.6.8E"])
def test_a_3x_device_gets_advisories_upgrade_target_and_latest_release_in_train(
    shown: str,
) -> None:
    device = _device(shown)

    results = _analyse(
        device,
        answers=(
            ReleaseAdvisories(
                os_type=OsType.IOS_XE,
                release="3.6.8E",
                advisories=(_advisory("3.6E", "3.6.9E"),),
            ),
        ),
        compatible=(
            CompatibleReleases(
                pid=MODEL,
                releases=(CompatibleRelease("3.6.9E", "MD"), CompatibleRelease("3.7.1E", "ED")),
            ),
        ),
    )

    assert not [f for f in results.findings if f.check.id == "advisory-could-not-check"]
    (finding,) = [f for f in results.findings if f.check.type is CheckType.ADVISORY]
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.first_fixed == "3.6.9E"
    (advice,) = results.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.MATCHES
    assert advice.advisory_outcome.release == "3.6.8E"
    assert advice.upgrade_target == "3.6.9E"
    assert advice.latest_release_in_train == "3.6.9E"
    assert advice.latest_release == "3.7.1E"


def test_a_3x_train_keeps_its_letter_so_other_image_lines_are_never_lumped() -> None:
    device = _device("03.02.02SE")

    results = _analyse(
        device,
        compatible=(
            CompatibleReleases(
                pid=MODEL,
                releases=(CompatibleRelease("3.2.4SG", "MD"), CompatibleRelease("3.2.3SE", "MD")),
            ),
        ),
    )

    (advice,) = results.advice
    assert advice.latest_release_in_train == "3.2.3SE"


@pytest.mark.parametrize("release", ["03.06.08E", "3.6.8E", "3.2.2SE", "3.16.4aS"])
def test_every_3x_spelling_analysis_holds_is_a_shape_advisories_allows(release: str) -> None:
    assert is_safe_release(release)
