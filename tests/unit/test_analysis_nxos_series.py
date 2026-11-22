"""The Nexus series comes from the chassis PID in `show inventory`, at Seam 1 (#134).

The NX-OS `show version` reader yields a model such as `C93180YC-EX`, never a series name, so
the series is worked out from the chassis PID the Run collected (`N9K-C93180YC-EX`). Driven
through `analysis.analyse` and `analysis.lookup_questions` with the records the real readers
produce: a model with no `N9K-` prefix, and an inventory whose chassis entry carries the PID.
When the Device Role refuses `show inventory`, the series falls back to the `Nexus<NNNN>` token
`show version` names (#159). Every PID, name and answer is synthetic.
"""

from dataclasses import replace

import pytest

from network_analyser import analysis, platforms, topology
from network_analyser.records.analysis import (
    AdvisoryAnswer,
    AdvisoryPlatform,
    AnalysisInput,
    CiscoAnswers,
    CompatibleRelease,
    CompatibleReleases,
    DeviceCollected,
    FixedRelease,
    OsType,
    ReleaseAdvisories,
    SuggestedReleases,
)
from network_analyser.records.collected import InventoryItem, InventoryKind
from network_analyser.records.device import DeviceRecord
from network_analyser.records.platform import Platform
from network_analyser.records.topology import (
    AdvisoryDetail,
    AdvisoryOutcomeKind,
    AnalysisResults,
    CiscoDetailKind,
    FindingLevel,
)
from network_analyser.records.unknown import Unknown
from tests.support import device_text
from tests.support.topology_records import ip, visited

A = "192.0.2.1"
MODEL = "C93180YC-EX"
CHASSIS = "N9K-C93180YC-EX"
RUNNING = "10.4(3)"
NEXUS9000 = "Cisco Nexus 9000 Series Switches"
COULD_NOT_WORK_OUT = (
    "hardware family not confirmed: the Nexus hardware family could not be worked out, "
    "so Cisco openVuln was not asked"
)


def _item(name: str, kind: InventoryKind, pid: str | Unknown) -> InventoryItem:
    return InventoryItem(name, kind, pid, "TEST0000N01")


def _device(
    *,
    chassis: str | Unknown | None = CHASSIS,
    inventory: tuple[InventoryItem, ...] | Unknown | None = None,
    hardware_series: str | None = None,
) -> DeviceRecord:
    """An NX-OS device as the real readers record it: model `C93180YC-EX`, PIDs in inventory."""
    if inventory is None:
        inventory = (
            _item("Slot 1", InventoryKind.SUPERVISOR, "N9K-SUP-A"),
            _item("Chassis", InventoryKind.CHASSIS, chassis if chassis is not None else MODEL),
            _item("Slot 2", InventoryKind.LINE_CARD, "N9K-X9636C-RX"),
        )
    record = visited(A, "S1", "sw-a", platform=Platform.NX_OS, inventory=inventory)
    version = record.version
    assert version is not None
    return replace(
        record,
        version=replace(
            version, model=MODEL, software_version=RUNNING, hardware_series=hardware_series
        ),
    )


def _input(record: DeviceRecord, answers: CiscoAnswers | None = None) -> AnalysisInput:
    assert record.collected is not None
    return AnalysisInput(
        topology=topology.build((record,)),
        collected=(DeviceCollected(ip(A), record.collected),),
        answers=answers if answers is not None else CiscoAnswers(),
    )


def _advisory() -> AdvisoryAnswer:
    return AdvisoryAnswer(
        detail=AdvisoryDetail(
            kind=CiscoDetailKind.ADVISORY,
            id="cisco-sa-nxos-0001",
            title="Example Advisory",
            sir=FindingLevel.HIGH,
            cvss="8.1",
            cves=("CVE-2026-0001",),
            published="2026-11-01",
            updated="2026-11-02",
            first_fixed=None,
        ),
        platforms=(AdvisoryPlatform(NEXUS9000, (FixedRelease("10.4", "10.4(5)"),)),),
    )


def _results(record: DeviceRecord, answers: CiscoAnswers) -> AnalysisResults:
    return analysis.analyse(_input(record, answers))


@pytest.mark.parametrize(
    ("pid", "alias"),
    [
        ("N9K-C93180YC-EX", "NEXUS9000"),
        ("N9K-9000v", "NEXUS9000"),
        ("N7K-C7010", "NEXUS7000"),
        ("N77-C7706", "NEXUS7000"),
        ("N5K-C5548UP", "NEXUS5000"),
        ("N3K-C3048TP-1GE", "NEXUS3000"),
        ("N3K-C3548P-10GX", "NEXUS3000"),
        ("N6K-C6001-64P", "NEXUS6000"),
    ],
)
def test_the_series_alias_comes_from_the_chassis_pid(pid: str, alias: str) -> None:
    questions = analysis.lookup_questions(_input(_device(chassis=pid)))

    assert [(q.os_type, q.release, q.hardware_family) for q in questions.releases] == [
        (OsType.NX_OS, RUNNING, alias)
    ]


def test_lookups_use_the_chassis_pid_and_never_the_show_version_model() -> None:
    questions = analysis.lookup_questions(_input(_device()))

    assert MODEL not in questions.pids
    assert CHASSIS in questions.pids
    assert questions.compatible_pids == (CHASSIS,)


@pytest.mark.parametrize(
    "pid",
    ["N2K-C2248TP-1GE", "C93180YC-EX", "WS-C3750-48P", "N9K"],
)
def test_a_chassis_pid_that_names_no_documented_series_gives_no_alias(pid: str) -> None:
    questions = analysis.lookup_questions(_input(_device(chassis=pid)))

    assert [(q.os_type, q.hardware_family) for q in questions.releases] == [(OsType.NX_OS, None)]


@pytest.mark.parametrize(
    "inventory",
    [
        None,
        Unknown("show inventory | json: denied"),
        (),
        (_item("Slot 1", InventoryKind.SUPERVISOR, "N9K-SUP-A"),),
        (_item("Chassis", InventoryKind.CHASSIS, Unknown("PID not reported by show inventory")),),
    ],
)
def test_no_chassis_pid_means_the_series_is_not_confirmed(
    inventory: tuple[InventoryItem, ...] | Unknown | None,
) -> None:
    base = visited(A, "S1", "sw-a", platform=Platform.NX_OS, inventory=inventory)
    version = base.version
    assert version is not None
    record = replace(base, version=replace(version, model=MODEL, software_version=RUNNING))

    questions = analysis.lookup_questions(_input(record))

    assert [(q.os_type, q.hardware_family) for q in questions.releases] == [(OsType.NX_OS, None)]
    assert questions.compatible_pids == ()
    assert MODEL not in questions.pids


def test_a_refused_show_inventory_falls_back_to_the_show_version_nexus_token() -> None:
    record = _device(
        inventory=Unknown("show inventory | json: denied"), hardware_series="Nexus9000"
    )

    questions = analysis.lookup_questions(_input(record))

    assert [(q.os_type, q.release, q.hardware_family) for q in questions.releases] == [
        (OsType.NX_OS, RUNNING, "NEXUS9000")
    ]
    assert questions.compatible_pids == ()
    assert MODEL not in questions.pids


def test_the_show_version_token_fallback_reaches_analysis_from_the_show_version_text() -> None:
    base = visited(A, "S1", "nx-a", platform=Platform.NX_OS, inventory=Unknown("denied"))
    record = replace(
        base, version=platforms.read_version(Platform.NX_OS, device_text.NXOS_SHOW_VERSION)
    )

    questions = analysis.lookup_questions(_input(record))

    assert [(q.os_type, q.hardware_family) for q in questions.releases] == [
        (OsType.NX_OS, "NEXUS9000")
    ]


def test_a_show_version_token_that_names_no_documented_series_gives_no_alias() -> None:
    record = _device(
        inventory=Unknown("show inventory | json: denied"), hardware_series="Nexus2000"
    )

    questions = analysis.lookup_questions(_input(record))

    assert [(q.os_type, q.hardware_family) for q in questions.releases] == [(OsType.NX_OS, None)]


def test_the_chassis_pid_still_wins_over_the_show_version_token() -> None:
    record = _device(chassis="N3K-C3048TP-1GE", hardware_series="Nexus9000")

    questions = analysis.lookup_questions(_input(record))

    assert [(q.os_type, q.hardware_family) for q in questions.releases] == [
        (OsType.NX_OS, "NEXUS3000")
    ]


def test_a_fallback_series_matches_advisories_without_the_not_confirmed_note() -> None:
    record = _device(
        inventory=Unknown("show inventory | json: denied"), hardware_series="Nexus9000"
    )
    answers = CiscoAnswers(
        advisories=(
            ReleaseAdvisories(OsType.NX_OS, RUNNING, (_advisory(),), hardware_family="NEXUS9000"),
        )
    )

    results = _results(record, answers)

    (finding,) = [f for f in results.findings if f.check.id == "advisory-cisco-sa-nxos-0001"]
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.first_fixed == "10.4(5)"
    assert finding.cisco_detail.hardware_family_not_confirmed is False
    assert "hardware family not confirmed" not in finding.what_was_found


def test_realistic_output_gives_advisory_findings_and_an_upgrade_target() -> None:
    answers = CiscoAnswers(
        advisories=(
            ReleaseAdvisories(OsType.NX_OS, RUNNING, (_advisory(),), hardware_family="NEXUS9000"),
        ),
        compatible=(
            CompatibleReleases(
                CHASSIS, (CompatibleRelease("10.4(5)", "ED"), CompatibleRelease("10.5(2)", "ED"))
            ),
        ),
    )

    results = _results(_device(), answers)

    (finding,) = [f for f in results.findings if f.check.id == "advisory-cisco-sa-nxos-0001"]
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.first_fixed == "10.4(5)"
    assert finding.cisco_detail.hardware_family_not_confirmed is False
    (advice,) = results.advice
    assert advice.upgrade_target == "10.4(5)"
    assert advice.latest_release_in_train == "10.4(5)"
    assert advice.latest_release == "10.5(2)"


def test_the_suggested_release_check_uses_the_chassis_pid() -> None:
    answers = CiscoAnswers(
        advisories=(),
        suggestions=(SuggestedReleases(CHASSIS, releases=("10.4(3)",)),),
    )

    results = _results(_device(), answers)

    assert not [f for f in results.findings if "Suggested" in f.check.name]


def test_an_unconfirmed_series_reads_hardware_family_not_confirmed_with_the_real_cause() -> None:
    record = _device(inventory=Unknown("show inventory | json: denied"))
    answers = CiscoAnswers(
        advisories=(ReleaseAdvisories(OsType.NX_OS, RUNNING, hardware_family="NEXUS9000"),)
    )

    results = _results(record, answers)

    (advice,) = results.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.COULD_NOT_CHECK
    assert advice.advisory_outcome.reason == COULD_NOT_WORK_OUT
    (finding,) = [f for f in results.findings if f.check.id == "advisory-could-not-check"]
    assert "gave no answer" not in finding.what_was_found
    assert COULD_NOT_WORK_OUT in finding.what_was_found
    assert "show inventory" in finding.what_to_do


def test_cisco_not_answering_a_question_that_was_asked_keeps_its_own_reason() -> None:
    answers = CiscoAnswers(advisories=())

    results = _results(_device(), answers)

    (advice,) = results.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.COULD_NOT_CHECK
    assert advice.advisory_outcome.reason == (
        f"Cisco openVuln gave no answer for release {RUNNING}"
    )
