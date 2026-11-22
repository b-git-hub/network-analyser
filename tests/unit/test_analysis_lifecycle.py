"""The Lifecycle Checks at Seam 1: synthetic Cisco answers in, Findings and advice out (#106).

Driven through `analysis.analyse` only. Every EoX and Software Suggestion answer is hand-written
synthetic data; no real Cisco reply, PID list or device output is here.
"""

import json
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from network_analyser import analysis, topology
from network_analyser.records.analysis import (
    AnalysisInput,
    CiscoAnswers,
    ConfigFact,
    ConfigFacts,
    DeviceInventory,
    EoxAnswers,
    HardwareEox,
    HardwareItem,
    HardwareKind,
    SoftwareEox,
    SourceUnavailable,
    SuggestedReleases,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.platform import Platform
from network_analyser.records.topology import (
    AnalysisResults,
    CheckType,
    CiscoDetailKind,
    EoxDetail,
    EoxItem,
    EoxKind,
    Finding,
    FindingLevel,
)
from tests.support.topology_records import visited

A = "192.0.2.1"
B = "192.0.2.2"
C = "192.0.2.3"
D = "192.0.2.4"
MODEL = "C9300-48P"
RELEASE = "17.9.4a"
PAST = "2024-01-31"
ALSO_PAST = "2025-06-30"
FUTURE = "2099-01-31"
AS_OF = datetime(2026, 11, 21, tzinfo=UTC)
CANARY = "CANARY-lifecycle-a1b2"
_NOT_ASKED = SourceUnavailable("not asked in this test")


def _device(  # noqa: PLR0913 (every device field the Checks read, by name)
    address: str,
    serial: str,
    hostname: str,
    *,
    platform: Platform = Platform.IOS_XE,
    model: str = MODEL,
    release: str = RELEASE,
) -> DeviceRecord:
    record = visited(address, serial, hostname)
    version = record.version
    assert version is not None
    return replace(
        record,
        platform=platform,
        version=replace(version, model=model, software_version=release),
    )


def _hardware(pid: str, *items: EoxItem) -> HardwareEox:
    return HardwareEox(pid=pid, items=tuple(items))


def _software(release: str, *items: EoxItem) -> SoftwareEox:
    return SoftwareEox(release=release, items=tuple(items))


def _item(  # noqa: PLR0913 (every Cisco date the Checks read, by name)
    kind: EoxKind = EoxKind.HARDWARE,
    name: str = MODEL,
    *,
    last_date_of_support: str | None = None,
    end_of_security_support: str | None = None,
    end_of_sw_maintenance: str | None = None,
    end_of_sale: str | None = None,
    replacement: str | None = None,
) -> EoxItem:
    return EoxItem(
        kind=kind,
        name=name,
        last_date_of_support=last_date_of_support,
        end_of_security_support=end_of_security_support,
        end_of_sw_maintenance=end_of_sw_maintenance,
        end_of_sale=end_of_sale,
        replacement=replacement,
    )


def _inventory(device: str, *items: tuple[str, HardwareKind]) -> DeviceInventory:
    return DeviceInventory(device, tuple(HardwareItem(pid, kind) for pid, kind in items))


def _results(  # noqa: PLR0913 (every Cisco source and the reference date, by name)
    *records: DeviceRecord,
    inventory: tuple[DeviceInventory, ...] = (),
    hardware: tuple[HardwareEox, ...] = (),
    software: tuple[SoftwareEox, ...] = (),
    suggestions: tuple[SuggestedReleases, ...] | SourceUnavailable = _NOT_ASKED,
    eox: SourceUnavailable | None = None,
    as_of: datetime = AS_OF,
) -> AnalysisResults:
    answers = CiscoAnswers(
        advisories=_NOT_ASKED,
        eox=eox if eox is not None else (EoxAnswers(hardware=hardware, software=software),),
        suggestions=suggestions,
    )
    return analysis.analyse(
        AnalysisInput(
            topology=topology.build(records),
            inventory=inventory,
            answers=answers,
            as_of=as_of,
        )
    )


def _lifecycle(results: AnalysisResults, check_id: str | None = None) -> list[Finding]:
    return [
        finding
        for finding in results.findings
        if finding.check.type is CheckType.LIFECYCLE
        and (check_id is None or finding.check.id == check_id)
    ]


def test_each_hardware_eox_milestone_sets_its_level() -> None:
    dispatcher = _device(A, "S1", "sw-a", model="C9200-24P")
    security = _device(B, "S2", "sw-b", model="C9300-24P")
    maintenance = _device(C, "S3", "sw-c", model="C9400-LC-48U")
    sale = _device(D, "S4", "sw-d", model="C9500-40X")
    results = _results(
        dispatcher,
        security,
        maintenance,
        sale,
        inventory=(
            _inventory("dev-S1", ("C9200-24P", HardwareKind.CHASSIS)),
            _inventory("dev-S2", ("C9300-24P", HardwareKind.CHASSIS)),
            _inventory("dev-S3", ("C9400-LC-48U", HardwareKind.LINE_CARD)),
            _inventory("dev-S4", ("C9500-40X", HardwareKind.CHASSIS)),
        ),
        hardware=(
            _hardware("C9200-24P", _item(name="C9200-24P", last_date_of_support=PAST)),
            _hardware("C9300-24P", _item(name="C9300-24P", end_of_security_support=PAST)),
            _hardware("C9400-LC-48U", _item(name="C9400-LC-48U", end_of_sw_maintenance=PAST)),
            _hardware("C9500-40X", _item(name="C9500-40X", end_of_sale=PAST)),
        ),
    )

    findings = _lifecycle(results, "lifecycle-hardware-eox")

    assert len(findings) == 4
    assert {finding.devices[0]: finding.level for finding in findings} == {
        "dev-S1": FindingLevel.HIGH,
        "dev-S2": FindingLevel.HIGH,
        "dev-S3": FindingLevel.MEDIUM,
        "dev-S4": FindingLevel.LOW,
    }
    for finding in findings:
        assert finding.check.name == "Hardware EoX"
        assert finding.check.type is CheckType.LIFECYCLE
        assert finding.source == "Cisco EoX"
        assert isinstance(finding.cisco_detail, EoxDetail)
        assert finding.cisco_detail.kind is CiscoDetailKind.EOX


def test_hardware_eox_covers_every_show_inventory_kind_story_73_names() -> None:
    record = _device(A, "S1", "sw-a")
    inventory = _inventory(
        "dev-S1",
        (MODEL, HardwareKind.CHASSIS),
        ("C9300-48P-SM", HardwareKind.STACK_MEMBER),
        ("C9400-SUP-1XL", HardwareKind.SUPERVISOR),
        ("C9300-NM-8X", HardwareKind.LINE_CARD),
    )
    hardware = tuple(
        _hardware(pid, _item(name=pid, end_of_sale=PAST))
        for pid in ("C9300-48P", "C9300-48P-SM", "C9400-SUP-1XL", "C9300-NM-8X")
    )
    results = _results(record, inventory=(inventory,), hardware=hardware)

    (finding,) = _lifecycle(results, "lifecycle-hardware-eox")

    assert finding.level is FindingLevel.LOW
    assert isinstance(finding.cisco_detail, EoxDetail)
    assert [item.name for item in finding.cisco_detail.items] == [
        MODEL,
        "C9300-48P-SM",
        "C9400-SUP-1XL",
        "C9300-NM-8X",
    ]


def test_hardware_eox_folds_every_item_into_one_finding_at_the_worst_level() -> None:
    record = _device(A, "S1", "sw-a")
    inventory = _inventory(
        "dev-S1",
        (MODEL, HardwareKind.CHASSIS),
        ("C9300-NM-8X", HardwareKind.LINE_CARD),
    )
    hardware = (
        _hardware(
            MODEL,
            _item(name=MODEL, end_of_sale=PAST, replacement="C9300X-48H"),
        ),
        _hardware(
            "C9300-NM-8X",
            _item(name="C9300-NM-8X", last_date_of_support=PAST),
        ),
    )
    results = _results(record, inventory=(inventory,), hardware=hardware)

    (finding,) = _lifecycle(results, "lifecycle-hardware-eox")

    assert finding.level is FindingLevel.HIGH
    assert finding.devices == ("dev-S1",)
    assert finding.id.startswith("finding-")
    assert isinstance(finding.cisco_detail, EoxDetail)
    assert [item.name for item in finding.cisco_detail.items] == [MODEL, "C9300-NM-8X"]
    assert finding.cisco_detail.items[0].end_of_sale == PAST
    assert finding.cisco_detail.items[0].replacement == "C9300X-48H"
    assert finding.cisco_detail.items[1].last_date_of_support == PAST
    assert "C9300X-48H" in finding.what_was_found
    assert PAST in finding.what_was_found
    assert finding.what_was_found == finding.summary

    again = _results(record, inventory=(inventory,), hardware=hardware)
    assert _lifecycle(again, "lifecycle-hardware-eox")[0].id == finding.id


def test_upcoming_eox_dates_are_advice_not_findings() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(
        record,
        inventory=(_inventory("dev-S1", (MODEL, HardwareKind.CHASSIS)),),
        hardware=(
            _hardware(
                MODEL,
                _item(
                    name=MODEL,
                    last_date_of_support=FUTURE,
                    end_of_sale=FUTURE,
                    replacement="C9300X-48H",
                ),
            ),
        ),
        software=(
            _software(
                RELEASE,
                _item(
                    kind=EoxKind.SOFTWARE,
                    name=RELEASE,
                    end_of_sw_maintenance=FUTURE,
                ),
            ),
        ),
    )

    assert _lifecycle(results) == []
    (advice,) = results.advice
    assert advice.upcoming_eox == (
        _item(
            name=MODEL,
            last_date_of_support=FUTURE,
            end_of_sale=FUTURE,
            replacement="C9300X-48H",
        ),
        _item(kind=EoxKind.SOFTWARE, name=RELEASE, end_of_sw_maintenance=FUTURE),
    )


def test_an_eox_date_of_today_counts_as_passed_and_is_not_upcoming() -> None:
    """A milestone dated today has passed, so it raises its Finding and adds no advice (#150).

    Counting it as neither used to lose it from both surfaces.
    """
    today = AS_OF.date().isoformat()
    record = _device(A, "S1", "sw-a")
    results = _results(
        record,
        inventory=(_inventory("dev-S1", (MODEL, HardwareKind.CHASSIS)),),
        hardware=(
            _hardware(
                MODEL,
                _item(
                    name=MODEL,
                    last_date_of_support=today,
                    end_of_sale=today,
                ),
            ),
        ),
        software=(
            _software(
                RELEASE,
                _item(
                    kind=EoxKind.SOFTWARE,
                    name=RELEASE,
                    end_of_sw_maintenance=today,
                ),
            ),
        ),
    )

    hardware_finding = next(
        finding
        for finding in _lifecycle(results, "lifecycle-hardware-eox")
        if finding.devices == ("dev-S1",)
    )
    software_finding = next(
        finding
        for finding in _lifecycle(results, "lifecycle-software-eox")
        if finding.devices == ("dev-S1",)
    )
    assert hardware_finding.level is FindingLevel.HIGH
    assert today in hardware_finding.what_was_found
    assert software_finding.level is FindingLevel.MEDIUM
    (advice,) = results.advice
    assert advice.upcoming_eox == ()


def test_upcoming_eox_rides_the_analysis_record_in_topology_json() -> None:
    record = _device(A, "S1", "sw-a")
    built = topology.build((record,))
    results = analysis.analyse(
        AnalysisInput(
            topology=built,
            inventory=(_inventory("dev-S1", (MODEL, HardwareKind.CHASSIS)),),
            answers=CiscoAnswers(
                advisories=_NOT_ASKED,
                eox=(
                    EoxAnswers(
                        hardware=(_hardware(MODEL, _item(last_date_of_support=FUTURE)),),
                    ),
                ),
                suggestions=_NOT_ASKED,
            ),
            as_of=AS_OF,
        )
    )

    document: Any = topology.to_document(
        replace(built, findings=results.findings, analysis=results.summary)
    )

    advice = document["analysis"]["advice"]
    assert isinstance(advice, list)
    upcoming = advice[0]["upcoming_eox"]
    assert isinstance(upcoming, list)
    assert upcoming[0]["kind"] == "hardware"
    assert upcoming[0]["name"] == MODEL
    assert upcoming[0]["last_date_of_support"] == FUTURE


def test_software_eox_levels_by_release() -> None:
    vulnerability = _device(A, "S1", "sw-a", release=RELEASE)
    maintenance = _device(B, "S2", "sw-b", release="17.12.1")
    results = _results(
        vulnerability,
        maintenance,
        software=(
            _software(
                RELEASE,
                _item(
                    kind=EoxKind.SOFTWARE,
                    name=RELEASE,
                    end_of_security_support=PAST,
                ),
            ),
            _software(
                "17.12.1",
                _item(
                    kind=EoxKind.SOFTWARE,
                    name="17.12.1",
                    end_of_sw_maintenance=PAST,
                ),
            ),
        ),
    )

    findings = _lifecycle(results, "lifecycle-software-eox")

    assert {finding.devices[0]: finding.level for finding in findings} == {
        "dev-S1": FindingLevel.HIGH,
        "dev-S2": FindingLevel.MEDIUM,
    }
    for finding in findings:
        assert finding.check.name == "Software EoX"
        assert finding.source == "Cisco EoX"
        assert isinstance(finding.cisco_detail, EoxDetail)
        assert finding.cisco_detail.items[0].kind is EoxKind.SOFTWARE


def test_software_eox_never_invents_a_level_from_a_date_story_75_does_not_name() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(
        record,
        software=(
            _software(
                RELEASE,
                _item(
                    kind=EoxKind.SOFTWARE,
                    name=RELEASE,
                    last_date_of_support=PAST,
                    end_of_sale=PAST,
                ),
            ),
        ),
    )

    assert _lifecycle(results, "lifecycle-software-eox") == []


def test_the_eox_item_kind_separates_the_hardware_and_software_checks() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(
        record,
        inventory=(_inventory("dev-S1", (MODEL, HardwareKind.CHASSIS)),),
        hardware=(
            _hardware(
                MODEL,
                _item(kind=EoxKind.SOFTWARE, name=MODEL, last_date_of_support=PAST),
            ),
        ),
        software=(
            _software(
                RELEASE,
                _item(kind=EoxKind.HARDWARE, name=RELEASE, last_date_of_support=PAST),
            ),
        ),
    )

    assert _lifecycle(results) == []


def test_hardware_eox_checks_only_the_pids_show_inventory_gave() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(
        record,
        inventory=(_inventory("dev-S1", ("C9300-NM-8X", HardwareKind.LINE_CARD)),),
        hardware=(_hardware(MODEL, _item(name=MODEL, last_date_of_support=PAST)),),
    )

    assert _lifecycle(results, "lifecycle-hardware-eox") == []


def test_a_release_that_is_not_suggested_raises_one_low_finding() -> None:
    record = _device(A, "S1", "sw-a", release=RELEASE)
    results = _results(
        record,
        suggestions=(SuggestedReleases(pid=MODEL, releases=("17.9.10", "17.12.4")),),
    )

    (finding,) = _lifecycle(results, "lifecycle-suggested-release")

    assert finding.level is FindingLevel.LOW
    assert finding.devices == ("dev-S1",)
    assert finding.check.name == "Suggested Release"
    assert finding.check.type is CheckType.LIFECYCLE
    assert finding.source == "Cisco Software Suggestion"
    assert RELEASE in finding.what_was_found
    assert "17.9.10" in finding.what_was_found
    assert "17.12.4" in finding.what_was_found
    assert finding.cisco_detail is None


def test_a_suggested_release_raises_nothing_and_normalises_before_comparing() -> None:
    suggested = _device(A, "S1", "sw-a", release="17.9.10")
    zero_padded = _device(B, "S2", "sw-b", release="17.09.10")
    results = _results(
        suggested,
        zero_padded,
        suggestions=(SuggestedReleases(pid=MODEL, releases=("17.9.10", "17.12.4")),),
    )

    assert _lifecycle(results, "lifecycle-suggested-release") == []


def test_suggested_release_could_not_check_when_cisco_returns_nothing_for_the_pid() -> None:
    empty = _device(A, "S1", "sw-a", release=RELEASE)
    absent = _device(B, "S2", "sw-b", model="C9500-48Y4C", release="17.12.1")
    results = _results(
        empty,
        absent,
        suggestions=(SuggestedReleases(pid=MODEL),),
    )

    findings = _lifecycle(results, "lifecycle-suggested-release")

    assert [finding.devices for finding in findings] == [("dev-S1",), ("dev-S2",)]
    for finding in findings:
        assert finding.level is FindingLevel.LOW
        assert "Could not check" in finding.what_was_found
    assert MODEL in findings[0].what_was_found
    assert "C9500-48Y4C" in findings[1].what_was_found


def test_an_unavailable_eox_source_skips_both_eox_checks_and_raises_nothing() -> None:
    reason = "Cisco EoX could not be reached"
    results = _results(_device(A, "S1", "sw-a"), eox=SourceUnavailable(reason))

    runs = {run.check.id: run for run in results.checks}
    assert runs["lifecycle-hardware-eox"].ran is False
    assert runs["lifecycle-hardware-eox"].reason == reason
    assert runs["lifecycle-software-eox"].ran is False
    assert runs["lifecycle-software-eox"].reason == reason
    assert _lifecycle(results) == []
    (advice,) = results.advice
    assert advice.upcoming_eox == ()


def test_an_unavailable_suggestion_source_skips_the_suggested_release_check() -> None:
    reason = "Software Suggestion could not be reached"
    results = _results(
        _device(A, "S1", "sw-a"),
        suggestions=SourceUnavailable(reason),
    )

    runs = {run.check.id: run for run in results.checks}
    assert runs["lifecycle-suggested-release"].ran is False
    assert runs["lifecycle-suggested-release"].reason == reason
    assert _lifecycle(results, "lifecycle-suggested-release") == []


def test_a_config_canary_never_reaches_a_lifecycle_finding() -> None:
    record = _device(A, "S1", "sw-a")
    built = topology.build((record,))
    facts = ConfigFacts("dev-S1", (ConfigFact(name="telnet", value=CANARY),))
    results = analysis.analyse(
        AnalysisInput(
            topology=built,
            config_facts=(facts,),
            inventory=(_inventory("dev-S1", (MODEL, HardwareKind.CHASSIS)),),
            answers=CiscoAnswers(
                advisories=_NOT_ASKED,
                eox=(
                    EoxAnswers(
                        hardware=(
                            _hardware(
                                MODEL,
                                _item(last_date_of_support=PAST, replacement="C9300X-48H"),
                            ),
                        ),
                    ),
                ),
                suggestions=(SuggestedReleases(pid=MODEL, releases=("17.9.10",)),),
            ),
            as_of=AS_OF,
        )
    )

    findings = _lifecycle(results)
    assert findings
    texts = "\n".join(
        part
        for finding in findings
        for part in (finding.what_was_found, finding.what_to_do, finding.summary)
    )
    assert CANARY not in texts
    document = topology.to_document(
        replace(built, findings=results.findings, analysis=results.summary)
    )
    assert CANARY not in json.dumps(document)


def test_a_pid_refused_by_the_safe_pattern_gives_its_device_a_could_not_check() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(
        record,
        inventory=(_inventory("dev-S1", ("C9300 48P", HardwareKind.CHASSIS)),),
    )

    (finding,) = _lifecycle(results, "lifecycle-hardware-eox-could-not-check")

    assert finding.level is FindingLevel.LOW
    assert finding.devices == ("dev-S1",)
    assert finding.check.name == "Hardware EoX could not check"
    assert finding.check.type is CheckType.LIFECYCLE
    assert finding.source == "Cisco EoX"
    assert "C9300 48P" in finding.what_was_found
    assert "does not match the safe pattern" in finding.what_was_found
    assert finding.what_was_found == finding.summary
    assert finding.cisco_detail is None


def test_a_pid_cisco_has_no_record_for_gives_its_device_a_could_not_check() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(
        record,
        inventory=(_inventory("dev-S1", (MODEL, HardwareKind.CHASSIS)),),
        hardware=(HardwareEox(MODEL, unanswered="SSA_ERR_026"),),
    )

    (finding,) = _lifecycle(results, "lifecycle-hardware-eox-could-not-check")

    assert finding.level is FindingLevel.LOW
    assert MODEL in finding.what_was_found
    assert "SSA_ERR_026" in finding.what_was_found
    assert _lifecycle(results, "lifecycle-hardware-eox") == []


def test_a_pid_cisco_was_not_asked_about_gives_its_device_a_could_not_check() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(
        record,
        inventory=(_inventory("dev-S1", (MODEL, HardwareKind.CHASSIS)),),
    )

    (finding,) = _lifecycle(results, "lifecycle-hardware-eox-could-not-check")

    assert finding.level is FindingLevel.LOW
    assert "no answer for PID" in finding.what_was_found


def test_a_pid_cisco_answered_with_no_eox_dates_is_not_a_could_not_check() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(
        record,
        inventory=(_inventory("dev-S1", (MODEL, HardwareKind.CHASSIS)),),
        hardware=(_hardware(MODEL),),
    )

    assert _lifecycle(results, "lifecycle-hardware-eox-could-not-check") == []


def test_one_unchecked_pid_beside_a_passed_date_raises_both_findings() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(
        record,
        inventory=(
            _inventory(
                "dev-S1",
                (MODEL, HardwareKind.CHASSIS),
                ("C9300-NM-8X", HardwareKind.LINE_CARD),
            ),
        ),
        hardware=(
            _hardware(MODEL, _item(end_of_sale=PAST)),
            HardwareEox("C9300-NM-8X", unanswered="SSA_ERR_026"),
        ),
    )

    (passed,) = _lifecycle(results, "lifecycle-hardware-eox")
    (gap,) = _lifecycle(results, "lifecycle-hardware-eox-could-not-check")

    assert passed.level is FindingLevel.LOW
    assert gap.level is FindingLevel.LOW
    assert gap.devices == ("dev-S1",)
    assert "C9300-NM-8X" in gap.what_was_found
    assert MODEL not in gap.what_was_found


def test_a_release_cisco_has_no_record_for_gives_its_device_a_could_not_check() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(
        record,
        software=(SoftwareEox(RELEASE, unanswered="SSA_ERR_026"),),
    )

    (finding,) = _lifecycle(results, "lifecycle-software-eox-could-not-check")

    assert finding.level is FindingLevel.LOW
    assert finding.devices == ("dev-S1",)
    assert finding.check.name == "Software EoX could not check"
    assert RELEASE in finding.what_was_found
    assert "SSA_ERR_026" in finding.what_was_found
    assert _lifecycle(results, "lifecycle-software-eox") == []


def test_a_release_whose_family_is_not_asked_about_gives_a_could_not_check() -> None:
    record = _device(A, "S1", "sw-a", release="14.2(4i)")
    results = _results(record)

    (finding,) = _lifecycle(results, "lifecycle-software-eox-could-not-check")

    assert finding.level is FindingLevel.LOW
    assert "OS family" in finding.what_was_found


def test_an_unreadable_release_gives_a_could_not_check() -> None:
    record = _device(A, "S1", "sw-a", release="")
    results = _results(record)

    (finding,) = _lifecycle(results, "lifecycle-software-eox-could-not-check")

    assert "release is not readable" in finding.what_was_found


def test_a_release_cisco_answered_with_no_eox_dates_is_not_a_could_not_check() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(record, software=(_software(RELEASE),))

    assert _lifecycle(results, "lifecycle-software-eox-could-not-check") == []


def test_an_unavailable_eox_source_skips_the_could_not_check_checks_too() -> None:
    reason = "Cisco EoX could not be reached"
    results = _results(
        _device(A, "S1", "sw-a"),
        inventory=(_inventory("dev-S1", (MODEL, HardwareKind.CHASSIS)),),
        eox=SourceUnavailable(reason),
    )

    runs = {run.check.id: run for run in results.checks}
    assert runs["lifecycle-hardware-eox-could-not-check"].ran is False
    assert runs["lifecycle-hardware-eox-could-not-check"].reason == reason
    assert runs["lifecycle-software-eox-could-not-check"].ran is False
    assert runs["lifecycle-software-eox-could-not-check"].reason == reason
    assert _lifecycle(results) == []


def test_lifecycle_findings_are_sorted_worst_first() -> None:
    record = _device(A, "S1", "sw-a", release=RELEASE)
    results = _results(
        record,
        inventory=(_inventory("dev-S1", (MODEL, HardwareKind.CHASSIS)),),
        hardware=(_hardware(MODEL, _item(end_of_sale=PAST)),),
        software=(
            _software(
                RELEASE,
                _item(
                    kind=EoxKind.SOFTWARE,
                    name=RELEASE,
                    end_of_sw_maintenance=ALSO_PAST,
                ),
            ),
        ),
        suggestions=(SuggestedReleases(pid=MODEL, releases=("17.9.10",)),),
    )

    findings = _lifecycle(results)

    assert [finding.level for finding in findings] == [
        FindingLevel.MEDIUM,
        FindingLevel.LOW,
        FindingLevel.LOW,
    ]
    assert [finding.order for finding in results.findings] == sorted(
        finding.order for finding in results.findings
    )
