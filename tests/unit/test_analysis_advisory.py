"""The Advisory Check at Seam 1: synthetic Cisco answers in, Findings and advice out (#105).

Driven through `analysis.analyse` and `analysis.lookup_questions` only. Every answer is
hand-written synthetic data; no real Cisco reply, device output or advisory text is here.
"""

from collections.abc import Iterable
from dataclasses import replace

from network_analyser import analysis, topology
from network_analyser.records.analysis import (
    AdvisoryAnswer,
    AnalysisInput,
    CiscoAnswers,
    CompatibleRelease,
    CompatibleReleases,
    FixedRelease,
    OsType,
    ReleaseAdvisories,
    SourceUnavailable,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.platform import Platform
from network_analyser.records.topology import (
    ADVISORY_FIXED_LINE,
    ADVISORY_STATUS,
    AdvisoryDetail,
    AdvisoryOutcomeKind,
    AnalysisResults,
    CheckType,
    CiscoDetailKind,
    Finding,
    FindingLevel,
)
from network_analyser.records.unknown import Unknown
from tests.support.analysis_records import collected_of
from tests.support.topology_records import chassis_inventory, visited

A = "192.0.2.1"
B = "192.0.2.2"
C = "192.0.2.3"
MODEL = "C9300-48P"
NEXUS_MODEL = "C93180YC-FX"
NEXUS_CHASSIS = "N9K-C93180YC-FX"
ADVISORY = "cisco-sa-example-abc123"


def _device(  # noqa: PLR0913 (every device field the Check reads, by name)
    address: str,
    serial: str,
    hostname: str,
    *,
    platform: Platform | None = Platform.IOS_XE,
    model: str | Unknown = MODEL,
    release: str | Unknown = "17.9.4a",
    chassis: str | None = None,
) -> DeviceRecord:
    inventory = chassis_inventory(chassis) if chassis is not None else None
    record = visited(address, serial, hostname, inventory=inventory)
    version = record.version
    assert version is not None
    return replace(
        record,
        platform=platform,
        version=replace(version, model=model, software_version=release),
    )


def _advisory(  # noqa: PLR0913 (every Cisco field the Check reads, by name)
    ident: str = ADVISORY,
    *,
    sir: FindingLevel = FindingLevel.HIGH,
    title: str = "Example Advisory",
    cvss: str = "8.1",
    cves: tuple[str, ...] = ("CVE-2026-0001",),
    first_fixed: tuple[FixedRelease, ...] = (FixedRelease("17.9", "17.9.5"),),
) -> AdvisoryAnswer:
    return AdvisoryAnswer(
        detail=AdvisoryDetail(
            kind=CiscoDetailKind.ADVISORY,
            id=ident,
            title=title,
            sir=sir,
            cvss=cvss,
            cves=cves,
            published="2026-11-01",
            updated="2026-11-02",
            first_fixed=None,
        ),
        first_fixed=first_fixed,
    )


def _answer(
    os_type: OsType = OsType.IOS_XE,
    release: str = "17.9.4a",
    *advisories: AdvisoryAnswer,
    hardware_family: str | None = None,
    unavailable: str | None = None,
) -> ReleaseAdvisories:
    return ReleaseAdvisories(
        os_type=os_type,
        release=release,
        advisories=tuple(advisories),
        hardware_family=hardware_family,
        unavailable=unavailable,
    )


def _results(
    *records: DeviceRecord,
    answers: Iterable[ReleaseAdvisories] = (),
    compatible: tuple[CompatibleReleases, ...] | SourceUnavailable = (),
) -> AnalysisResults:
    return analysis.analyse(
        AnalysisInput(
            topology=topology.build(records),
            collected=collected_of(*records),
            answers=CiscoAnswers(advisories=tuple(answers), compatible=compatible),
        )
    )


def _advisory_findings(results: AnalysisResults) -> list[Finding]:
    return [
        finding
        for finding in results.findings
        if finding.check.type is CheckType.ADVISORY
        and finding.check.id != "advisory-could-not-check"
    ]


def _could_not_check(results: AnalysisResults) -> list[Finding]:
    return [
        finding for finding in results.findings if finding.check.id == "advisory-could-not-check"
    ]


def test_a_critical_and_a_high_advisory_each_raise_one_full_finding() -> None:
    critical = _advisory(
        "cisco-sa-critical-0001",
        sir=FindingLevel.CRITICAL,
        title="Critical example",
        cves=("CVE-2026-0001", "CVE-2026-0002"),
    )
    high = _advisory("cisco-sa-high-0002", sir=FindingLevel.HIGH, title="High example")
    results = _results(
        _device(A, "S1", "sw-a"),
        answers=(_answer(OsType.IOS_XE, "17.9.4a", critical, high),),
    )

    findings = sorted(_advisory_findings(results), key=lambda finding: finding.check.id)
    assert [finding.level for finding in findings] == [FindingLevel.CRITICAL, FindingLevel.HIGH]

    first = findings[0]
    assert first.check.id == "advisory-cisco-sa-critical-0001"
    assert first.check.name == "Critical example"
    assert first.check.type is CheckType.ADVISORY
    assert first.devices == ("dev-S1",)
    assert first.items == ()
    assert first.evidence == ()
    assert first.kind is None
    assert first.source == "Cisco openVuln"
    assert isinstance(first.cisco_detail, AdvisoryDetail)
    assert first.cisco_detail.kind is CiscoDetailKind.ADVISORY
    assert first.cisco_detail.id == "cisco-sa-critical-0001"
    assert first.cisco_detail.title == "Critical example"
    assert first.cisco_detail.sir is FindingLevel.CRITICAL
    assert first.cisco_detail.cvss == "8.1"
    assert first.cisco_detail.cves == ("CVE-2026-0001", "CVE-2026-0002")
    assert first.cisco_detail.published == "2026-11-01"
    assert first.cisco_detail.updated == "2026-11-02"
    assert first.cisco_detail.first_fixed == "17.9.5"
    assert first.cisco_detail.status == ADVISORY_STATUS == "Affected release"
    assert first.cisco_detail.fixed_line == ADVISORY_FIXED_LINE
    assert "17.9.4a" in first.what_was_found
    assert "17.9.5" in first.what_was_found
    assert "17.9.5" in first.what_to_do

    (advice,) = results.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.MATCHES
    assert advice.advisory_outcome.matched == 2
    assert advice.advisory_outcome.text == "2 Advisories match"


def test_one_finding_per_advisory_even_though_it_names_many_cves() -> None:
    advisory = _advisory(cves=("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"))
    results = _results(
        _device(A, "S1", "sw-a"), answers=(_answer(OsType.IOS_XE, "17.9.4a", advisory),)
    )

    (finding,) = _advisory_findings(results)

    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert len(finding.cisco_detail.cves) == 3
    assert finding.devices == ("dev-S1",)


def test_medium_and_low_advisories_raise_no_findings() -> None:
    medium = _advisory("cisco-sa-medium-0001", sir=FindingLevel.MEDIUM)
    low = _advisory("cisco-sa-low-0002", sir=FindingLevel.LOW)
    results = _results(
        _device(A, "S1", "sw-a"),
        answers=(_answer(OsType.IOS_XE, "17.9.4a", medium, low),),
    )

    assert _advisory_findings(results) == []
    (advice,) = results.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.NONE
    assert advice.advisory_outcome.text == "no known Critical/High Advisories for release 17.9.4a"
    assert advice.upgrade_target == "no Critical/High Advisories"


def test_an_answered_release_with_no_advisories_says_none_match() -> None:
    results = _results(
        _device(A, "S1", "sw-a"),
        answers=(_answer(OsType.IOS_XE, "17.9.4a"),),
    )

    assert _advisory_findings(results) == []
    assert _could_not_check(results) == []
    (advice,) = results.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.NONE
    assert advice.advisory_outcome.text == "no known Critical/High Advisories for release 17.9.4a"


def test_the_same_advisory_on_two_devices_is_two_findings_with_one_check() -> None:
    results = _results(
        _device(A, "S1", "sw-a"),
        _device(B, "S2", "sw-b"),
        answers=(_answer(OsType.IOS_XE, "17.9.4a", _advisory()),),
    )

    first, second = sorted(_advisory_findings(results), key=lambda finding: finding.devices)
    assert first.check.id == second.check.id == "advisory-cisco-sa-example-abc123"
    assert first.devices == ("dev-S1",)
    assert second.devices == ("dev-S2",)
    assert first.id != second.id


def test_classic_ios_and_ios_xe_answers_are_never_confused() -> None:
    classic = _device(A, "S1", "sw-a", release="15.2(7)E4")
    wrong_family = _results(classic, answers=(_answer(OsType.IOS_XE, "15.2(7)E4", _advisory()),))
    right_family = _results(classic, answers=(_answer(OsType.IOS, "15.2(7)E4", _advisory()),))

    assert _advisory_findings(wrong_family) == []
    (advice,) = wrong_family.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.COULD_NOT_CHECK
    assert _advisory_findings(right_family)[0].devices == ("dev-S1",)


def test_ios_xe_zero_padding_is_stripped_before_lookup_and_matching() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="16.09.01"),
        answers=(_answer(OsType.IOS_XE, "16.9.1", _advisory()),),
    )

    (finding,) = _advisory_findings(results)
    assert finding.devices == ("dev-S1",)

    questions = analysis.lookup_questions(
        AnalysisInput(topology=topology.build((_device(B, "S2", "sw-b", release="16.09.01"),)))
    )
    assert [question.release for question in questions.releases] == ["16.9.1"]


def test_the_nxos_build_suffix_is_dropped_before_lookup_and_matching() -> None:
    results = _results(
        _device(A, "S1", "sw-a", platform=Platform.NX_OS, release="9.3(10) [build 1]"),
        answers=(_answer(OsType.NX_OS, "9.3(10)", _advisory(first_fixed=())),),
    )

    (finding,) = _advisory_findings(results)
    assert finding.devices == ("dev-S1",)


def test_one_question_per_distinct_family_and_normalised_release() -> None:
    questions = analysis.lookup_questions(
        AnalysisInput(
            topology=topology.build(
                (
                    _device(A, "S1", "sw-a", release="16.09.01"),
                    _device(B, "S2", "sw-b", release="16.9.1"),
                    _device(C, "S3", "sw-c", release="15.2(7)E4"),
                )
            )
        )
    )

    assert [(q.os_type, q.release, q.hardware_family) for q in questions.releases] == [
        (OsType.IOS, "15.2(7)E4", None),
        (OsType.IOS_XE, "16.9.1", None),
    ]


def test_a_family_the_table_does_not_hold_is_never_matched() -> None:
    aci = _device(A, "S1", "sw-a", platform=Platform.NX_OS, release="14.2(4i)")
    # An IOS-XE SD-WAN controller release: outside the IOS-XE trains the table holds.
    sdwan_controller = _device(B, "S2", "sw-b", release="20.6.1")
    unknown_platform = _device(C, "S3", "sw-c", platform=None)
    answers = (
        _answer(OsType.NX_OS, "14.2(4i)", _advisory()),
        _answer(OsType.IOS_XE, "20.6.1", _advisory()),
    )

    results = _results(aci, sdwan_controller, unknown_platform, answers=answers)

    assert _advisory_findings(results) == []
    could_not_check = _could_not_check(results)
    assert len(could_not_check) == 3
    assert all(finding.level is FindingLevel.LOW for finding in could_not_check)
    outcomes = {advice.device: advice.advisory_outcome for advice in results.advice}
    assert outcomes["dev-S1"].kind is AdvisoryOutcomeKind.COULD_NOT_CHECK
    assert outcomes["dev-S1"].text == "could not check: NX-OS in ACI mode is not matched"
    assert outcomes["dev-S2"].kind is AdvisoryOutcomeKind.COULD_NOT_CHECK
    assert "family" in (outcomes["dev-S2"].reason or "")
    assert outcomes["dev-S3"].kind is AdvisoryOutcomeKind.COULD_NOT_CHECK
    assert "family" in (outcomes["dev-S3"].reason or "")

    questions = analysis.lookup_questions(
        AnalysisInput(topology=topology.build((aci, sdwan_controller, unknown_platform)))
    )
    assert questions.releases == ()


def test_nxos_is_matched_on_its_nexus_hardware_family() -> None:
    nexus = _device(
        A,
        "S1",
        "sw-a",
        platform=Platform.NX_OS,
        model=NEXUS_MODEL,
        chassis=NEXUS_CHASSIS,
        release="9.3(10)",
    )
    results = _results(
        nexus,
        answers=(
            _answer(
                OsType.NX_OS,
                "9.3(10)",
                _advisory(first_fixed=()),
                hardware_family="NEXUS9000",
            ),
        ),
    )

    (finding,) = _advisory_findings(results)
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.hardware_family_not_confirmed is False
    assert "hardware family not confirmed" not in finding.what_was_found

    questions = analysis.lookup_questions(
        AnalysisInput(topology=topology.build((nexus,)), collected=collected_of(nexus))
    )
    assert [(q.os_type, q.release, q.hardware_family) for q in questions.releases] == [
        (OsType.NX_OS, "9.3(10)", "NEXUS9000")
    ]


def test_an_unconfirmed_nxos_family_marks_the_finding_and_asks_on_release_alone() -> None:
    results = _results(
        _device(
            A,
            "S1",
            "sw-a",
            platform=Platform.NX_OS,
            model=Unknown("model not found in show version"),
            release="9.3(10)",
        ),
        answers=(_answer(OsType.NX_OS, "9.3(10)", _advisory(first_fixed=())),),
    )

    (finding,) = _advisory_findings(results)
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.hardware_family_not_confirmed is True
    assert "hardware family not confirmed" in finding.what_was_found

    questions = analysis.lookup_questions(
        AnalysisInput(
            topology=topology.build(
                (_device(B, "S2", "sw-b", platform=Platform.NX_OS, release="9.3(10)"),)
            )
        )
    )
    assert [(q.os_type, q.release, q.hardware_family) for q in questions.releases] == [
        (OsType.NX_OS, "9.3(10)", None)
    ]


def test_the_upgrade_target_is_the_highest_fix_within_the_devices_train() -> None:
    lower = _advisory("cisco-sa-lower-0001", first_fixed=(FixedRelease("17.9", "17.9.5"),))
    higher = _advisory("cisco-sa-higher-0002", first_fixed=(FixedRelease("17.9", "17.9.10"),))
    other_train = _advisory("cisco-sa-other-0003", first_fixed=(FixedRelease("17.12", "17.12.4"),))
    results = _results(
        _device(A, "S1", "sw-a", release="17.9.4a"),
        answers=(_answer(OsType.IOS_XE, "17.9.4a", lower, higher, other_train),),
    )

    (advice,) = results.advice
    assert advice.upgrade_target == "17.9.10"
    findings = {finding.cisco_detail.id: finding for finding in _advisory_findings(results)}  # type: ignore[union-attr]
    assert findings["cisco-sa-lower-0001"].cisco_detail.first_fixed == "17.9.5"  # type: ignore[union-attr]
    assert findings["cisco-sa-higher-0002"].cisco_detail.first_fixed == "17.9.10"  # type: ignore[union-attr]
    assert findings["cisco-sa-other-0003"].cisco_detail.first_fixed is None  # type: ignore[union-attr]
    assert "No fix in Train 17.9" in findings["cisco-sa-other-0003"].what_was_found
    assert "17.12.4" not in advice.upgrade_target


def test_no_fix_in_the_devices_train_says_so_and_never_picks_another_train() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.9.4a"),
        answers=(
            _answer(
                OsType.IOS_XE,
                "17.9.4a",
                _advisory(first_fixed=(FixedRelease("17.12", "17.12.4"),)),
            ),
        ),
    )

    (advice,) = results.advice
    assert advice.upgrade_target == "no fix in Train 17.9"
    (finding,) = _advisory_findings(results)
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.first_fixed is None
    assert "17.12.4" not in advice.upgrade_target


def test_the_nxos_upgrade_target_is_not_available_rather_than_guessed() -> None:
    results = _results(
        _device(A, "S1", "sw-a", platform=Platform.NX_OS, release="9.3(10)"),
        answers=(_answer(OsType.NX_OS, "9.3(10)", _advisory(first_fixed=())),),
    )

    (advice,) = results.advice
    assert advice.upgrade_target == "not available"
    (finding,) = _advisory_findings(results)
    assert isinstance(finding.cisco_detail, AdvisoryDetail)
    assert finding.cisco_detail.first_fixed is None


def test_the_latest_release_is_advice_beside_the_target_not_a_finding() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.9.4a"),
        answers=(_answer(OsType.IOS_XE, "17.9.4a", _advisory()),),
        compatible=(
            CompatibleReleases(
                pid=MODEL,
                releases=(
                    CompatibleRelease("17.9.12", "MD"),
                    CompatibleRelease("17.12.6", "ED"),
                ),
            ),
        ),
    )

    (advice,) = results.advice
    assert advice.upgrade_target == "17.9.5"
    assert advice.latest_release_in_train == "17.9.12"
    assert advice.latest_in_train_lifecycle == "MD"
    assert advice.latest_release == "17.12.6"
    assert advice.latest_release_lifecycle == "ED"
    assert all("17.12.6" not in finding.what_was_found for finding in results.findings)
    assert all(finding.check.type is CheckType.ADVISORY for finding in _advisory_findings(results))


def test_latest_release_is_not_available_when_the_compatible_source_gives_none() -> None:
    answered = _results(
        _device(A, "S1", "sw-a", release="17.9.4a"),
        answers=(_answer(OsType.IOS_XE, "17.9.4a", _advisory()),),
        compatible=(CompatibleReleases(pid=MODEL),),
    )
    missing = _results(
        _device(B, "S2", "sw-b", release="17.9.4a"),
        answers=(_answer(OsType.IOS_XE, "17.9.4a", _advisory()),),
        compatible=SourceUnavailable("Software Suggestion could not be reached"),
    )

    for results in (answered, missing):
        (advice,) = results.advice
        assert advice.latest_release_in_train == "not available"
        assert advice.latest_release == "not available"


def test_an_unreadable_version_is_a_low_could_not_check_finding() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release=Unknown("software version not found in show version")),
        answers=(_answer(OsType.IOS_XE, "17.9.4a", _advisory()),),
    )

    (finding,) = _could_not_check(results)
    assert finding.level is FindingLevel.LOW
    assert finding.devices == ("dev-S1",)
    assert finding.check.name == "Advisory could not check"
    assert _advisory_findings(results) == []
    (advice,) = results.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.COULD_NOT_CHECK
    assert advice.advisory_outcome.text.startswith("could not check: the release is unreadable")
    assert advice.upgrade_target == "not available"


def test_show_version_not_read_is_its_own_could_not_check_case() -> None:
    record = _device(A, "S1", "sw-a")
    results = _results(
        replace(record, version=None), answers=(_answer(OsType.IOS_XE, "17.9.4a", _advisory()),)
    )

    (finding,) = _could_not_check(results)
    assert finding.level is FindingLevel.LOW
    (advice,) = results.advice
    assert advice.advisory_outcome.text == "could not check: show version was not read"


def test_an_unknown_family_is_a_low_could_not_check_finding() -> None:
    results = _results(
        _device(A, "S1", "sw-a", platform=None),
        answers=(_answer(OsType.IOS_XE, "17.9.4a", _advisory()),),
    )

    (finding,) = _could_not_check(results)
    assert finding.level is FindingLevel.LOW
    (advice,) = results.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.COULD_NOT_CHECK
    assert "family" in (advice.advisory_outcome.reason or "")


def test_an_unknown_release_from_openvuln_is_a_low_could_not_check_finding() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.99.1"),
        answers=(_answer(OsType.IOS_XE, "17.99.1", unavailable="INVALID_IOS_VERSION"),),
    )

    (finding,) = _could_not_check(results)
    assert finding.level is FindingLevel.LOW
    assert _advisory_findings(results) == []
    (advice,) = results.advice
    assert advice.advisory_outcome.kind is AdvisoryOutcomeKind.COULD_NOT_CHECK
    assert "INVALID_IOS_VERSION" in (advice.advisory_outcome.reason or "")
    assert advice.upgrade_target == "not available"


def test_a_source_unavailable_skips_the_advisory_checks_and_adds_no_findings() -> None:
    reason = "Cisco openVuln could not be reached"
    results = analysis.analyse(
        AnalysisInput(
            topology=topology.build((_device(A, "S1", "sw-a"),)),
            answers=CiscoAnswers.unavailable(reason),
        )
    )

    assert all(finding.check.type is not CheckType.ADVISORY for finding in results.findings)
    runs = {run.check.id: run for run in results.checks}
    assert runs["advisory-openvuln"].ran is False
    assert runs["advisory-openvuln"].reason == reason
    assert runs["advisory-could-not-check"].ran is False
    assert runs["advisory-could-not-check"].reason == reason
    assert runs["consistency-model-drift"].ran is True
    (advice,) = results.advice
    assert advice.advisory_outcome.text == f"could not check: {reason}"
    assert advice.upgrade_target == "not available"


def test_every_advisory_check_runs_when_the_source_answers() -> None:
    results = _results(
        _device(A, "S1", "sw-a"),
        answers=(_answer(OsType.IOS_XE, "17.9.4a", _advisory()),),
    )

    assert [run.check.id for run in results.checks] == [
        "advisory-could-not-check",
        "advisory-openvuln",
        "config-cisco-insecure-list",
        "config-copp-applied",
        "config-device-role-out-of-date",
        "config-guest-shell",
        "config-ntp-synchronised",
        "config-snmpv3-user-crypto",
        "config-ssh-key-size",
        "consistency-bundle-mode",
        "consistency-model-drift",
        "consistency-stack-mismatch",
        "consistency-standard-support-train",
        "consistency-vpc-mismatch",
        "hardening-aaa-central",
        "hardening-aaa-fallback",
        "hardening-brute-force",
        "hardening-enable-secret",
        "hardening-exec-timeout",
        "hardening-fhrp-authentication",
        "hardening-http-server",
        "hardening-icmp",
        "hardening-insecure-mode",
        "hardening-legacy-services",
        "hardening-ntp",
        "hardening-remote-syslog",
        "hardening-routing-authentication",
        "hardening-snmp-v1-v2c",
        "hardening-snmp-v3-priv",
        "hardening-ssh-v2",
        "hardening-strength-check",
        "hardening-telnet",
        "hardening-type-6",
        "hardening-vty-access-class",
        "hardening-weak-secret-types",
        "lifecycle-hardware-eox",
        "lifecycle-software-eox",
        "lifecycle-suggested-release",
    ]
    runs = {run.check.id: run for run in results.checks}
    assert runs["advisory-openvuln"].ran is True
    assert runs["advisory-could-not-check"].ran is True
