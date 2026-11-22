"""The bridge from Analysis's questions to `advisories`, and Cisco's answers back (#104)."""

from dataclasses import replace

from network_analyser import topology
from network_analyser.advisories.replies import NOT_UNDERSTOOD
from network_analyser.cli import run_analysis
from network_analyser.records import Platform
from network_analyser.records.analysis import (
    AdvisoryPlatform,
    AnalysisInput,
    FixedRelease,
    OsType,
    SourceUnavailable,
)
from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoAdvisory,
    CiscoAnswers,
    CiscoCallTally,
    CiscoEndpoint,
    CiscoOsType,
    CiscoPlatform,
    CompatibleAnswer,
    CompatibleAnswers,
    EndpointUse,
    EoxAnswer,
    EoxRecord,
    EoxUnanswered,
    LookupQuestions,
    ReleaseQuestion,
    SuggestedRelease,
    SuggestionAnswer,
    SuggestionsAnswer,
    TokenOutcome,
    TokenResult,
)
from network_analyser.records.cisco import (
    CompatibleRelease as CiscoCompatibleRelease,
)
from network_analyser.records.cisco import (
    SourceUnavailable as CiscoUnavailable,
)
from network_analyser.records.topology import (
    AdvisoryOutcomeKind,
    EoxKind,
    FindingLevel,
    Topology,
)
from tests.support.analysis_records import collected_of
from tests.support.topology_records import chassis_inventory, visited


def _built() -> Topology:
    return topology.build([visited("192.0.2.1", "TEST0000A01")])


def _asked() -> LookupQuestions:
    return run_analysis.lookup_questions(AnalysisInput(topology=_built()))


def _eox(*, input_type: str) -> EoxRecord:
    return EoxRecord(
        input_value="C9300-48P" if input_type == "PID" else "17.9.4",
        input_type=input_type,
        product_id="C9300-48P" if input_type == "PID" else "17.9.4",
        description="Synthetic",
        bulletin="EOL-SYNTHETIC-1",
        bulletin_url="https://cisco.example/bulletin",
        end_of_sale="2025-01-01",
        end_of_sw_maintenance="2025-06-01",
        end_of_security_vul_support="2026-01-01",
        last_date_of_support="2027-01-01",
        migration_product_id="C9300-48P",
        migration_url="https://cisco.example/upgrade",
    )


def _replies() -> CiscoAnswers:
    question = ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4")
    return CiscoAnswers(
        advisories=(
            AdvisoriesAnswer(
                question,
                (
                    CiscoAdvisory(
                        advisory_id="cisco-sa-test-104",
                        title="Synthetic advisory",
                        sir="High",
                        cvss_base_score=8.6,
                        cves=("CVE-2026-0001",),
                        first_published="2026-01-01T00:00:00",
                        last_updated="2026-02-01T00:00:00",
                        first_fixed=("17.9.5", "17.12.2"),
                    ),
                ),
            ),
        ),
        hardware_eox=EoxAnswer(records=(_eox(input_type="PID"),), unanswered=()),
        software_eox=EoxAnswer(records=(_eox(input_type="Software"),), unanswered=()),
        suggestions=SuggestionsAnswer(
            answers=(
                SuggestionAnswer(
                    "C9300-48P",
                    "Synthetic product",
                    (
                        SuggestedRelease("17.9.5", suggested=True, release_date=None, train="17.9"),
                        SuggestedRelease(
                            "17.9.6", suggested=False, release_date=None, train="17.9"
                        ),
                    ),
                ),
            ),
            unanswered=(),
        ),
        compatible=CompatibleAnswers(
            answers=(
                CompatibleAnswer(
                    "C9300-48P",
                    (
                        CiscoCompatibleRelease(
                            "17.12.8", suggested=False, train="17.12", lifecycle="MD"
                        ),
                        CiscoCompatibleRelease(
                            "26.2.1", suggested=False, train="26.2", lifecycle="ED"
                        ),
                    ),
                ),
            ),
            unanswered=(),
        ),
        tally=CiscoCallTally(
            token=TokenResult(TokenOutcome.OK),
            endpoints=tuple(
                EndpointUse(endpoint=endpoint, calls=1, values=1, retries=0)
                for endpoint in CiscoEndpoint
            ),
        ),
    )


def _answered(question: ReleaseQuestion) -> AdvisoriesAnswer:
    """The synthetic Advisory, re-asked for another release, so a reply keeps its shape."""
    reply = _replies().advisories[0]
    assert isinstance(reply, AdvisoriesAnswer)
    return AdvisoriesAnswer(question, reply.advisories)


def test_the_questions_are_only_de_duplicated_pids_and_releases() -> None:
    asked = _asked()

    assert asked.releases == (ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4"),)
    assert asked.hardware_pids == ("C9300-48P",)
    assert asked.software_releases == ("17.9.4",)
    assert asked.suggestion_pids == ("C9300-48P",)
    assert asked.compatible_pids == ("C9300-48P",)


def test_advisories_become_analysis_answers_with_cisco_s_detail() -> None:
    asked = _asked()
    replies = _replies()

    answers = run_analysis.analysis_answers(replies, asked)

    assert isinstance(answers.advisories, tuple)
    (release,) = answers.advisories
    assert release.os_type is OsType.IOS_XE
    assert release.release == "17.9.4"
    assert release.hardware_family is None
    (advisory,) = release.advisories
    assert advisory.detail.id == "cisco-sa-test-104"
    assert advisory.detail.sir is FindingLevel.HIGH
    assert advisory.detail.cvss == "8.6"
    assert advisory.detail.cves == ("CVE-2026-0001",)
    assert advisory.detail.first_fixed == "17.9.5"
    assert advisory.first_fixed == (
        FixedRelease("17.9", "17.9.5"),
        FixedRelease("17.12", "17.12.2"),
    )


def test_a_503_on_one_release_leaves_the_other_releases_answered() -> None:
    second = ReleaseQuestion(CiscoOsType.IOS_XE, "17.12.1")
    asked = replace(_asked(), releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4"), second))
    replies = replace(
        _replies(),
        advisories=(
            CiscoUnavailable("Cisco returned HTTP 503"),
            _answered(second),
        ),
    )

    answers = run_analysis.analysis_answers(replies, asked)

    assert isinstance(answers.advisories, tuple)
    failed, good = answers.advisories
    assert (failed.release, failed.advisories, failed.unavailable) == (
        "17.9.4",
        (),
        "Cisco returned HTTP 503",
    )
    assert good.release == "17.12.1"
    assert good.unavailable is None
    assert len(good.advisories) == 1


def test_an_unreadable_200_on_one_release_leaves_the_other_releases_answered() -> None:
    second = ReleaseQuestion(CiscoOsType.IOS_XE, "17.12.1")
    asked = replace(_asked(), releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4"), second))
    replies = replace(
        _replies(),
        advisories=(
            CiscoUnavailable(NOT_UNDERSTOOD),
            _answered(second),
        ),
    )

    answers = run_analysis.analysis_answers(replies, asked)

    assert isinstance(answers.advisories, tuple)
    failed, good = answers.advisories
    assert (failed.release, failed.advisories, failed.unavailable) == (
        "17.9.4",
        (),
        NOT_UNDERSTOOD,
    )
    assert good.release == "17.12.1"
    assert good.unavailable is None
    assert len(good.advisories) == 1


def test_every_release_failing_still_collapses_the_source() -> None:
    second = ReleaseQuestion(CiscoOsType.IOS_XE, "17.12.1")
    asked = replace(_asked(), releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4"), second))
    replies = replace(
        _replies(),
        advisories=(
            CiscoUnavailable("Cisco returned HTTP 503"),
            CiscoUnavailable("Cisco returned HTTP 503"),
        ),
    )

    answers = run_analysis.analysis_answers(replies, asked)

    assert answers.advisories == SourceUnavailable("Cisco returned HTTP 503")


def test_a_rejected_key_still_collapses_the_source_with_every_release() -> None:
    second = ReleaseQuestion(CiscoOsType.IOS_XE, "17.12.1")
    asked = replace(_asked(), releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4"), second))
    replies = replace(
        _replies(),
        advisories=(
            AdvisoriesAnswer(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4"), ()),
            CiscoUnavailable("Cisco rejected the API key"),
        ),
    )

    answers = run_analysis.analysis_answers(replies, asked)

    assert answers.advisories == SourceUnavailable("Cisco rejected the API key")


def test_a_device_whose_own_release_had_a_503_reads_could_not_check() -> None:
    first = visited("192.0.2.1", "TEST0000A01", hostname="sw-a")
    second_record = visited("192.0.2.2", "TEST0000A02", hostname="sw-b")
    version = second_record.version
    assert version is not None
    second = replace(second_record, version=replace(version, software_version="17.12.1"))
    built = topology.build([first, second])
    asked = run_analysis.lookup_questions(AnalysisInput(topology=built))
    replies = replace(
        _replies(),
        advisories=tuple(
            CiscoUnavailable("Cisco returned HTTP 503")
            if question.release == "17.12.1"
            else _answered(question)
            for question in asked.releases
        ),
    )

    answers = run_analysis.analysis_answers(replies, asked)
    results = run_analysis.analysed(built, answers)
    advice = {item.device: item.advisory_outcome for item in results.advice}
    ids = {device.management_ip: device.id for device in built.devices}

    assert advice[ids[first.ip]].kind is AdvisoryOutcomeKind.MATCHES
    assert advice[ids[second.ip]].kind is AdvisoryOutcomeKind.COULD_NOT_CHECK


def test_one_release_cisco_does_not_know_leaves_the_other_releases_answered() -> None:
    unknown = ReleaseQuestion(CiscoOsType.IOS_XE, "17.99.1")
    replies = _replies()
    replies = replace(
        replies,
        advisories=(
            AdvisoriesAnswer(unknown, (), unavailable="INVALID_IOS_VERSION"),
            *replies.advisories,
        ),
    )

    answers = run_analysis.analysis_answers(replies, _asked())

    assert isinstance(answers.advisories, tuple)
    bad, good = answers.advisories
    assert (bad.release, bad.advisories, bad.unavailable) == ("17.99.1", (), "INVALID_IOS_VERSION")
    assert good.unavailable is None
    assert len(good.advisories) == 1


def test_eox_becomes_one_answer_per_pid_and_per_release_asked() -> None:
    answers = run_analysis.analysis_answers(_replies(), _asked())

    assert isinstance(answers.eox, tuple)
    (eox,) = answers.eox
    (hardware,) = eox.hardware
    (software,) = eox.software
    assert hardware.pid == "C9300-48P"
    assert hardware.items[0].kind is EoxKind.HARDWARE
    assert hardware.items[0].last_date_of_support == "2027-01-01"
    assert software.release == "17.9.4"
    assert software.items[0].kind is EoxKind.SOFTWARE


def test_an_eox_no_record_becomes_that_pids_unanswered_reason() -> None:
    replies = replace(
        _replies(),
        hardware_eox=EoxAnswer(
            records=(_eox(input_type="PID"),),
            unanswered=(EoxUnanswered("C9300-24P", "SSA_ERR_026"),),
        ),
    )
    asked = replace(_asked(), hardware_pids=("C9300-48P", "C9300-24P"))

    answers = run_analysis.analysis_answers(replies, asked)

    assert isinstance(answers.eox, tuple)
    (eox,) = answers.eox
    assert [(item.pid, item.unanswered) for item in eox.hardware] == [
        ("C9300-48P", None),
        ("C9300-24P", "SSA_ERR_026"),
    ]


def test_an_eox_value_outside_the_safe_pattern_is_marked_not_sent() -> None:
    asked = replace(_asked(), hardware_pids=("C9300 48P",))

    answers = run_analysis.analysis_answers(_replies(), asked)

    assert isinstance(answers.eox, tuple)
    (eox,) = answers.eox
    (hardware,) = eox.hardware
    assert hardware.pid == "C9300 48P"
    assert hardware.items == ()
    assert hardware.unanswered is not None
    assert "safe pattern" in hardware.unanswered


def test_a_software_release_no_record_becomes_that_release_s_unanswered_reason() -> None:
    replies = replace(
        _replies(),
        software_eox=EoxAnswer(
            records=(_eox(input_type="Software"),),
            unanswered=(EoxUnanswered("17.12.1", "SSA_ERR_026"),),
        ),
    )
    asked = replace(_asked(), software_releases=("17.9.4", "17.12.1"))

    answers = run_analysis.analysis_answers(replies, asked)

    assert isinstance(answers.eox, tuple)
    (eox,) = answers.eox
    assert [(item.release, item.unanswered) for item in eox.software] == [
        ("17.9.4", None),
        ("17.12.1", "SSA_ERR_026"),
    ]


def test_suggestions_keep_only_the_releases_cisco_suggests() -> None:
    answers = run_analysis.analysis_answers(_replies(), _asked())

    assert isinstance(answers.suggestions, tuple)
    (suggested,) = answers.suggestions
    assert suggested.pid == "C9300-48P"
    assert suggested.releases == ("17.9.5",)


def test_compatible_releases_carry_each_lifecycle_code() -> None:
    answers = run_analysis.analysis_answers(_replies(), _asked())

    assert isinstance(answers.compatible, tuple)
    (compatible,) = answers.compatible
    assert compatible.pid == "C9300-48P"
    assert [(item.release, item.lifecycle) for item in compatible.releases] == [
        ("17.12.8", "MD"),
        ("26.2.1", "ED"),
    ]
    assert compatible.unanswered is None


def test_a_source_unavailable_stays_unavailable_and_has_no_answers() -> None:
    asked = _asked()
    missing = CiscoUnavailable("Cisco could not be reached")
    replies = CiscoAnswers(
        advisories=(CiscoUnavailable("Cisco could not be reached"),),
        hardware_eox=missing,
        software_eox=missing,
        suggestions=missing,
        compatible=missing,
        tally=_replies().tally,
    )

    answers = run_analysis.analysis_answers(replies, asked)

    assert isinstance(answers.advisories, SourceUnavailable)
    assert isinstance(answers.eox, SourceUnavailable)
    assert isinstance(answers.suggestions, SourceUnavailable)
    assert isinstance(answers.compatible, SourceUnavailable)


def test_an_nxos_release_is_not_sent_without_its_hardware_family() -> None:
    nxos = topology.build([visited("192.0.2.1", "TEST0000A01", platform=Platform.NX_OS)])

    asked = run_analysis.lookup_questions(AnalysisInput(topology=nxos))

    assert all(question.os_type is not CiscoOsType.NX_OS for question in asked.releases)


def test_an_nxos_release_is_sent_with_the_hardware_family_it_was_matched_on() -> None:
    record = visited(
        "192.0.2.1",
        "TEST0000A01",
        platform=Platform.NX_OS,
        inventory=chassis_inventory("N9K-C93180YC-FX"),
    )
    version = record.version
    assert version is not None
    record = replace(
        record, version=replace(version, model="C93180YC-FX", software_version="9.3(10)")
    )
    nxos = topology.build([record])

    asked = run_analysis.lookup_questions(
        AnalysisInput(topology=nxos, collected=collected_of(record))
    )

    expected = ReleaseQuestion(CiscoOsType.NX_OS, "9.3(10)", "NEXUS9000")
    assert asked.releases == (expected,)
    answers = run_analysis.analysis_answers(
        replace(_replies(), advisories=(AdvisoriesAnswer(expected, ()),)), asked
    )
    assert isinstance(answers.advisories, tuple)
    assert answers.advisories[0].hardware_family == "NEXUS9000"


def test_an_nxos_i_series_release_keeps_its_own_train() -> None:
    question = ReleaseQuestion(CiscoOsType.NX_OS, "7.0(3)I7(9)", "NEXUS9000")
    advisory = CiscoAdvisory(
        advisory_id="cisco-sa-test-123",
        title="Synthetic advisory",
        sir="High",
        cvss_base_score=8.6,
        cves=("CVE-2026-0001",),
        first_published="2026-01-01T00:00:00",
        last_updated="2026-02-01T00:00:00",
        first_fixed=(),
        platforms=(
            CiscoPlatform(
                name="Cisco Nexus 9000 Series Switches",
                first_fixed=("7.0(3)I7(10)",),
            ),
        ),
    )
    asked = LookupQuestions(
        releases=(question,),
        hardware_pids=(),
        software_releases=(),
        suggestion_pids=(),
    )
    replies = replace(_replies(), advisories=(AdvisoriesAnswer(question, (advisory,)),))

    answers = run_analysis.analysis_answers(replies, asked)

    assert isinstance(answers.advisories, tuple)
    (release,) = answers.advisories
    assert release.advisories[0].first_fixed == ()
    assert release.advisories[0].platforms == (
        AdvisoryPlatform(
            name="Cisco Nexus 9000 Series Switches",
            first_fixed=(FixedRelease("7.0I7", "7.0(3)I7(10)"),),
        ),
    )
