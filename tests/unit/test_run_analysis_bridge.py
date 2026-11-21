"""The bridge from Analysis's questions to `advisories`, and Cisco's answers back (#104)."""

from dataclasses import replace

from network_analyser import topology
from network_analyser.cli import run_analysis
from network_analyser.records import Platform
from network_analyser.records.analysis import (
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
    EndpointUse,
    EoxAnswer,
    EoxRecord,
    LookupQuestions,
    ReleaseQuestion,
    SuggestedRelease,
    SuggestionAnswer,
    SuggestionsAnswer,
    TokenOutcome,
    TokenResult,
)
from network_analyser.records.cisco import (
    SourceUnavailable as CiscoUnavailable,
)
from network_analyser.records.topology import EoxKind, FindingLevel, Topology
from tests.support.topology_records import visited


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
        tally=CiscoCallTally(
            token=TokenResult(TokenOutcome.OK),
            endpoints=tuple(
                EndpointUse(endpoint=endpoint, calls=1, values=1, retries=0)
                for endpoint in CiscoEndpoint
            ),
        ),
    )


def test_the_questions_are_only_de_duplicated_pids_and_releases() -> None:
    asked = _asked()

    assert asked.releases == (ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4"),)
    assert asked.hardware_pids == ("C9300-48P",)
    assert asked.software_releases == ("17.9.4",)
    assert asked.suggestion_pids == ("C9300-48P",)


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


def test_suggestions_keep_only_the_releases_cisco_suggests() -> None:
    answers = run_analysis.analysis_answers(_replies(), _asked())

    assert isinstance(answers.suggestions, tuple)
    (suggested,) = answers.suggestions
    assert suggested.pid == "C9300-48P"
    assert suggested.releases == ("17.9.5",)


def test_a_source_unavailable_stays_unavailable_and_has_no_answers() -> None:
    asked = _asked()
    missing = CiscoUnavailable("Cisco could not be reached")
    replies = CiscoAnswers(
        advisories=(CiscoUnavailable("Cisco could not be reached"),),
        hardware_eox=missing,
        software_eox=missing,
        suggestions=missing,
        tally=_replies().tally,
    )

    answers = run_analysis.analysis_answers(replies, asked)

    assert isinstance(answers.advisories, SourceUnavailable)
    assert isinstance(answers.eox, SourceUnavailable)
    assert isinstance(answers.suggestions, SourceUnavailable)


def test_an_nxos_release_is_not_sent_without_its_hardware_family() -> None:
    nxos = topology.build([visited("192.0.2.1", "TEST0000A01", platform=Platform.NX_OS)])

    asked = run_analysis.lookup_questions(AnalysisInput(topology=nxos))

    assert all(question.os_type is not CiscoOsType.NX_OS for question in asked.releases)


def test_an_nxos_release_is_sent_with_the_hardware_family_it_was_matched_on() -> None:
    record = visited("192.0.2.1", "TEST0000A01", platform=Platform.NX_OS)
    version = record.version
    assert version is not None
    nxos = topology.build(
        [
            replace(
                record,
                version=replace(version, model="N9K-C93180YC-FX", software_version="9.3(10)"),
            )
        ]
    )

    asked = run_analysis.lookup_questions(AnalysisInput(topology=nxos))

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
        first_fixed=("7.0(3)I7(10)",),
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
    assert release.advisories[0].first_fixed == (FixedRelease("7.0(3)I7", "7.0(3)I7(10)"),)
