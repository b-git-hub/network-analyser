"""`ask_cisco` against a fake Cisco: token once, batches, pacing, retry, auth split (#95).

The fake records every request and refuses a value that left without its pattern or a request
without the token, so each test also proves the envelope held. All data is synthetic.
"""

from typing import Any

from network_analyser.advisories import Pacer, ask_cisco, check_api_key
from network_analyser.advisories.transport import HttpResponse, TransportFailed
from network_analyser.credentials import Secret, SecretScan
from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoAnswers,
    CiscoEndpoint,
    CiscoOsType,
    EoxAnswer,
    LookupQuestions,
    ReleaseQuestion,
    SourceUnavailable,
    SuggestionsAnswer,
    TokenOutcome,
    TokenResult,
)
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, TOKEN, FakeCisco


def advisory(
    advisory_id: str = "cisco-sa-test-1", *, first_fixed: tuple[str, ...] = ("17.9.5",)
) -> dict[str, Any]:
    return {
        "advisoryId": advisory_id,
        "advisoryTitle": "Synthetic advisory",
        "sir": "High",
        "cvssBaseScore": "8.6",
        "cves": ["CVE-2026-0001"],
        "firstPublished": "2026-01-01T00:00:00",
        "lastUpdated": "2026-02-01T00:00:00",
        "firstFixed": list(first_fixed),
    }


def eox_record(product_id: str) -> dict[str, Any]:
    return {
        "EOLProductID": product_id,
        "ProductIDDescription": "Synthetic switch",
        "ProductBulletinNumber": "EOL-SYNTHETIC-1",
        "LinkToProductBulletinURL": "https://cisco.example/bulletin",
        "EndOfSaleDate": {"value": "2025-01-01"},
        "EndOfSWMaintenanceReleases": {"value": "2025-06-01"},
        "EndOfSecurityVulSupportDate": {"value": "2026-01-01"},
        "LastDateOfSupport": {"value": "2027-01-01"},
        "EOXMigrationDetails": {
            "MigrationProductId": "C9300-48P",
            "MigrationProductInfoURL": "https://cisco.example/upgrade",
        },
        "EOXInputType": "PID",
        "EOXInputValue": product_id,
    }


def suggested(release: str) -> dict[str, Any]:
    return {
        "relDispName": release,
        "isSuggested": "Y",
        "releaseDate": "2026-03-01",
        "trainDispName": "17.9",
    }


def release_question(release: str = "17.9.4a") -> ReleaseQuestion:
    return ReleaseQuestion(CiscoOsType.IOS_XE, release)


def questions(
    *,
    releases: tuple[ReleaseQuestion, ...] | None = None,
    hardware_pids: tuple[str, ...] = (),
    software_releases: tuple[str, ...] = (),
    suggestion_pids: tuple[str, ...] = (),
) -> LookupQuestions:
    return LookupQuestions(
        releases=(release_question(),) if releases is None else releases,
        hardware_pids=hardware_pids,
        software_releases=software_releases,
        suggestion_pids=suggestion_pids,
    )


def pids(count: int) -> tuple[str, ...]:
    return tuple(f"C9300-{index:02d}P" for index in range(count))


def fast_pacer() -> tuple[Pacer, list[float]]:
    """A Pacer that records waits and moves a fake clock instead of sleeping."""
    now = [0.0]
    waits: list[float] = []

    def wait(seconds: float) -> None:
        waits.append(seconds)
        now[0] += seconds

    return Pacer(clock=lambda: now[0], wait=wait), waits


def lookup(
    fake: FakeCisco, asked: LookupQuestions, *, scan: SecretScan | None = None
) -> tuple[CiscoAnswers, list[float]]:
    pacer, waits = fast_pacer()
    answers = ask_cisco(
        asked,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=fake,
        pacer=pacer,
        scan=scan,
    )
    return answers, waits


def uses(answers: CiscoAnswers) -> dict[CiscoEndpoint, Any]:
    return {use.endpoint: use for use in answers.tally.endpoints}


def test_the_token_is_requested_once_however_many_questions_there_are() -> None:
    fake = FakeCisco(
        advisories={
            ("iosxe", "17.9.4a", None): [advisory()],
            ("iosxe", "17.9.5", None): [advisory()],
            ("nxos", "9.3(10)", "NEXUS9000"): [],
        },
        eox_pid={"C9300-48P": eox_record("C9300-48P")},
        suggestions={"C9300-48P": [suggested("17.9.5")]},
    )
    asked = questions(
        releases=(
            release_question(),
            ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.5"),
            ReleaseQuestion(CiscoOsType.NX_OS, "9.3(10)", "NEXUS9000"),
        ),
        hardware_pids=("C9300-48P",),
        suggestion_pids=("C9300-48P",),
    )

    answers, _ = lookup(fake, asked)

    assert fake.token_calls() == 1
    assert answers.tally.token == TokenResult(TokenOutcome.OK, 200)
    assert all("Bearer" not in request.path for request in fake.api_requests())


def test_one_request_per_distinct_question() -> None:
    fake = FakeCisco(
        advisories={
            ("iosxe", "17.9.4a", None): [advisory("cisco-sa-a")],
            ("iosxe", "17.9.5", None): [advisory("cisco-sa-b")],
        },
        eox_pid={"C9300-48P": eox_record("C9300-48P")},
        suggestions={"C9300-48P": [suggested("17.9.5")]},
    )
    asked = questions(
        releases=(
            release_question(),
            release_question(),
            ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.5"),
            release_question(),
        ),
        hardware_pids=("C9300-48P", "C9300-48P"),
        software_releases=("17.9.4a", "17.9.4a"),
        suggestion_pids=("C9300-48P", "C9300-48P"),
    )

    answers, _ = lookup(fake, asked)

    advisory_paths = [path for path in fake.paths() if path.startswith("/security")]
    assert advisory_paths == [
        "/security/advisories/v2/OSType/iosxe?version=17.9.4a",
        "/security/advisories/v2/OSType/iosxe?version=17.9.5",
    ]
    assert len(answers.advisories) == 2
    assert len([path for path in fake.paths() if "/EOXByProductID/" in path]) == 1
    assert len([path for path in fake.paths() if "/EOXBySWReleaseString/" in path]) == 1
    assert len([path for path in fake.paths() if "/productIds/" in path]) == 1


def test_an_nxos_question_sends_the_nexus_family() -> None:
    fake = FakeCisco(advisories={("nxos", "9.3(10)", "NEXUS9000"): [advisory()]})

    answers, _ = lookup(
        fake, questions(releases=(ReleaseQuestion(CiscoOsType.NX_OS, "9.3(10)", "NEXUS9000"),))
    )

    assert fake.paths() == [
        "/oauth2/default/v1/token",
        "/security/advisories/v2/OSType/nxos?version=9.3(10)&platformAlias=NEXUS9000",
    ]
    assert isinstance(answers.advisories[0], AdvisoriesAnswer)
    assert answers.advisories[0].question.platform_alias == "NEXUS9000"


def test_eox_takes_twenty_values_a_call() -> None:
    values = pids(25)
    fake = FakeCisco(eox_pid={value: eox_record(value) for value in values})

    answers, _ = lookup(fake, questions(releases=(), hardware_pids=values))

    paths = [path for path in fake.paths() if "/EOXByProductID/" in path]
    assert len(paths) == 2
    assert len(paths[0].split("/", 7)[-1].split(",")) == 20
    assert len(paths[1].split("/", 7)[-1].split(",")) == 5
    assert uses(answers)[CiscoEndpoint.EOX].values == 25
    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert len(answers.hardware_eox.records) == 25


def test_suggestion_takes_ten_values_a_call() -> None:
    values = pids(11)
    fake = FakeCisco(suggestions={value: [suggested("17.9.5")] for value in values})

    answers, _ = lookup(fake, questions(releases=(), suggestion_pids=values))

    paths = [path for path in fake.paths() if "/productIds/" in path]
    assert len(paths) == 2
    assert paths[0].endswith("/productIds/" + ",".join(values[:10]))
    assert paths[1].endswith("/productIds/" + values[10])
    assert uses(answers)[CiscoEndpoint.SUGGESTION].values == 11
    assert isinstance(answers.suggestions, SuggestionsAnswer)
    assert len(answers.suggestions.answers) == 11


def test_openvuln_calls_are_paced_under_thirty_a_minute() -> None:
    fake = FakeCisco(
        advisories={
            ("iosxe", "17.9.4a", None): [],
            ("iosxe", "17.9.5", None): [],
            ("iosxe", "17.9.6", None): [],
        }
    )
    asked = questions(
        releases=(
            release_question("17.9.4a"),
            release_question("17.9.5"),
            release_question("17.9.6"),
        )
    )

    _, waits = lookup(fake, asked)

    assert waits == [2.0, 2.0]


def test_a_rate_limited_403_is_retried_once_after_retry_after() -> None:
    fake = FakeCisco(advisories={("iosxe", "17.9.4a", None): [advisory()]})
    fake.scripted.append(
        (
            "/security",
            HttpResponse(
                status=403,
                headers=(
                    ("X-Mashery-Error-Code", "ERR_403_DEVELOPER_OVER_QPS"),
                    ("Retry-After", "4"),
                ),
                body=b"",
            ),
        )
    )

    answers, waits = lookup(fake, questions())

    assert 4.0 in waits
    assert len([path for path in fake.paths() if path.startswith("/security")]) == 2
    assert uses(answers)[CiscoEndpoint.OPENVULN].calls == 2
    assert uses(answers)[CiscoEndpoint.OPENVULN].retries == 1
    assert isinstance(answers.advisories[0], AdvisoriesAnswer)
    assert answers.advisories[0].advisories[0].advisory_id == "cisco-sa-test-1"


def test_an_auth_403_is_never_retried_and_stops_every_later_call() -> None:
    fake = FakeCisco(eox_pid={"C9300-48P": eox_record("C9300-48P")})
    fake.scripted.append(
        (
            "/security",
            HttpResponse(
                status=403,
                headers=(("X-Mashery-Error-Code", "ERR_403_NOT_AUTHORIZED"),),
                body=b"",
            ),
        )
    )
    asked = questions(
        releases=(release_question(),),
        hardware_pids=("C9300-48P",),
        suggestion_pids=("C9300-48P",),
    )

    answers, _ = lookup(fake, asked)

    assert len(fake.api_requests()) == 1
    assert isinstance(answers.advisories[0], SourceUnavailable)
    assert "rejected the API key" in answers.advisories[0].reason
    assert isinstance(answers.hardware_eox, SourceUnavailable)
    assert isinstance(answers.suggestions, SourceUnavailable)
    assert answers.tally.token.outcome is TokenOutcome.OK


def test_a_401_is_never_retried() -> None:
    fake = FakeCisco()
    fake.scripted.append(("/security", HttpResponse(status=401, body=b"")))

    answers, _ = lookup(fake, questions())

    assert len(fake.api_requests()) == 1
    assert isinstance(answers.advisories[0], SourceUnavailable)
    assert uses(answers)[CiscoEndpoint.OPENVULN].retries == 0


def test_a_400_invalid_client_is_a_rejected_key_and_nothing_else_is_sent() -> None:
    fake = FakeCisco()
    fake.token_status = 400
    fake.token_error = "invalid_client"

    answers, _ = lookup(
        fake,
        questions(hardware_pids=("C9300-48P",), suggestion_pids=("C9300-48P",)),
    )

    assert fake.token_calls() == 1
    assert fake.api_requests() == []
    assert answers.tally.token == TokenResult(TokenOutcome.REJECTED, 400, "invalid_client")
    assert isinstance(answers.advisories[0], SourceUnavailable)
    assert "rejected the API key" in answers.advisories[0].reason
    assert isinstance(answers.hardware_eox, SourceUnavailable)


def test_a_401_token_is_a_rejected_key() -> None:
    fake = FakeCisco()
    fake.token_status = 401

    answers, _ = lookup(fake, questions())

    assert answers.tally.token.outcome is TokenOutcome.REJECTED
    assert fake.api_requests() == []


def test_a_rate_limit_is_retried_only_once() -> None:
    fake = FakeCisco()
    limited = HttpResponse(status=429, headers=(("Retry-After", "1"),), body=b"")
    fake.scripted.extend([("/security", limited), ("/security", limited)])

    answers, waits = lookup(fake, questions())

    assert len([path for path in fake.paths() if path.startswith("/security")]) == 2
    assert uses(answers)[CiscoEndpoint.OPENVULN].calls == 2
    assert uses(answers)[CiscoEndpoint.OPENVULN].retries == 1
    assert 1.0 in waits
    assert isinstance(answers.advisories[0], SourceUnavailable)
    assert "rate limited" in answers.advisories[0].reason


def test_cisco_unreachable_is_one_retry_then_source_unavailable() -> None:
    fake = FakeCisco(outage=True)

    answers, _ = lookup(fake, questions())

    assert answers.tally.token.outcome is TokenOutcome.UNAVAILABLE
    assert uses(answers)[CiscoEndpoint.TOKEN].calls == 2
    assert uses(answers)[CiscoEndpoint.TOKEN].retries == 1
    assert isinstance(answers.advisories[0], SourceUnavailable)
    assert "did not answer in time" in answers.advisories[0].reason
    assert all("Bearer" not in request.path for request in fake.requests)


def test_a_reply_the_tool_does_not_understand_never_reads_as_no_advisories() -> None:
    fake = FakeCisco()
    fake.scripted.append(("/security", HttpResponse(status=200, body=b'{"items": []}')))

    answers, _ = lookup(fake, questions())

    assert isinstance(answers.advisories[0], SourceUnavailable)
    assert "not understood" in answers.advisories[0].reason


def test_an_odd_outbound_value_is_refused_before_anything_is_sent() -> None:
    fake = FakeCisco()
    asked = questions(
        releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a\r\nHost: evil"),),
        hardware_pids=("C9300-48P; DROP",),
        suggestion_pids=("C9300 48P",),
    )

    answers, waits = lookup(fake, asked)

    assert fake.requests == []
    assert waits == []
    assert answers.tally.token.outcome is TokenOutcome.NOT_REQUESTED
    assert all(use.calls == 0 for use in answers.tally.endpoints)
    assert isinstance(answers.advisories[0], SourceUnavailable)
    assert "did not match" in answers.advisories[0].reason
    assert isinstance(answers.hardware_eox, SourceUnavailable)
    assert isinstance(answers.suggestions, SourceUnavailable)


def test_an_alias_on_ios_or_missing_on_nxos_is_refused() -> None:
    fake = FakeCisco()
    asked = questions(
        releases=(
            ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a", "NEXUS9000"),
            ReleaseQuestion(CiscoOsType.NX_OS, "9.3(10)"),
        )
    )

    answers, _ = lookup(fake, asked)

    assert fake.requests == []
    assert [type(answer) for answer in answers.advisories] == [SourceUnavailable] * 2


def test_eox_values_cisco_has_no_record_for_keep_its_code() -> None:
    fake = FakeCisco(eox_pid={"C9300-48P": eox_record("C9300-48P")})

    answers, _ = lookup(fake, questions(releases=(), hardware_pids=("C9300-48P", "C9300-24P")))

    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [record.product_id for record in answers.hardware_eox.records] == ["C9300-48P"]
    assert answers.hardware_eox.unanswered[0].input_value == "C9300-24P"
    assert answers.hardware_eox.unanswered[0].reason == "SSA_ERR_026"


def test_eox_pages_until_the_last_index() -> None:
    fake = FakeCisco(last_page={"EOXByProductID": 2})
    fake.page_records[("EOXByProductID", 1)] = [eox_record("C9300-48P")]
    fake.page_records[("EOXByProductID", 2)] = [eox_record("C9300-24P")]

    answers, _ = lookup(fake, questions(releases=(), hardware_pids=("C9300-48P", "C9300-24P")))

    paths = [path for path in fake.paths() if "/EOXByProductID/" in path]
    assert paths == [
        "/supporttools/eox/rest/5/EOXByProductID/1/C9300-48P,C9300-24P",
        "/supporttools/eox/rest/5/EOXByProductID/2/C9300-48P,C9300-24P",
    ]
    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [record.product_id for record in answers.hardware_eox.records] == [
        "C9300-48P",
        "C9300-24P",
    ]


def test_no_question_makes_no_connection_at_all() -> None:
    fake = FakeCisco()

    answers, waits = lookup(fake, LookupQuestions())

    assert fake.requests == []
    assert waits == []
    assert answers.tally.token.outcome is TokenOutcome.NOT_REQUESTED
    assert answers.advisories == ()


def test_a_token_reply_that_is_not_a_token_is_never_used() -> None:
    fake = FakeCisco()
    fake.scripted.append(
        (
            "/oauth2",
            HttpResponse(
                status=200,
                body=b'{"access_token": "bad\\r\\nX-Evil: 1"}',
            ),
        )
    )

    answers, _ = lookup(fake, questions())

    assert answers.tally.token.outcome is TokenOutcome.UNAVAILABLE
    assert fake.api_requests() == []
    assert isinstance(answers.advisories[0], SourceUnavailable)


def test_an_eox_reply_with_only_an_error_code_is_unavailable() -> None:
    fake = FakeCisco()
    fake.scripted.append(
        (
            "/supporttools",
            HttpResponse(status=200, body=b'{"SSA_ERR_021_Pid": "no such PID"}'),
        )
    )

    answers, _ = lookup(fake, questions(releases=(), hardware_pids=("C9300-48P",)))

    assert isinstance(answers.hardware_eox, SourceUnavailable)
    assert "SSA_ERR_021_Pid" in answers.hardware_eox.reason


def test_check_api_key_sends_one_token_request_and_nothing_else() -> None:
    fake = FakeCisco()
    pacer, _ = fast_pacer()

    result = check_api_key(Secret(CLIENT_ID), Secret(CLIENT_SECRET), transport=fake, pacer=pacer)

    assert result == TokenResult(TokenOutcome.OK, 200)
    assert fake.token_calls() == 1
    assert fake.api_requests() == []
    assert TOKEN not in repr(result)


def test_check_api_key_reports_a_rejected_key() -> None:
    fake = FakeCisco(token_status=400, token_error="invalid_client")
    pacer, _ = fast_pacer()

    result = check_api_key(Secret(CLIENT_ID), Secret(CLIENT_SECRET), transport=fake, pacer=pacer)

    assert result == TokenResult(TokenOutcome.REJECTED, 400, "invalid_client")


def test_a_connection_failure_reason_reaches_the_answer() -> None:
    fake = FakeCisco()
    fake.scripted.append(("/security", TransportFailed("Cisco's certificate was not trusted")))
    fake.scripted.append(("/security", TransportFailed("Cisco's certificate was not trusted")))

    answers, _ = lookup(fake, questions())

    assert isinstance(answers.advisories[0], SourceUnavailable)
    assert answers.advisories[0].reason == "Cisco's certificate was not trusted"
