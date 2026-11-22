"""Cisco's HTTP errors are classified per call, and only a key problem stops every call (#131).

A 400 or 404 from `apix.cisco.com` is that one call's answer, never "the key was rejected".
Only a 400 `invalid_client` or a 401 from the token endpoint and an auth-coded 403 stop all
calls as a rejected key; those are never retried. (A 401 from `apix.cisco.com` comes after a
token was issued, so it is an expired token, not a rejected key: see
`test_advisories_token_expiry.py`.) The fake Cisco scripts each error shape. All data is
synthetic.
"""

from typing import Any

import pytest

from network_analyser.advisories import Pacer, ask_cisco
from network_analyser.advisories.transport import HttpResponse, TransportFailed
from network_analyser.credentials import Secret
from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoAnswers,
    CiscoEndpoint,
    CiscoOsType,
    CompatibleAnswers,
    EoxAnswer,
    LookupQuestions,
    ReleaseQuestion,
    SourceUnavailable,
    SuggestionsAnswer,
    TokenOutcome,
    TokenResult,
)
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco

GOOD = ("iosxe", "17.9.4a", None)
BAD = ("iosxe", "17.99.1", None)
COMPATIBLE = "/software/suggestion/v2/suggestions/compatible/productId/"


def advisory() -> dict[str, Any]:
    return {
        "advisoryId": "cisco-sa-test-131",
        "advisoryTitle": "Synthetic advisory",
        "sir": "High",
        "cvssBaseScore": "8.6",
        "cves": ["CVE-2026-0001"],
        "firstPublished": "2026-01-01T00:00:00",
        "lastUpdated": "2026-02-01T00:00:00",
        "firstFixed": ["17.9.5"],
    }


def eox_record(product_id: str) -> dict[str, Any]:
    return {
        "EOLProductID": product_id,
        "ProductIDDescription": "Synthetic switch",
        "ProductBulletinNumber": "EOL-SYNTHETIC-1",
        "LinkToProductBulletinURL": "https://cisco.example/bulletin",
        "EndOfSaleDate": {"value": "2025-01-01"},
        "EOXInputType": "PID",
        "EOXInputValue": product_id,
    }


def release(name: str) -> dict[str, Any]:
    return {
        "releaseFormat1": name,
        "isSuggested": "N",
        "releaseTrain": "17.12",
        "releaseLifeCycle": "MD",
    }


def questions(
    *,
    releases: tuple[ReleaseQuestion, ...] = (),
    hardware_pids: tuple[str, ...] = (),
    suggestion_pids: tuple[str, ...] = (),
    compatible_pids: tuple[str, ...] = (),
) -> LookupQuestions:
    return LookupQuestions(
        releases=releases,
        hardware_pids=hardware_pids,
        suggestion_pids=suggestion_pids,
        compatible_pids=compatible_pids,
    )


def releases_asked() -> tuple[ReleaseQuestion, ...]:
    return (
        ReleaseQuestion(CiscoOsType.IOS_XE, "17.99.1"),
        ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a"),
    )


def lookup(fake: FakeCisco, asked: LookupQuestions) -> CiscoAnswers:
    now = [0.0]

    def wait(seconds: float) -> None:
        now[0] += seconds

    return ask_cisco(
        asked,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=fake,
        pacer=Pacer(clock=lambda: now[0], wait=wait),
    )


def uses(answers: CiscoAnswers) -> dict[CiscoEndpoint, Any]:
    return {use.endpoint: use for use in answers.tally.endpoints}


def openvuln_paths(fake: FakeCisco) -> list[str]:
    return [path for path in fake.paths() if path.startswith("/security")]


@pytest.mark.parametrize(
    ("status", "code", "reason"),
    [
        (400, "INVALID_IOS_VERSION", "INVALID_IOS_VERSION"),
        (404, "INVALID_IOS_VERSION", "INVALID_IOS_VERSION"),
        (400, "", "HTTP 400"),
        (404, "", "HTTP 404"),
    ],
)
def test_a_400_or_404_on_one_release_leaves_the_other_releases_intact(
    status: int, code: str, reason: str
) -> None:
    fake = FakeCisco(
        advisories={GOOD: [advisory()]},
        advisory_errors={BAD: (status, code)},
        eox_pid={"C9300-48P": eox_record("C9300-48P")},
        suggestions={"C9300-48P": [{"relDispName": "17.9.5", "isSuggested": "Y"}]},
    )

    answers = lookup(
        fake,
        questions(
            releases=releases_asked(),
            hardware_pids=("C9300-48P",),
            suggestion_pids=("C9300-48P",),
        ),
    )

    bad, good = answers.advisories
    assert isinstance(bad, AdvisoriesAnswer)
    assert bad.question.release == "17.99.1"
    assert (bad.advisories, bad.unavailable) == ((), reason)
    assert isinstance(good, AdvisoriesAnswer)
    assert good.unavailable is None
    assert [item.advisory_id for item in good.advisories] == ["cisco-sa-test-131"]
    assert len(openvuln_paths(fake)) == 2  # nothing is retried and the second release is asked
    assert uses(answers)[CiscoEndpoint.OPENVULN].retries == 0
    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert isinstance(answers.suggestions, SuggestionsAnswer)
    assert answers.tally.token == TokenResult(TokenOutcome.OK, 200)


@pytest.mark.parametrize("status", [200, 404])
def test_no_data_found_is_an_empty_answer_not_an_outage(status: int) -> None:
    fake = FakeCisco(advisory_errors={GOOD: (status, "NO_DATA_FOUND")})

    answers = lookup(fake, questions(releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a"),)))

    (answer,) = answers.advisories
    assert isinstance(answer, AdvisoriesAnswer)
    assert (answer.advisories, answer.unavailable) == ((), None)


def test_an_unknown_403_code_is_one_calls_failure_and_never_a_rejected_key() -> None:
    fake = FakeCisco(advisories={GOOD: [advisory()]})
    fake.scripted.append(
        (
            "/security",
            HttpResponse(
                status=403, headers=(("X-Mashery-Error-Code", "ERR_403_SOMETHING_NEW"),), body=b""
            ),
        )
    )

    answers = lookup(fake, questions(releases=releases_asked()))

    first, second = answers.advisories
    assert isinstance(first, AdvisoriesAnswer)
    assert first.unavailable == "HTTP 403"
    assert isinstance(second, AdvisoriesAnswer)
    assert second.unavailable is None
    assert len(openvuln_paths(fake)) == 2
    assert uses(answers)[CiscoEndpoint.OPENVULN].retries == 0


def test_a_400_on_eox_names_the_http_status_not_a_rejected_key() -> None:
    fake = FakeCisco(suggestions={"C9300-48P": [{"relDispName": "17.9.5", "isSuggested": "Y"}]})
    fake.scripted.append(("/supporttools", HttpResponse(status=400, body=b"")))

    answers = lookup(
        fake,
        questions(releases=(), hardware_pids=("C9300-48P",), suggestion_pids=("C9300-48P",)),
    )

    assert answers.hardware_eox == SourceUnavailable("Cisco returned HTTP 400")
    assert isinstance(answers.suggestions, SuggestionsAnswer)


@pytest.mark.parametrize(
    ("status", "code"),
    [(400, "INVALID_PRODUCT_ID"), (404, ""), (400, "")],
)
def test_a_4xx_on_one_compatible_pid_leaves_the_other_pids_intact(status: int, code: str) -> None:
    fake = FakeCisco(
        compatible={"C9300-24T": [release("17.12.7b")]},
        compatible_errors={"C9300-48P": (status, code)},
    )

    answers = lookup(fake, questions(compatible_pids=("C9300-48P", "C9300-24T")))

    assert isinstance(answers.compatible, CompatibleAnswers)
    (unanswered,) = answers.compatible.unanswered
    assert unanswered.product_id == "C9300-48P"
    assert unanswered.reason == (code or f"HTTP {status}")
    (answer,) = answers.compatible.answers
    assert (answer.product_id, answer.releases[0].release) == ("C9300-24T", "17.12.7b")
    assert uses(answers)[CiscoEndpoint.COMPATIBLE].retries == 0


def test_a_malformed_compatible_entry_is_that_pids_failure_only() -> None:
    fake = FakeCisco(
        compatible={"C9300-24T": [release("17.12.7b")], "C9300-48P": [{"isSuggested": "N"}]}
    )

    answers = lookup(fake, questions(compatible_pids=("C9300-48P", "C9300-24T")))

    assert isinstance(answers.compatible, CompatibleAnswers)
    (unanswered,) = answers.compatible.unanswered
    assert unanswered.product_id == "C9300-48P"
    assert unanswered.reason == "Cisco's reply was not understood"
    assert [answer.product_id for answer in answers.compatible.answers] == ["C9300-24T"]


def test_a_long_retry_after_is_that_compatible_pids_failure_only() -> None:
    fake = FakeCisco(
        compatible={"C9300-24T": [release("17.12.7b")], "C9300-48P": [release("17.12.8")]}
    )
    fake.scripted.append(
        (COMPATIBLE, HttpResponse(status=429, headers=(("Retry-After", "9999"),), body=b""))
    )

    answers = lookup(fake, questions(compatible_pids=("C9300-48P", "C9300-24T")))

    assert isinstance(answers.compatible, CompatibleAnswers)
    (unanswered,) = answers.compatible.unanswered
    assert (unanswered.product_id, unanswered.reason) == (
        "C9300-48P",
        "Cisco asked for a long wait",
    )
    assert [answer.product_id for answer in answers.compatible.answers] == ["C9300-24T"]


def test_no_connection_still_makes_the_whole_compatible_source_unavailable() -> None:
    fake = FakeCisco(compatible={"C9300-48P": [release("17.12.8")], "C9300-24T": []})
    down = TransportFailed("Cisco did not answer in time")
    fake.scripted.extend([(COMPATIBLE, down), (COMPATIBLE, down)])

    answers = lookup(fake, questions(compatible_pids=("C9300-48P", "C9300-24T")))

    assert isinstance(answers.compatible, SourceUnavailable)
    assert len([path for path in fake.paths() if path.startswith(COMPATIBLE)]) == 2


@pytest.mark.parametrize(
    ("status", "headers"),
    [
        (403, (("X-Mashery-Error-Code", "ERR_403_NOT_AUTHORIZED"),)),
        (403, (("X-Mashery-Error-Code", "ERR_403_DEVELOPER_INACTIVE"),)),
    ],
)
def test_an_auth_failure_still_stops_every_call_and_is_never_retried(
    status: int, headers: tuple[tuple[str, str], ...]
) -> None:
    fake = FakeCisco(compatible={"C9300-48P": [release("17.12.8")]})
    fake.scripted.append(("/security", HttpResponse(status=status, headers=headers, body=b"")))

    answers = lookup(
        fake,
        questions(
            releases=releases_asked(),
            suggestion_pids=("C9300-48P",),
            compatible_pids=("C9300-48P",),
        ),
    )

    assert len(fake.api_requests()) == 1
    assert uses(answers)[CiscoEndpoint.OPENVULN].retries == 0
    assert all(isinstance(item, SourceUnavailable) for item in answers.advisories)
    assert isinstance(answers.suggestions, SourceUnavailable)
    assert answers.suggestions.reason == "Cisco rejected the API key"
    assert isinstance(answers.compatible, SourceUnavailable)


def test_a_400_invalid_client_from_the_token_endpoint_is_a_rejected_key() -> None:
    fake = FakeCisco(token_status=400, token_error="invalid_client")

    answers = lookup(fake, questions(releases=releases_asked()))

    assert answers.tally.token == TokenResult(TokenOutcome.REJECTED, 400, "invalid_client")
    assert fake.token_calls() == 1
    assert fake.api_requests() == []


def test_any_other_400_from_the_token_endpoint_is_not_a_rejected_key() -> None:
    fake = FakeCisco(token_status=400, token_error="invalid_request")

    answers = lookup(fake, questions(releases=releases_asked()))

    assert answers.tally.token == TokenResult(TokenOutcome.UNAVAILABLE, 400, "invalid_request")
    assert fake.token_calls() == 1  # a client error is not retried
    assert fake.api_requests() == []
    assert all(isinstance(item, SourceUnavailable) for item in answers.advisories)
    assert all("rejected" not in item.reason for item in answers.advisories)  # type: ignore[union-attr]


def test_an_unknown_403_from_the_token_endpoint_is_not_a_rejected_key() -> None:
    fake = FakeCisco(token_status=403, token_headers=(("X-Mashery-Error-Code", "ERR_403_NEW"),))

    answers = lookup(fake, questions(releases=releases_asked()))

    assert answers.tally.token.outcome is TokenOutcome.UNAVAILABLE
    assert fake.token_calls() == 1
    assert all("rejected" not in item.reason for item in answers.advisories)  # type: ignore[union-attr]


@pytest.mark.parametrize("status", [400, 403])
def test_no_data_found_on_a_status_148_did_not_confirm_is_not_an_empty_answer(
    status: int,
) -> None:
    """`NO_DATA_FOUND` means an empty answer only on 200 and 404, the statuses #148 confirmed.

    On any other status the reply contradicts itself, so the release reads unavailable with
    the HTTP status rather than as "no Advisories" (#155).
    """
    fake = FakeCisco(advisory_errors={GOOD: (status, "NO_DATA_FOUND")})

    answers = lookup(fake, questions(releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a"),)))

    (answer,) = answers.advisories
    assert isinstance(answer, AdvisoriesAnswer)
    assert (answer.advisories, answer.unavailable) == ((), f"HTTP {status}")
