"""The compatible-releases call against a fake Cisco at its HTTP transport seam (#127).

The fake records every request and refuses a request without the bearer token, an out-of-pattern
value, or `currentRelease` in any path, so each test also proves the envelope held. All values
are synthetic; the release strings are public Cisco numbering only.
"""

from typing import Any

from network_analyser.advisories import Pacer, ask_cisco
from network_analyser.advisories.transport import HttpResponse
from network_analyser.credentials import Secret
from network_analyser.records.cisco import (
    CiscoAnswers,
    CiscoEndpoint,
    CompatibleAnswers,
    LookupQuestions,
    SourceUnavailable,
    TokenOutcome,
)
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco

PREFIX = "/software/suggestion/v2/suggestions/compatible/productId/"


def suggestion(
    release: str,
    *,
    lifecycle: str = "MD",
    train: str = "17.12",
    suggested: str = "N",
) -> dict[str, Any]:
    return {
        "releaseFormat1": release,
        "isSuggested": suggested,
        "releaseTrain": train,
        "releaseLifeCycle": lifecycle,
    }


def fast_pacer() -> tuple[Pacer, list[float]]:
    now = [0.0]
    waits: list[float] = []

    def wait(seconds: float) -> None:
        waits.append(seconds)
        now[0] += seconds

    return Pacer(clock=lambda: now[0], wait=wait), waits


def lookup(fake: FakeCisco, asked: LookupQuestions) -> tuple[CiscoAnswers, list[float]]:
    pacer, waits = fast_pacer()
    answers = ask_cisco(
        asked,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=fake,
        pacer=pacer,
    )
    return answers, waits


def uses(answers: CiscoAnswers) -> dict[CiscoEndpoint, Any]:
    return {use.endpoint: use for use in answers.tally.endpoints}


def test_one_call_per_distinct_chassis_pid_and_no_current_release() -> None:
    fake = FakeCisco(
        compatible={
            "C9300-48P": [suggestion("17.12.8")],
            "C9300-24T": [suggestion("17.12.7b")],
        }
    )
    asked = LookupQuestions(
        compatible_pids=("C9300-48P", "C9300-48P", "C9300-24T"),
    )

    answers, _ = lookup(fake, asked)

    assert fake.paths() == [
        "/oauth2/default/v1/token",
        f"{PREFIX}C9300-48P?pageIndex=1",
        f"{PREFIX}C9300-24T?pageIndex=1",
    ]
    assert all("currentRelease" not in path for path in fake.paths())
    assert uses(answers)[CiscoEndpoint.COMPATIBLE].calls == 2
    assert uses(answers)[CiscoEndpoint.COMPATIBLE].values == 2
    assert uses(answers)[CiscoEndpoint.COMPATIBLE].pages == 2
    assert isinstance(answers.compatible, CompatibleAnswers)
    assert [
        (answer.product_id, answer.releases[0].release) for answer in answers.compatible.answers
    ] == [
        ("C9300-48P", "17.12.8"),
        ("C9300-24T", "17.12.7b"),
    ]


def test_compatible_pages_until_the_last_index_and_counts_the_pages() -> None:
    fake = FakeCisco(compatible_last_page={"C9300-48P": 2})
    fake.compatible_pages[("C9300-48P", 1)] = [suggestion("17.12.8")]
    fake.compatible_pages[("C9300-48P", 2)] = [suggestion("17.12.7b")]

    answers, _ = lookup(fake, LookupQuestions(compatible_pids=("C9300-48P",)))

    assert [path for path in fake.paths() if path.startswith(PREFIX)] == [
        f"{PREFIX}C9300-48P?pageIndex=1",
        f"{PREFIX}C9300-48P?pageIndex=2",
    ]
    assert isinstance(answers.compatible, CompatibleAnswers)
    assert [item.release for item in answers.compatible.answers[0].releases] == [
        "17.12.8",
        "17.12.7b",
    ]
    use = uses(answers)[CiscoEndpoint.COMPATIBLE]
    assert (use.calls, use.values, use.pages) == (2, 1, 2)


def test_the_twentieth_page_is_the_cap_and_the_pid_is_unanswered() -> None:
    fake = FakeCisco(compatible={"C9300-48P": []}, compatible_last_page={"C9300-48P": 25})

    answers, _ = lookup(fake, LookupQuestions(compatible_pids=("C9300-48P",)))

    paths = [path for path in fake.paths() if path.startswith(PREFIX)]
    assert len(paths) == 20
    assert paths[-1] == f"{PREFIX}C9300-48P?pageIndex=20"
    assert isinstance(answers.compatible, CompatibleAnswers)
    assert answers.compatible.answers == ()
    assert answers.compatible.unanswered[0].reason == "page cap"
    assert uses(answers)[CiscoEndpoint.COMPATIBLE].pages == 20


def test_the_compatible_call_is_paced_and_honours_retry_after_once() -> None:
    fake = FakeCisco(compatible={"C9300-48P": [suggestion("17.12.8")]})
    fake.scripted.append(
        (
            PREFIX,
            HttpResponse(
                status=429,
                headers=(("Retry-After", "3"),),
                body=b"",
            ),
        )
    )

    answers, waits = lookup(fake, LookupQuestions(compatible_pids=("C9300-48P",)))

    assert [path for path in fake.paths() if path.startswith(PREFIX)] == [
        f"{PREFIX}C9300-48P?pageIndex=1",
        f"{PREFIX}C9300-48P?pageIndex=1",
    ]
    assert 3.0 in waits
    use = uses(answers)[CiscoEndpoint.COMPATIBLE]
    assert (use.calls, use.retries) == (2, 1)
    assert isinstance(answers.compatible, CompatibleAnswers)
    assert answers.compatible.answers[0].releases[0].release == "17.12.8"


def test_two_pids_are_paced_between_calls() -> None:
    fake = FakeCisco(
        compatible={"C9300-48P": [suggestion("17.12.8")], "C9300-24T": [suggestion("17.12.7")]},
    )

    _, waits = lookup(fake, LookupQuestions(compatible_pids=("C9300-48P", "C9300-24T")))

    assert 0.1 in waits


def test_an_auth_error_is_never_retried_and_stops_every_later_call() -> None:
    fake = FakeCisco(compatible={"C9300-48P": [suggestion("17.12.8")]})
    fake.scripted.append(
        (
            PREFIX,
            HttpResponse(
                status=403,
                headers=(("X-Mashery-Error-Code", "ERR_403_NOT_AUTHORIZED"),),
                body=b"",
            ),
        )
    )

    answers, _ = lookup(
        fake,
        LookupQuestions(
            compatible_pids=("C9300-48P",),
            suggestion_pids=("C9300-24T",),
        ),
    )

    assert [request.path for request in fake.api_requests() if "compatible" in request.path] == [
        f"{PREFIX}C9300-48P?pageIndex=1"
    ]
    assert uses(answers)[CiscoEndpoint.COMPATIBLE].retries == 0
    assert isinstance(answers.compatible, SourceUnavailable)
    assert "rejected the API key" in answers.compatible.reason
    assert isinstance(answers.suggestions, SourceUnavailable)


def test_an_odd_chassis_pid_is_refused_and_nothing_is_sent() -> None:
    fake = FakeCisco()

    answers, waits = lookup(fake, LookupQuestions(compatible_pids=("C9300 48P",)))

    assert fake.requests == []
    assert waits == []
    assert answers.tally.token.outcome is TokenOutcome.NOT_REQUESTED
    assert all(use.calls == 0 for use in answers.tally.endpoints)
    assert isinstance(answers.compatible, SourceUnavailable)
    assert "did not match" in answers.compatible.reason


def test_the_suggestion_fields_are_parsed() -> None:
    fake = FakeCisco(
        compatible={
            "C9300-48P": [
                suggestion("26.2.1", lifecycle="ED", train="26.2", suggested="Y"),
            ]
        }
    )

    answers, _ = lookup(fake, LookupQuestions(compatible_pids=("C9300-48P",)))

    assert isinstance(answers.compatible, CompatibleAnswers)
    (release,) = answers.compatible.answers[0].releases
    assert release.release == "26.2.1"
    assert release.lifecycle == "ED"
    assert release.train == "26.2"
    assert release.suggested is True


def test_an_unknown_pid_keeps_ciscos_error_code() -> None:
    fake = FakeCisco()

    answers, _ = lookup(fake, LookupQuestions(compatible_pids=("C9300-99P",)))

    assert isinstance(answers.compatible, CompatibleAnswers)
    assert answers.compatible.unanswered[0].product_id == "C9300-99P"
    assert answers.compatible.unanswered[0].reason == "S3_INV_BASEPID"
