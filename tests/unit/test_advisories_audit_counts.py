"""The Audit counts say what was sent, and a retry keeps to the pacing and to what can pass (#133).

Values are counted once, when the first attempt is sent, so a call that timed out twice still
carried its value out; a page is counted only for a 200; EoX counts its pages; a retry waits for
the Pacer like any call; and a refusal that cannot change (a refused redirect, an over-cap
reply) is not tried again. The Pacer's clock is a counter, so nothing sleeps. All data is
synthetic and no count holds a value.
"""

from typing import Any

import pytest

from network_analyser.advisories import HttpRequest, Pacer, ask_cisco
from network_analyser.advisories.transport import HttpResponse, TransportFailed
from network_analyser.credentials import Secret
from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoAnswers,
    CiscoEndpoint,
    CiscoOsType,
    CompatibleAnswers,
    LookupQuestions,
    ReleaseQuestion,
    SourceUnavailable,
)
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco

SECURITY = "/security"
COMPATIBLE = "/software/suggestion/v2/suggestions/compatible/"
PID = "C9300-48P"
TIMEOUT = TransportFailed("Cisco did not answer in time")


def one_release() -> LookupQuestions:
    return LookupQuestions(releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a"),))


def lookup(
    fake: FakeCisco, asked: LookupQuestions
) -> tuple[CiscoAnswers, list[float], list[float]]:
    """Return the answers, the Pacer's waits and the clock time of each non-token request."""
    now = [0.0]
    waits: list[float] = []
    sent_at: list[float] = []

    def wait(seconds: float) -> None:
        waits.append(seconds)
        now[0] += seconds

    def note(request: HttpRequest) -> None:
        if request.method == "GET":
            sent_at.append(now[0])

    fake.on_request = note
    answers = ask_cisco(
        asked,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=fake,
        pacer=Pacer(clock=lambda: now[0], wait=wait),
    )
    return answers, waits, sent_at


def uses(answers: CiscoAnswers) -> dict[CiscoEndpoint, Any]:
    return {use.endpoint: use for use in answers.tally.endpoints}


def test_a_value_is_counted_even_when_both_attempts_timed_out() -> None:
    fake = FakeCisco()
    fake.scripted.extend([(SECURITY, TIMEOUT), (SECURITY, TIMEOUT)])

    answers, _, _ = lookup(fake, one_release())

    openvuln = uses(answers)[CiscoEndpoint.OPENVULN]
    assert (openvuln.calls, openvuln.values, openvuln.retries, openvuln.pages) == (2, 1, 1, 0)
    assert isinstance(answers.advisories[0], SourceUnavailable)


def test_a_retry_does_not_count_the_value_twice() -> None:
    fake = FakeCisco()
    fake.scripted.append((SECURITY, TIMEOUT))

    answers, _, _ = lookup(fake, one_release())

    openvuln = uses(answers)[CiscoEndpoint.OPENVULN]
    assert (openvuln.calls, openvuln.values, openvuln.retries) == (2, 1, 1)
    assert isinstance(answers.advisories[0], AdvisoriesAnswer)


def test_two_500s_count_no_page() -> None:
    fake = FakeCisco(compatible={PID: []})
    server_error = HttpResponse(status=500, body=b"")
    fake.scripted.extend([(COMPATIBLE, server_error), (COMPATIBLE, server_error)])

    answers, _, _ = lookup(fake, LookupQuestions(compatible_pids=(PID,)))

    compatible = uses(answers)[CiscoEndpoint.COMPATIBLE]
    assert (compatible.calls, compatible.values, compatible.retries, compatible.pages) == (
        2,
        1,
        1,
        0,
    )


def test_a_500_then_a_200_counts_one_page() -> None:
    fake = FakeCisco(compatible={PID: []})
    fake.scripted.append((COMPATIBLE, HttpResponse(status=500, body=b"")))

    answers, _, _ = lookup(fake, LookupQuestions(compatible_pids=(PID,)))

    compatible = uses(answers)[CiscoEndpoint.COMPATIBLE]
    assert (compatible.calls, compatible.values, compatible.retries, compatible.pages) == (
        2,
        1,
        1,
        1,
    )
    assert isinstance(answers.compatible, CompatibleAnswers)


def test_a_refused_call_is_not_a_page() -> None:
    fake = FakeCisco(compatible_errors={PID: (404, "INVALID_PID")})

    answers, _, _ = lookup(fake, LookupQuestions(compatible_pids=(PID,)))

    compatible = uses(answers)[CiscoEndpoint.COMPATIBLE]
    assert (compatible.calls, compatible.values, compatible.pages) == (1, 1, 0)


def test_eox_counts_one_page_for_a_single_page_batch() -> None:
    fake = FakeCisco()

    answers, _, _ = lookup(fake, LookupQuestions(hardware_pids=(PID, "C9300-24P")))

    eox = uses(answers)[CiscoEndpoint.EOX]
    assert (eox.calls, eox.values, eox.pages) == (1, 2, 1)


def test_eox_counts_its_values_once_and_every_page() -> None:
    fake = FakeCisco(last_page={"EOXByProductID": 3})

    answers, _, _ = lookup(fake, LookupQuestions(hardware_pids=(PID, "C9300-24P")))

    eox = uses(answers)[CiscoEndpoint.EOX]
    assert (eox.calls, eox.values, eox.pages) == (3, 2, 3)


def test_a_retry_with_a_zero_retry_after_still_waits_for_the_pacer() -> None:
    fake = FakeCisco()
    fake.scripted.append(
        (SECURITY, HttpResponse(status=429, headers=(("Retry-After", "0"),), body=b""))
    )

    answers, waits, sent_at = lookup(fake, one_release())

    assert sent_at == [0.0, 2.0]  # never two openVuln calls inside the two-second spacing
    assert waits == [2.0]
    assert isinstance(answers.advisories[0], AdvisoriesAnswer)


def test_a_retry_after_longer_than_the_spacing_adds_no_extra_wait() -> None:
    fake = FakeCisco()
    fake.scripted.append(
        (SECURITY, HttpResponse(status=429, headers=(("Retry-After", "4"),), body=b""))
    )

    _, waits, sent_at = lookup(fake, one_release())

    assert waits == [4.0]
    assert sent_at == [0.0, 4.0]


def test_a_timeout_retry_waits_the_default_which_already_covers_the_spacing() -> None:
    fake = FakeCisco()
    fake.scripted.append((SECURITY, TIMEOUT))

    _, waits, sent_at = lookup(fake, one_release())

    assert waits == [2.0]  # the default wait already covers the two-second spacing
    assert sent_at == [0.0, 2.0]


@pytest.mark.parametrize(
    "reason",
    [
        "refused a redirect (HTTP 302)",
        "the reply was larger than the tool accepts",
        "refused a host outside the Cisco fence",
        "the proxy setting cannot be used",
    ],
)
def test_a_refusal_that_cannot_change_is_not_retried(reason: str) -> None:
    fake = FakeCisco()
    fake.scripted.append((SECURITY, TransportFailed(reason, retryable=False)))

    answers, waits, _ = lookup(fake, one_release())

    assert len([path for path in fake.paths() if path.startswith(SECURITY)]) == 1
    assert answers.advisories[0] == SourceUnavailable(reason)
    openvuln = uses(answers)[CiscoEndpoint.OPENVULN]
    assert (openvuln.calls, openvuln.values, openvuln.retries) == (1, 1, 0)
    assert waits == []


def test_a_connection_failure_is_still_retried_once() -> None:
    fake = FakeCisco()
    fake.scripted.extend([(SECURITY, TIMEOUT), (SECURITY, TIMEOUT)])

    answers, _, _ = lookup(fake, one_release())

    assert len([path for path in fake.paths() if path.startswith(SECURITY)]) == 2
    assert uses(answers)[CiscoEndpoint.OPENVULN].retries == 1
