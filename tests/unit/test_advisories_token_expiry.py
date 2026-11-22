"""A token that runs out mid-Run costs no answer and is never called a rejected key (#133).

The spec allows one token a Run, so the tool does not ask for a second: a 401 from
`apix.cisco.com` after a token was issued keeps every answer already received and the Audit
counts, says in fixed text that Cisco's token expired, and stops. The tool also stops by itself
before the token's `expires_in` runs out, so a long Run does not reach the 401. The Pacer's
clock is a counter that its waits move, so nothing sleeps. All data is synthetic.
"""

from typing import Any

import pytest

from network_analyser.advisories import HttpRequest, Pacer, ask_cisco
from network_analyser.advisories.session import TOKEN_EXPIRED
from network_analyser.advisories.transport import HttpResponse
from network_analyser.credentials import Secret
from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoAnswers,
    CiscoEndpoint,
    CiscoOsType,
    CompatibleAnswers,
    LookupQuestions,
    ReleaseQuestion,
    SoftwareEoxQuestion,
    SourceUnavailable,
    TokenOutcome,
)
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco

SECURITY = "/security"
COMPATIBLE = "/software/suggestion/v2/suggestions/compatible/"
PIDS = ("C9300-48P", "C9300-24T", "C9300-24P")


def releases(count: int) -> tuple[ReleaseQuestion, ...]:
    return tuple(ReleaseQuestion(CiscoOsType.IOS_XE, f"17.9.{number}") for number in range(count))


def lookup(fake: FakeCisco, asked: LookupQuestions) -> tuple[CiscoAnswers, list[float]]:
    now = [0.0]
    waits: list[float] = []

    def wait(seconds: float) -> None:
        waits.append(seconds)
        now[0] += seconds

    answers = ask_cisco(
        asked,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=fake,
        pacer=Pacer(clock=lambda: now[0], wait=wait),
    )
    return answers, waits


def uses(answers: CiscoAnswers) -> dict[CiscoEndpoint, Any]:
    return {use.endpoint: use for use in answers.tally.endpoints}


def expire_on(fake: FakeCisco, prefix: str, nth: int) -> None:
    """Make Cisco answer 401 to the `nth` request whose path starts with `prefix`."""
    seen: list[str] = []

    def count(request: HttpRequest) -> None:
        if request.path.startswith(prefix):
            seen.append(request.path)
            if len(seen) == nth:
                fake.scripted.append((prefix, HttpResponse(status=401, body=b"")))

    fake.on_request = count


def paths(fake: FakeCisco, prefix: str) -> list[str]:
    return [path for path in fake.paths() if path.startswith(prefix)]


def test_a_401_during_openvuln_keeps_the_answers_already_received() -> None:
    fake = FakeCisco()
    expire_on(fake, SECURITY, 3)

    answers, _ = lookup(fake, LookupQuestions(releases=releases(4)))

    assert [type(item) for item in answers.advisories] == [
        AdvisoriesAnswer,
        AdvisoriesAnswer,
        SourceUnavailable,
        SourceUnavailable,
    ]
    assert answers.advisories[2] == SourceUnavailable(TOKEN_EXPIRED)
    assert answers.advisories[3] == SourceUnavailable(TOKEN_EXPIRED)
    assert len(paths(fake, SECURITY)) == 3  # nothing is sent after the 401, and it is not retried
    assert fake.token_calls() == 1  # the one-token rule holds: no second token is asked for
    assert uses(answers)[CiscoEndpoint.TOKEN].calls == 1


def test_the_audit_counts_survive_a_401_and_the_token_is_still_ok() -> None:
    fake = FakeCisco()
    expire_on(fake, SECURITY, 3)

    answers, _ = lookup(fake, LookupQuestions(releases=releases(4)))

    assert answers.tally.token.outcome is TokenOutcome.OK
    openvuln = uses(answers)[CiscoEndpoint.OPENVULN]
    assert (openvuln.calls, openvuln.values, openvuln.retries) == (3, 3, 0)


def test_the_fixed_reason_says_the_token_expired_and_never_blames_the_key() -> None:
    assert TOKEN_EXPIRED == "Cisco's token expired"
    lowered = TOKEN_EXPIRED.lower()
    assert "rejected" not in lowered
    assert "key" not in lowered
    assert "cisco-key" not in lowered


def test_a_401_stops_every_source_still_to_be_asked_without_sending_anything() -> None:
    fake = FakeCisco()
    expire_on(fake, SECURITY, 1)
    asked = LookupQuestions(
        releases=releases(2),
        hardware_pids=("C9300-48P",),
        software_releases=(SoftwareEoxQuestion(CiscoOsType.IOS_XE, "17.9.4a"),),
        suggestion_pids=("C9300-48P",),
        compatible_pids=("C9300-48P",),
    )

    answers, _ = lookup(fake, asked)

    expired = SourceUnavailable(TOKEN_EXPIRED)
    assert list(answers.advisories) == [expired, expired]
    assert answers.compatible == expired
    assert answers.hardware_eox == expired
    assert answers.software_eox == expired
    assert answers.suggestions == expired
    assert len(fake.api_requests()) == 1
    assert fake.token_calls() == 1


def test_a_401_while_paging_the_compatible_lists_keeps_the_pids_already_answered() -> None:
    fake = FakeCisco(compatible={pid: [] for pid in PIDS})
    expire_on(fake, COMPATIBLE, 2)

    answers, _ = lookup(fake, LookupQuestions(compatible_pids=PIDS))

    assert isinstance(answers.compatible, CompatibleAnswers)
    assert [answer.product_id for answer in answers.compatible.answers] == [PIDS[0]]
    assert [(item.product_id, item.reason) for item in answers.compatible.unanswered] == [
        (PIDS[1], TOKEN_EXPIRED),
        (PIDS[2], TOKEN_EXPIRED),
    ]
    assert len(paths(fake, COMPATIBLE)) == 2
    assert answers.tally.token.outcome is TokenOutcome.OK
    compatible = uses(answers)[CiscoEndpoint.COMPATIBLE]
    assert (compatible.calls, compatible.values, compatible.pages) == (2, 2, 1)


def test_a_401_after_other_sources_finished_keeps_those_whole() -> None:
    fake = FakeCisco(compatible={pid: [] for pid in PIDS})
    expire_on(fake, COMPATIBLE, 1)
    asked = LookupQuestions(releases=releases(2), compatible_pids=PIDS)

    answers, _ = lookup(fake, asked)

    assert all(isinstance(item, AdvisoriesAnswer) for item in answers.advisories)
    assert isinstance(answers.compatible, CompatibleAnswers)
    assert answers.compatible.answers == ()
    assert len(answers.compatible.unanswered) == len(PIDS)


def test_calls_stop_before_the_token_runs_out_so_no_401_is_ever_reached() -> None:
    fake = FakeCisco(token_expires_in=70)

    answers, _ = lookup(fake, LookupQuestions(releases=releases(25)))

    # openVuln is two seconds apart; the token has 70 s, less the 30 s margin, so 40 s of calls.
    assert len(paths(fake, SECURITY)) == 20
    assert all(isinstance(item, AdvisoriesAnswer) for item in answers.advisories[:20])
    assert all(item == SourceUnavailable(TOKEN_EXPIRED) for item in answers.advisories[20:])
    assert fake.token_calls() == 1
    assert answers.tally.token.outcome is TokenOutcome.OK
    assert uses(answers)[CiscoEndpoint.OPENVULN].calls == 20


def test_the_retry_is_not_sent_when_the_wait_ran_the_token_out() -> None:
    fake = FakeCisco(token_expires_in=100)
    fake.scripted.append(
        (SECURITY, HttpResponse(status=429, headers=(("Retry-After", "90"),), body=b""))
    )

    answers, waits = lookup(fake, LookupQuestions(releases=releases(1)))

    assert 90.0 in waits
    assert len(paths(fake, SECURITY)) == 1
    assert answers.advisories[0] == SourceUnavailable(TOKEN_EXPIRED)
    openvuln = uses(answers)[CiscoEndpoint.OPENVULN]
    assert (openvuln.calls, openvuln.retries) == (1, 0)


@pytest.mark.parametrize("odd", [None, "²", "soon", -5, True, 1.5, "9" * 5000, []], ids=repr)
def test_a_token_reply_without_a_usable_lifetime_does_not_stop_calls_early(odd: object) -> None:
    fake = FakeCisco(token_expires_in=odd)

    answers, _ = lookup(fake, LookupQuestions(releases=releases(25)))

    assert len(paths(fake, SECURITY)) == 25
    assert all(isinstance(item, AdvisoriesAnswer) for item in answers.advisories)


def test_a_401_from_the_token_endpoint_is_still_a_rejected_key() -> None:
    fake = FakeCisco(token_status=401)

    answers, _ = lookup(fake, LookupQuestions(releases=releases(1), hardware_pids=("C9300-48P",)))

    assert answers.tally.token.outcome is TokenOutcome.REJECTED
    assert answers.advisories[0] == SourceUnavailable("Cisco rejected the API key")
    assert fake.api_requests() == []


def test_a_source_eox_401_keeps_the_sources_that_were_answered() -> None:
    fake = FakeCisco(compatible={"C9300-48P": []})
    expire_on(fake, "/supporttools", 1)
    asked = LookupQuestions(
        releases=releases(1), hardware_pids=("C9300-48P",), compatible_pids=("C9300-48P",)
    )

    answers, _ = lookup(fake, asked)

    assert isinstance(answers.advisories[0], AdvisoriesAnswer)
    assert isinstance(answers.compatible, CompatibleAnswers)
    assert answers.hardware_eox == SourceUnavailable(TOKEN_EXPIRED)
