"""A source Cisco keeps refusing is stopped, so a persistent limit cannot walk the estate (#154).

A rate limit that survives its one retry opens the breaker for that source at once, and three
rate-limit or 5xx replies in a row open it too. From then on the source is not asked again: the
values still to be asked come back with the fixed reason "Cisco kept refusing the calls", and no
request is sent. A lone 400 or 404 is still only that value's own answer. The breaker is per
source, so a refused compatible list does not cost the EoX answer.

The Pacer's clock is a counter that its waits move, so nothing sleeps: 40 chassis PIDs all
answering 429 with `Retry-After: 120` cost two API requests and one 120-second wait, not the 80
requests and 4800 seconds the review probe measured at 0.3.0. All values are synthetic.
"""

from typing import Any

from network_analyser.advisories import Pacer, ask_cisco
from network_analyser.advisories.session import KEPT_REFUSING
from network_analyser.advisories.transport import HttpResponse
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
)
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco

COMPATIBLE = "/software/suggestion/v2/suggestions/compatible/"
EOX = "/supporttools"
SECURITY = "/security"
SUGGESTION = "/software/suggestion/v2/suggestions/releases"
OTHER_SWITCH = "C9300-24P"
SWITCH = "C9300-48P"


def pids(count: int) -> tuple[str, ...]:
    """`count` distinct chassis PIDs, all synthetic and in the PID pattern."""
    return tuple(f"C9300-{index:02d}P" for index in range(count))


def releases(count: int) -> tuple[ReleaseQuestion, ...]:
    """`count` distinct openVuln questions, each a synthetic IOS-XE release."""
    return tuple(ReleaseQuestion(CiscoOsType.IOS_XE, f"17.9.{number}") for number in range(count))


def eox_record(product_id: str) -> dict[str, Any]:
    """One EoX record for a PID that has EoX data."""
    return {
        "EOLProductID": product_id,
        "ProductIDDescription": "Synthetic switch",
        "ProductBulletinNumber": "EOL-SYNTHETIC-154",
        "LinkToProductBulletinURL": "https://cisco.example/bulletin",
        "EndOfSaleDate": {"value": "2025-01-01"},
        "EOXInputType": "PID",
        "EOXInputValue": product_id,
    }


def limited(retry_after: str = "120") -> HttpResponse:
    """A 429 that names a wait the tool honours, so the call is retried once."""
    return HttpResponse(status=429, headers=(("Retry-After", retry_after),), body=b"")


def server_error() -> HttpResponse:
    """A 5xx, which the tool also retries once."""
    return HttpResponse(status=500, body=b"")


def release(name: str) -> dict[str, Any]:
    """One compatible release as Cisco shapes it."""
    return {
        "releaseFormat1": name,
        "isSuggested": "N",
        "releaseTrain": "17.12",
        "releaseLifeCycle": "MD",
    }


def lookup(fake: FakeCisco, asked: LookupQuestions) -> tuple[CiscoAnswers, list[float]]:
    """Ask the fake Cisco at the module's public seam, recording waits instead of sleeping."""
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


def paths(fake: FakeCisco, prefix: str) -> list[str]:
    return [path for path in fake.paths() if path.startswith(prefix)]


def test_forty_pids_all_rate_limited_cost_two_requests_and_one_wait() -> None:
    fake = FakeCisco()
    fake.scripted.extend([(COMPATIBLE, limited()), (COMPATIBLE, limited())])

    answers, waits = lookup(fake, LookupQuestions(compatible_pids=pids(40)))

    assert len(paths(fake, COMPATIBLE)) == 2  # the call and its one retry, then nothing
    assert fake.token_calls() == 1
    assert sum(waits) <= 300  # 120 s, not the probe's 4800 s
    assert isinstance(answers.compatible, CompatibleAnswers)
    assert answers.compatible.answers == ()
    reasons = [item.reason for item in answers.compatible.unanswered]
    assert len(reasons) == 40
    assert reasons[0] == "Cisco rate limited the calls"
    assert set(reasons[1:]) == {KEPT_REFUSING}
    assert uses(answers)[CiscoEndpoint.COMPATIBLE].calls == 2


def test_a_404_on_the_first_pid_still_lets_the_other_pids_be_asked() -> None:
    fake = FakeCisco(
        compatible={
            "C9300-24T": [release("17.12.7b")],
            "C9300-24P": [release("17.12.7")],
        }
    )
    fake.scripted.append((COMPATIBLE, HttpResponse(status=404, body=b"")))

    answers, _ = lookup(
        fake, LookupQuestions(compatible_pids=("C9300-48P", "C9300-24T", "C9300-24P"))
    )

    assert len(paths(fake, COMPATIBLE)) == 3
    assert isinstance(answers.compatible, CompatibleAnswers)
    assert [(item.product_id, item.reason) for item in answers.compatible.unanswered] == [
        ("C9300-48P", "HTTP 404")
    ]
    assert [answer.product_id for answer in answers.compatible.answers] == [
        "C9300-24T",
        "C9300-24P",
    ]
    assert uses(answers)[CiscoEndpoint.COMPATIBLE].retries == 0


def test_three_5xx_replies_in_a_row_stop_the_source() -> None:
    fake = FakeCisco()
    fake.scripted.extend([(SECURITY, server_error()) for _ in range(6)])

    answers, _ = lookup(fake, LookupQuestions(releases=releases(4)))

    assert len(paths(fake, SECURITY)) == 6  # three calls, each with its one retry
    assert [type(item) for item in answers.advisories] == [
        SourceUnavailable,
        SourceUnavailable,
        SourceUnavailable,
        AdvisoriesAnswer,
    ]
    assert all(
        item == SourceUnavailable("Cisco returned HTTP 500") for item in answers.advisories[:3]
    )
    fourth = answers.advisories[3]
    assert isinstance(fourth, AdvisoriesAnswer)
    assert fourth.unavailable == KEPT_REFUSING
    assert fourth.advisories == ()
    assert fake.token_calls() == 1  # never a second token


def test_an_answer_between_refusals_starts_the_count_again() -> None:
    empty = HttpResponse(
        status=200, headers=(("Content-Type", "application/json"),), body=b'{"advisories": []}'
    )
    fake = FakeCisco(advisories={("iosxe", "17.9.1", None): []})
    fake.scripted.extend(
        [
            (SECURITY, server_error()),
            (SECURITY, server_error()),
            (SECURITY, empty),
            (SECURITY, server_error()),
            (SECURITY, server_error()),
            (SECURITY, empty),
        ]
    )

    answers, _ = lookup(fake, LookupQuestions(releases=releases(4)))

    assert len(paths(fake, SECURITY)) == 6  # every release is still asked: the run never reached 3
    assert [type(item) for item in answers.advisories] == [
        SourceUnavailable,
        AdvisoriesAnswer,
        SourceUnavailable,
        AdvisoriesAnswer,
    ]
    assert answers.advisories[1] == AdvisoriesAnswer(
        question=releases(4)[1], advisories=(), unavailable=None
    )
    assert answers.advisories[3] == AdvisoriesAnswer(
        question=releases(4)[3], advisories=(), unavailable=None
    )


def test_the_openvuln_loop_stops_after_the_first_limit_that_survives_its_retry() -> None:
    fake = FakeCisco()
    fake.scripted.extend([(SECURITY, limited()), (SECURITY, limited()), (SECURITY, limited())])

    answers, waits = lookup(fake, LookupQuestions(releases=releases(3)))

    assert len(paths(fake, SECURITY)) == 2
    assert sum(waits) <= 300
    assert answers.advisories[0] == SourceUnavailable("Cisco rate limited the calls")
    assert all(item.unavailable == KEPT_REFUSING for item in answers.advisories[1:])  # type: ignore[union-attr]
    assert uses(answers)[CiscoEndpoint.OPENVULN].calls == 2
    assert fake.token_calls() == 1


def test_the_eox_loop_stops_after_the_first_limit_that_survives_its_retry() -> None:
    fake = FakeCisco()
    fake.scripted.extend([(EOX, limited()), (EOX, limited())])

    answers, waits = lookup(fake, LookupQuestions(hardware_pids=pids(40)))

    assert len(paths(fake, EOX)) == 2  # the first batch, and nothing for the second
    assert sum(waits) <= 300
    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert answers.hardware_eox.records == ()
    unanswered = answers.hardware_eox.unanswered
    assert [item.input_value for item in unanswered] == list(pids(40))
    assert {item.reason for item in unanswered[:20]} == {"Cisco rate limited the calls"}
    assert {item.reason for item in unanswered[20:]} == {KEPT_REFUSING}


def test_the_split_of_a_refused_eox_batch_stops_at_the_first_limit_too() -> None:
    fake = FakeCisco()
    fake.scripted.extend(
        [
            (EOX, HttpResponse(status=400, body=b"")),
            (EOX, limited()),
            (EOX, limited()),
        ]
    )

    answers, _ = lookup(
        fake, LookupQuestions(hardware_pids=("C9300-48P", OTHER_SWITCH, "C9300-24T"))
    )

    assert len(paths(fake, EOX)) == 3  # the refused batch, then one value's call and its retry
    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [(item.input_value, item.reason) for item in answers.hardware_eox.unanswered] == [
        ("C9300-48P", "Cisco rate limited the calls"),
        (OTHER_SWITCH, KEPT_REFUSING),
        ("C9300-24T", KEPT_REFUSING),
    ]


def test_the_suggestion_loop_stops_after_the_first_limit_that_survives_its_retry() -> None:
    fake = FakeCisco()
    fake.scripted.extend([(SUGGESTION, limited()), (SUGGESTION, limited())])

    answers, waits = lookup(fake, LookupQuestions(suggestion_pids=pids(15)))

    assert len(paths(fake, SUGGESTION)) == 2  # the first batch of ten, and nothing for the rest
    assert sum(waits) <= 300
    assert isinstance(answers.suggestions, SuggestionsAnswer)
    assert answers.suggestions.answers == ()
    unanswered = answers.suggestions.unanswered
    assert [item.product_id for item in unanswered] == list(pids(15))
    assert {item.reason for item in unanswered[:10]} == {"Cisco rate limited the calls"}
    assert {item.reason for item in unanswered[10:]} == {KEPT_REFUSING}


def test_a_refused_compatible_list_does_not_stop_the_eox_answer() -> None:
    fake = FakeCisco(eox_pid={OTHER_SWITCH: eox_record(OTHER_SWITCH)})
    fake.scripted.extend([(COMPATIBLE, limited()), (COMPATIBLE, limited())])

    answers, _ = lookup(
        fake,
        LookupQuestions(compatible_pids=("C9300-48P", "C9300-24T"), hardware_pids=(OTHER_SWITCH,)),
    )

    assert isinstance(answers.compatible, CompatibleAnswers)
    assert answers.compatible.answers == ()
    assert [item.reason for item in answers.compatible.unanswered] == [
        "Cisco rate limited the calls",
        KEPT_REFUSING,
    ]
    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [record.product_id for record in answers.hardware_eox.records] == [OTHER_SWITCH]
    assert len(paths(fake, EOX)) == 1
