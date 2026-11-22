"""An odd number in a Cisco reply never raises, and no answer is lost to it (#133).

`lastIndex`, `LastIndex` and `Retry-After` come from Cisco and are untrusted: a string such as
`"²"` passes `str.isdigit()` yet is no number, and a digit string of thousands of characters is
refused by `int()`. Each is read as ASCII digits of a sane length or not at all, and a reply
that still cannot be read makes only its own source "not understood". The fake Cisco is at the
transport seam and the Pacer's clock is a counter, so nothing sleeps. All data is synthetic.
"""

from typing import Any

import pytest

from network_analyser.advisories import HttpRequest, LookupInterrupted, Pacer, ask_cisco, replies
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
    TokenOutcome,
)
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco

PID = "C9300-48P"
ODD_NUMBERS: tuple[object, ...] = (
    "²",
    "9" * 5000,
    "-3",
    "",
    "two",
    " 2 ",
    "\u0663",
    True,
    False,
    -4,
    2.5,
    None,
    [],
    {},
)
"""Every odd shape a page number or wait can take; each reads as absent."""


def release_entry(name: str) -> dict[str, Any]:
    return {
        "releaseFormat1": name,
        "isSuggested": "N",
        "releaseTrain": "17.12",
        "releaseLifeCycle": "MD",
    }


def eox_record(product_id: str) -> dict[str, Any]:
    return {
        "EOLProductID": product_id,
        "ProductIDDescription": "Synthetic switch",
        "ProductBulletinNumber": "EOL-SYNTHETIC-133",
        "LinkToProductBulletinURL": "https://cisco.example/bulletin",
        "EndOfSaleDate": {"value": "2025-01-01"},
        "EOXInputType": "PID",
        "EOXInputValue": product_id,
    }


def advisory() -> dict[str, Any]:
    return {
        "advisoryId": "cisco-sa-test-133",
        "advisoryTitle": "Synthetic advisory",
        "sir": "High",
        "cvssBaseScore": "8.6",
        "cves": ["CVE-2026-0001"],
        "firstPublished": "2026-01-01T00:00:00",
        "lastUpdated": "2026-02-01T00:00:00",
        "firstFixed": ["17.9.5"],
    }


def release_question() -> ReleaseQuestion:
    return ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a")


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


@pytest.mark.parametrize("odd", ODD_NUMBERS, ids=repr)
def test_an_odd_compatible_last_index_reads_as_one_page_and_loses_nothing(odd: object) -> None:
    fake = FakeCisco(
        advisories={("iosxe", "17.9.4a", None): [advisory()]},
        compatible={PID: [release_entry("17.12.8")]},
        compatible_last_page={PID: odd},
    )

    answers, _ = lookup(
        fake, LookupQuestions(releases=(release_question(),), compatible_pids=(PID,))
    )

    assert isinstance(answers.advisories[0], AdvisoriesAnswer)
    assert isinstance(answers.compatible, CompatibleAnswers)
    assert [item.release for item in answers.compatible.answers[0].releases] == ["17.12.8"]
    assert uses(answers)[CiscoEndpoint.COMPATIBLE].pages == 1
    assert answers.tally.token.outcome is TokenOutcome.OK


@pytest.mark.parametrize("odd", ODD_NUMBERS, ids=repr)
def test_an_odd_eox_last_index_reads_as_one_page_and_loses_nothing(odd: object) -> None:
    fake = FakeCisco(
        advisories={("iosxe", "17.9.4a", None): [advisory()]},
        eox_pid={PID: eox_record(PID)},
        last_page={"EOXByProductID": odd},
    )

    answers, _ = lookup(fake, LookupQuestions(releases=(release_question(),), hardware_pids=(PID,)))

    assert isinstance(answers.advisories[0], AdvisoriesAnswer)
    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [record.product_id for record in answers.hardware_eox.records] == [PID]
    assert len([path for path in fake.paths() if "/EOXByProductID/" in path]) == 1


@pytest.mark.parametrize("last", ["99", "9999", 99, 10**9])
def test_a_last_index_past_the_cap_is_clamped_to_the_cap_not_chased(last: object) -> None:
    fake = FakeCisco(compatible={PID: []}, compatible_last_page={PID: last})

    answers, _ = lookup(fake, LookupQuestions(compatible_pids=(PID,)))

    assert isinstance(answers.compatible, CompatibleAnswers)
    assert answers.compatible.unanswered[0].reason == "page cap"
    assert uses(answers)[CiscoEndpoint.COMPATIBLE].pages == 20


@pytest.mark.parametrize("odd", ODD_NUMBERS, ids=repr)
def test_an_odd_retry_after_is_the_default_wait_never_a_crash(odd: object) -> None:
    fake = FakeCisco(advisories={("iosxe", "17.9.4a", None): [advisory()]})
    fake.scripted.append(
        ("/security", HttpResponse(status=429, headers=(("Retry-After", str(odd)),), body=b""))
    )

    answers, waits = lookup(fake, LookupQuestions(releases=(release_question(),)))

    assert isinstance(answers.advisories[0], AdvisoriesAnswer)
    assert 2.0 in waits
    assert uses(answers)[CiscoEndpoint.OPENVULN].retries == 1


def test_an_ascii_retry_after_is_still_honoured() -> None:
    fake = FakeCisco(advisories={("iosxe", "17.9.4a", None): [advisory()]})
    fake.scripted.append(
        ("/security", HttpResponse(status=429, headers=(("Retry-After", "7"),), body=b""))
    )

    answers, waits = lookup(fake, LookupQuestions(releases=(release_question(),)))

    assert 7.0 in waits
    assert isinstance(answers.advisories[0], AdvisoriesAnswer)


def test_a_malformed_200_body_can_be_planted_at_the_fake_and_is_not_understood() -> None:
    """The fake carries a status, headers and any body, so a malformed shape can be planted."""
    fake = FakeCisco()
    fake.scripted.append(
        (
            "/security",
            HttpResponse(
                status=200,
                headers=(("Content-Type", "application/json"),),
                body=b'{"advisories": "not a list"}',
            ),
        )
    )

    answers, _ = lookup(fake, LookupQuestions(releases=(release_question(),)))

    assert answers.advisories == (SourceUnavailable("Cisco's reply was not understood"),)
    assert answers.tally.token.outcome is TokenOutcome.OK


def test_a_reply_that_cannot_be_parsed_makes_only_its_own_source_not_understood(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(_body: bytes) -> None:
        raise ValueError

    monkeypatch.setattr("network_analyser.advisories.lookup.eox_answer", broken)
    fake = FakeCisco(
        advisories={("iosxe", "17.9.4a", None): [advisory()]},
        eox_pid={PID: eox_record(PID)},
    )

    answers, _ = lookup(fake, LookupQuestions(releases=(release_question(),), hardware_pids=(PID,)))

    assert isinstance(answers.advisories[0], AdvisoriesAnswer)
    assert answers.hardware_eox == SourceUnavailable("Cisco's reply was not understood")
    assert answers.tally.token.outcome is TokenOutcome.OK
    assert uses(answers)[CiscoEndpoint.OPENVULN].calls == 1
    assert uses(answers)[CiscoEndpoint.EOX].calls == 1


def test_an_unparseable_compatible_reply_is_that_pids_not_understood_and_the_rest_go_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = replies.compatible_answer

    def broken_for_the_first(pid: str, body: bytes) -> object:
        if pid == PID:
            raise ValueError
        return real(pid, body)

    monkeypatch.setattr(
        "network_analyser.advisories.lookup.compatible_answer", broken_for_the_first
    )
    fake = FakeCisco(compatible={PID: [release_entry("17.12.8")], "C9300-24T": []})

    answers, _ = lookup(fake, LookupQuestions(compatible_pids=(PID, "C9300-24T")))

    assert isinstance(answers.compatible, CompatibleAnswers)
    assert [(item.product_id, item.reason) for item in answers.compatible.unanswered] == [
        (PID, "Cisco's reply was not understood")
    ]
    assert [answer.product_id for answer in answers.compatible.answers] == ["C9300-24T"]


def test_a_failure_nothing_expected_still_hands_back_what_was_sent() -> None:
    fake = FakeCisco(
        advisories={("iosxe", "17.9.4a", None): [advisory()]},
        eox_pid={PID: eox_record(PID)},
    )

    def explode(request: HttpRequest) -> None:
        if request.path.startswith("/supporttools"):
            raise RuntimeError

    fake.on_request = explode

    with pytest.raises(LookupInterrupted) as stopped:
        lookup(fake, LookupQuestions(releases=(release_question(),), hardware_pids=(PID,)))

    tally = stopped.value.tally
    assert tally.token.outcome is TokenOutcome.OK
    by_endpoint = {use.endpoint: use for use in tally.endpoints}
    assert (
        by_endpoint[CiscoEndpoint.OPENVULN].calls,
        by_endpoint[CiscoEndpoint.OPENVULN].values,
    ) == (1, 1)
    assert (by_endpoint[CiscoEndpoint.EOX].calls, by_endpoint[CiscoEndpoint.EOX].values) == (1, 1)
    assert PID not in repr(tally)
