"""One odd value is refused on its own; the rest of the lookup is still asked (#130).

The fake Cisco refuses an out-of-pattern value or a percent-encoded PID, so a request that
arrives has already proved the envelope held. The hostile values are synthetic. A refusal
never echoes the value, and the Audit log's counts never hold a PID.
"""

from typing import Any

import pytest

from network_analyser.advisories import HttpRequest, Pacer, ask_cisco
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
    SoftwareEoxQuestion,
    SourceUnavailable,
    SuggestionsAnswer,
    TokenOutcome,
)
from tests.support.fake_cisco import (
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN,
    FakeCisco,
    UnsafeValueSentError,
)

GOOD = "C9300-48P"
ROUTER = "ISR4451-X/K9"
VIRTUAL = "C9300v"
HOSTILE = (
    "C9300-48P\r\nHost: evil.example",
    "../../C9300-48P",
    "C9300%2e00-48P",
    "C9300-48P%0d%0a",
    "C9300-48P?x=1&y=2",
    "C9300-48P#frag",
    "C9300-48P/../x",
    "C9300-48P/K9/K9",
    "C9300-\u096a\u096eP",
    "C9300-48P\u00e9",
    "C9300 48P",
    "=C9300-48P",
    "",
)


def advisory() -> dict[str, Any]:
    return {
        "advisoryId": "cisco-sa-test-130",
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
        "ProductIDDescription": "Synthetic router",
        "ProductBulletinNumber": "EOL-SYNTHETIC-130",
        "LinkToProductBulletinURL": "https://cisco.example/bulletin",
        "EndOfSaleDate": {"value": "2025-01-01"},
        "EOXInputType": "PID",
        "EOXInputValue": product_id,
    }


def compatible_entry(release: str) -> dict[str, Any]:
    return {
        "releaseFormat1": release,
        "isSuggested": "N",
        "releaseTrain": "17.9",
        "releaseLifeCycle": "MD",
    }


def suggestion(release: str) -> dict[str, Any]:
    return {
        "relDispName": release,
        "isSuggested": "Y",
        "releaseDate": "2026-03-01",
        "trainDispName": "17.9",
    }


def fake() -> FakeCisco:
    return FakeCisco(
        advisories={("iosxe", "17.9.4a", None): [advisory()]},
        eox_pid={ROUTER: eox_record(ROUTER), GOOD: eox_record(GOOD)},
        suggestions={ROUTER: [suggestion("17.9.5")], GOOD: [suggestion("17.9.5")]},
        compatible={ROUTER: [compatible_entry("17.9.5")], GOOD: [compatible_entry("17.9.5")]},
    )


def lookup(cisco: FakeCisco, asked: LookupQuestions) -> CiscoAnswers:
    now = [0.0]

    def wait(seconds: float) -> None:
        now[0] += seconds

    return ask_cisco(
        asked,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=cisco,
        pacer=Pacer(clock=lambda: now[0], wait=wait),
    )


def asking(*pids: str, release: str = "17.9.4a") -> LookupQuestions:
    return LookupQuestions(
        releases=(ReleaseQuestion(CiscoOsType.IOS_XE, release),),
        hardware_pids=pids,
        software_releases=(SoftwareEoxQuestion(CiscoOsType.IOS_XE, release),),
        suggestion_pids=pids,
        compatible_pids=pids,
    )


@pytest.mark.parametrize("odd", HOSTILE)
def test_a_hostile_pid_is_not_sent_and_the_rest_of_the_lookup_still_is(odd: str) -> None:
    cisco = fake()

    answers = lookup(cisco, asking(GOOD, odd))

    paths = cisco.paths()
    assert any(GOOD in path for path in paths)
    assert all("\r" not in path and "\n" not in path for path in paths)
    assert all(odd not in path for path in paths if odd)
    assert answers.tally.token.outcome is TokenOutcome.OK
    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [record.input_value for record in answers.hardware_eox.records] == [GOOD]
    assert isinstance(answers.suggestions, SuggestionsAnswer)
    assert [answer.product_id for answer in answers.suggestions.answers] == [GOOD]
    assert isinstance(answers.compatible, CompatibleAnswers)
    assert [answer.product_id for answer in answers.compatible.answers] == [GOOD]
    assert isinstance(answers.advisories[0], AdvisoriesAnswer)


@pytest.mark.parametrize("odd", [value for value in HOSTILE if value])
def test_a_refusal_never_echoes_the_value_into_an_answer_or_the_counts(odd: str) -> None:
    answers = lookup(fake(), asking(GOOD, odd))

    assert odd not in repr(answers)


def test_an_odd_release_is_refused_alone_and_the_good_release_is_still_asked() -> None:
    cisco = fake()
    asked = LookupQuestions(
        releases=(
            ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a"),
            ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a\r\nHost: evil.example"),
            ReleaseQuestion(CiscoOsType.IOS_XE, "../17.9"),
        ),
        software_releases=(
            SoftwareEoxQuestion(CiscoOsType.IOS_XE, "17.9.4a"),
            SoftwareEoxQuestion(CiscoOsType.IOS_XE, "17.9.4a%0d%0a"),
            SoftwareEoxQuestion(CiscoOsType.IOS_XE, "17.9.4a/.."),
        ),
    )

    answers = lookup(cisco, asked)

    assert [path for path in cisco.paths() if "OSType" in path] == [
        "/security/advisories/v2/OSType/iosxe?version=17.9.4a"
    ]
    assert [path for path in cisco.paths() if "EOXBySW" in path] == [
        "/supporttools/eox/rest/5/EOXBySWReleaseString/1?input1=17.9.4a,IOS-XE"
    ]
    assert isinstance(answers.advisories[0], AdvisoriesAnswer)
    assert answers.advisories[0].question.release == "17.9.4a"
    assert isinstance(answers.software_eox, EoxAnswer)


def test_an_estate_with_an_isr_router_and_a_switch_asks_for_both() -> None:
    cisco = fake()

    answers = lookup(cisco, asking(GOOD, ROUTER, VIRTUAL))

    paths = cisco.paths()
    assert "/supporttools/eox/rest/5/EOXByProductID/1/C9300-48P,ISR4451-X/K9,C9300v" in paths
    assert (
        "/software/suggestion/v2/suggestions/releases/productIds/C9300-48P,ISR4451-X/K9,C9300v"
        in paths
    )
    compatible = "/software/suggestion/v2/suggestions/compatible/productId/"
    assert f"{compatible}ISR4451-X/K9?pageIndex=1" in paths
    assert not any("%" in path for path in paths)
    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [record.input_value for record in answers.hardware_eox.records] == [GOOD, ROUTER]
    assert isinstance(answers.compatible, CompatibleAnswers)
    assert [answer.product_id for answer in answers.compatible.answers] == [GOOD, ROUTER]


def test_a_slashed_pid_echoed_with_trailing_whitespace_still_names_its_pid() -> None:
    cisco = fake()
    cisco.eox_pid[ROUTER] = {**eox_record(ROUTER), "EOXInputValue": f"{ROUTER} "}

    answers = lookup(cisco, asking(ROUTER))

    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [record.input_value for record in answers.hardware_eox.records] == [ROUTER]


def test_the_audit_counts_hold_numbers_only_never_a_pid() -> None:
    answers = lookup(fake(), asking(GOOD, ROUTER, "C9300 48P"))

    text = repr(answers.tally)
    for value in (GOOD, ROUTER, "48P", "K9", "C9300"):
        assert value not in text
    for use in answers.tally.endpoints:
        assert all(type(count) is int for count in (use.calls, use.values, use.retries, use.pages))


def test_the_counts_cover_only_the_values_that_were_sent() -> None:
    answers = lookup(fake(), asking(GOOD, "C9300 48P"))

    uses = {use.endpoint: use for use in answers.tally.endpoints}
    assert uses[CiscoEndpoint.EOX].values == 2  # one PID and one release, none for the odd value
    assert uses[CiscoEndpoint.SUGGESTION].values == 1
    assert uses[CiscoEndpoint.COMPATIBLE].values == 1


def test_a_source_whose_values_were_all_odd_says_why_instead_of_reading_as_nothing_found() -> None:
    cisco = fake()
    asked = LookupQuestions(
        releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a"),),
        hardware_pids=("C9300 48P",),
        suggestion_pids=(GOOD,),
    )

    answers = lookup(cisco, asked)

    assert isinstance(answers.hardware_eox, SourceUnavailable)
    assert "safe pattern" in answers.hardware_eox.reason
    assert isinstance(answers.suggestions, SuggestionsAnswer)
    assert isinstance(answers.advisories[0], AdvisoriesAnswer)
    assert not any("EOXByProductID" in path for path in cisco.paths())


def test_when_every_value_is_odd_nothing_is_sent_and_every_source_says_why() -> None:
    cisco = fake()

    answers = lookup(
        cisco,
        LookupQuestions(
            hardware_pids=("C9300 48P",),
            suggestion_pids=("C9300 48P",),
            compatible_pids=("C9300 48P",),
        ),
    )

    assert cisco.requests == []
    assert answers.tally.token.outcome is TokenOutcome.NOT_REQUESTED
    assert isinstance(answers.hardware_eox, SourceUnavailable)
    assert isinstance(answers.suggestions, SourceUnavailable)
    assert isinstance(answers.compatible, SourceUnavailable)


def test_the_fake_has_its_own_pid_path_rule_not_the_codes_safe_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A loosened code pattern must not make the fake accept an odd PID (#155).

    The fake's rule is its own literal path check, so it never imports `is_safe_pid`. The
    planted violation below makes the code's pattern accept anything, and the fake must
    ignore it.
    """
    monkeypatch.setattr("tests.support.fake_cisco.is_safe_pid", lambda _value: True, raising=False)
    request = HttpRequest(
        host="apix.cisco.com",
        port=443,
        method="GET",
        path="/supporttools/eox/rest/5/EOXByProductID/1/C9300;48P",
        headers=(("Authorization", f"Bearer {TOKEN}"),),
    )

    with pytest.raises(UnsafeValueSentError):
        FakeCisco()(request)
