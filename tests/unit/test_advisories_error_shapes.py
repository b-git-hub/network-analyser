"""Cisco's per-value error shapes: one value with no data, every other one still answered (#166).

The shapes came from #148's live runs, recorded there as types and lengths only. A hardware
EoX reply keeps the normal `EOXRecord` envelope and puts a value with no EoX data in an entry
with empty `EOLProductID` and `EOXInputValue` and a nested `EOXError`. A Software Suggestion
reply puts an unknown PID in a `productList` entry whose `product` has no `basePID`, with the
code in `suggestions[].errorDetailsResponse`. A top-level `EOXError` refuses the whole call.
Each is Cisco's code for that value, never "not understood" for its whole source.

Every reply here is synthetic, written for these tests; no value from a live reply is used.
"""

import json
from typing import Any

from network_analyser.advisories import HttpRequest, Pacer, ask_cisco
from network_analyser.advisories.transport import HttpResponse
from network_analyser.credentials import Secret
from network_analyser.records.cisco import (
    CiscoAnswers,
    EoxAnswer,
    LookupQuestions,
    SourceUnavailable,
    SuggestionsAnswer,
    TokenOutcome,
)
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, TOKEN, FakeCisco

SWITCH = "C9300-48P"
OTHER_SWITCH = "C9300-24P"
NO_DATA_CODE = "SSA_ERR_026"
UNKNOWN_PID_CODE = "S3_INV_BASEPID"


def eox_record(product_id: str) -> dict[str, Any]:
    """One EoX record with every field filled, as a PID that has EoX data gets."""
    return {
        "EOLProductID": product_id,
        "ProductIDDescription": "Synthetic switch",
        "ProductBulletinNumber": "EOL-SYNTHETIC-166",
        "LinkToProductBulletinURL": "https://cisco.example/bulletin",
        "EndOfSaleDate": {"value": "2025-01-01"},
        "EndOfSWMaintenanceReleases": {"value": "2025-06-01"},
        "EndOfSecurityVulSupportDate": {"value": "2026-01-01"},
        "LastDateOfSupport": {"value": "2027-01-01"},
        "EOXInputType": "PID",
        "EOXInputValue": product_id,
    }


def eox_no_data() -> dict[str, Any]:
    """The entry Cisco returns for a PID with no EoX data: no ids, and the code nested (#148)."""
    return {
        "EOLProductID": "",
        "EOXInputValue": "",
        "EOXInputType": "PID",
        "EOXError": {"ErrorID": NO_DATA_CODE, "ErrorDescription": "synthetic"},
    }


def eox_reply(*entries: dict[str, Any], last_page: int = 1) -> HttpResponse:
    """An EoX reply carrying `entries`, naming `last_page` pages."""
    return _reply(
        {
            "EOXRecord": list(entries),
            "PaginationResponseRecord": {"LastIndex": last_page},
        }
    )


def suggestion_no_data() -> dict[str, Any]:
    """The entry Cisco returns for a PID Software Suggestion does not know (#148)."""
    return {
        "product": {},
        "suggestions": [{"errorDetailsResponse": {"errorCode": UNKNOWN_PID_CODE}}],
    }


def suggestion_releases(product_id: str, release: str) -> dict[str, Any]:
    """One `productList` entry with a known PID and one suggested release."""
    return {
        "product": {"basePID": product_id, "productName": "synthetic product"},
        "suggestions": [{"relDispName": release, "isSuggested": "Y"}],
    }


def suggestion_reply(*entries: dict[str, Any]) -> HttpResponse:
    """A Software Suggestion reply as Cisco shapes it: a `productList`."""
    return _reply({"productList": list(entries)})


def _reply(document: object) -> HttpResponse:
    return HttpResponse(
        status=200,
        headers=(("Content-Type", "application/json"),),
        body=json.dumps(document).encode(),
    )


def _body(cisco: FakeCisco, path: str) -> dict[str, Any]:
    """The JSON document the fake answers one API path with."""
    reply = cisco(
        HttpRequest(
            host="apix.cisco.com",
            port=443,
            method="GET",
            path=path,
            headers=(("Authorization", f"Bearer {TOKEN}"),),
        )
    )
    assert isinstance(reply, HttpResponse)
    document: dict[str, Any] = json.loads(reply.body)
    return document


def lookup(cisco: FakeCisco, asked: LookupQuestions) -> CiscoAnswers:
    """Ask the fake Cisco through the module's public interface, with no sleeping."""
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


def test_a_record_level_eox_error_is_ciscos_code_for_the_pid_in_that_position() -> None:
    cisco = FakeCisco()
    cisco.scripted.append(
        ("/supporttools", eox_reply(eox_record(SWITCH), eox_no_data())),
    )

    answers = lookup(cisco, LookupQuestions(hardware_pids=(SWITCH, OTHER_SWITCH)))

    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [record.product_id for record in answers.hardware_eox.records] == [SWITCH]
    assert [(item.input_value, item.reason) for item in answers.hardware_eox.unanswered] == [
        (OTHER_SWITCH, NO_DATA_CODE)
    ]
    assert answers.tally.token.outcome is TokenOutcome.OK


def test_an_eox_error_record_stays_unnamed_when_the_reply_has_more_entries_than_values() -> None:
    cisco = FakeCisco()
    cisco.scripted.append(
        (
            "/supporttools",
            eox_reply(eox_record(SWITCH), eox_record(SWITCH), eox_no_data()),
        ),
    )

    answers = lookup(cisco, LookupQuestions(hardware_pids=(SWITCH, OTHER_SWITCH)))

    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [(item.input_value, item.reason) for item in answers.hardware_eox.unanswered] == [
        (None, NO_DATA_CODE)
    ]


def test_an_eox_error_record_stays_unnamed_on_a_paged_reply() -> None:
    cisco = FakeCisco()
    cisco.scripted.extend(
        [
            ("/supporttools", eox_reply(eox_no_data(), eox_record(SWITCH), last_page=2)),
            ("/supporttools", eox_reply(eox_record(OTHER_SWITCH), last_page=2)),
        ]
    )

    answers = lookup(cisco, LookupQuestions(hardware_pids=(SWITCH, OTHER_SWITCH)))

    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [record.product_id for record in answers.hardware_eox.records] == [
        SWITCH,
        OTHER_SWITCH,
    ]
    assert [(item.input_value, item.reason) for item in answers.hardware_eox.unanswered] == [
        (None, NO_DATA_CODE)
    ]


def test_a_top_level_eox_error_is_the_whole_source_unavailable_with_ciscos_code() -> None:
    cisco = FakeCisco()
    cisco.scripted.append(
        (
            "/supporttools",
            _reply({"EOXError": {"ErrorID": NO_DATA_CODE, "ErrorDescription": "synthetic"}}),
        ),
    )

    answers = lookup(cisco, LookupQuestions(hardware_pids=(SWITCH,)))

    assert isinstance(answers.hardware_eox, SourceUnavailable)
    assert NO_DATA_CODE in answers.hardware_eox.reason
    assert "not understood" not in answers.hardware_eox.reason


def test_a_software_suggestion_batch_answers_the_pids_it_knows_and_marks_the_rest() -> None:
    cisco = FakeCisco()
    cisco.scripted.append(
        (
            "/software/suggestion/v2/suggestions/releases",
            suggestion_reply(
                suggestion_releases(SWITCH, "17.9.5"),
                suggestion_no_data(),
            ),
        ),
    )

    answers = lookup(cisco, LookupQuestions(suggestion_pids=(SWITCH, OTHER_SWITCH)))

    assert isinstance(answers.suggestions, SuggestionsAnswer)
    (known,) = answers.suggestions.answers
    assert known.product_id == SWITCH
    assert [release.release for release in known.releases] == ["17.9.5"]
    assert [(item.product_id, item.reason) for item in answers.suggestions.unanswered] == [
        (OTHER_SWITCH, UNKNOWN_PID_CODE)
    ]


def test_the_fakes_own_error_entries_answer_the_values_that_have_data() -> None:
    cisco = FakeCisco(
        eox_pid={SWITCH: eox_record(SWITCH)},
        suggestions={SWITCH: [{"relDispName": "17.9.5", "isSuggested": "Y"}]},
    )

    answers = lookup(
        cisco,
        LookupQuestions(
            hardware_pids=(SWITCH, OTHER_SWITCH),
            suggestion_pids=(SWITCH, OTHER_SWITCH),
        ),
    )

    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [record.product_id for record in answers.hardware_eox.records] == [SWITCH]
    assert [(item.input_value, item.reason) for item in answers.hardware_eox.unanswered] == [
        (OTHER_SWITCH, NO_DATA_CODE)
    ]
    assert isinstance(answers.suggestions, SuggestionsAnswer)
    assert [answer.product_id for answer in answers.suggestions.answers] == [SWITCH]
    assert [(item.product_id, item.reason) for item in answers.suggestions.unanswered] == [
        (OTHER_SWITCH, UNKNOWN_PID_CODE)
    ]


def test_the_fake_answers_with_ciscos_observed_error_shapes() -> None:
    cisco = FakeCisco()

    eox = _body(cisco, f"/supporttools/eox/rest/5/EOXByProductID/1/{SWITCH},{OTHER_SWITCH}")[
        "EOXRecord"
    ][1]
    assert (eox["EOLProductID"], eox["EOXInputValue"]) == ("", "")
    assert eox["EOXError"] == {"ErrorID": NO_DATA_CODE, "ErrorDescription": "synthetic"}
    assert "ErrorCode" not in eox

    (suggestion,) = _body(
        cisco,
        f"/software/suggestion/v2/suggestions/releases/productIds/{OTHER_SWITCH}",
    )["productList"]
    assert "basePID" not in suggestion["product"]
    assert suggestion["suggestions"][0]["errorDetailsResponse"] == {"errorCode": UNKNOWN_PID_CODE}
