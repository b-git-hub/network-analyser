"""A refused EoX or Software Suggestion batch is split, so one value never costs the rest (#153).

A 4xx from `apix.cisco.com` that is not an auth failure is one call's refusal. EoX and Software
Suggestion send several values per call, so that batch is retried one value at a time, and only
a value whose own call still fails becomes `unanswered` with Cisco's code or `HTTP <status>`.
A 401, an auth-coded 403 or a token-endpoint `invalid_client` still stops every call, and a 5xx
or a long `Retry-After` still makes the whole source unavailable, as before.

Every value, record and error here is synthetic; no live Cisco reply is used.
"""

import json
from typing import Any

import pytest

from network_analyser.advisories import Pacer, ask_cisco
from network_analyser.advisories.transport import HttpResponse
from network_analyser.credentials import Secret
from network_analyser.records.cisco import (
    CiscoAnswers,
    EoxAnswer,
    LookupQuestions,
    SourceUnavailable,
    SuggestionsAnswer,
)
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco

SWITCH = "C9300-48P"
OTHER_SWITCH = "C9300-24P"
EOX = "/supporttools"
SUGGESTION = "/software/suggestion/v2/suggestions/releases"


def eox_record(product_id: str) -> dict[str, Any]:
    """One EoX record for a PID that has EoX data."""
    return {
        "EOLProductID": product_id,
        "ProductIDDescription": "Synthetic switch",
        "ProductBulletinNumber": "EOL-SYNTHETIC-153",
        "LinkToProductBulletinURL": "https://cisco.example/bulletin",
        "EndOfSaleDate": {"value": "2025-01-01"},
        "EOXInputType": "PID",
        "EOXInputValue": product_id,
    }


def eox_reply(*entries: dict[str, Any], last_page: int = 1) -> HttpResponse:
    """An EoX reply carrying `entries`, naming `last_page` pages."""
    return _reply(
        {"EOXRecord": list(entries), "PaginationResponseRecord": {"LastIndex": last_page}}
    )


def suggestion_reply(*entries: dict[str, Any]) -> HttpResponse:
    """A Software Suggestion reply as Cisco shapes it: a `productList`."""
    return _reply({"productList": list(entries)})


def suggestion_entry(product_id: str, release: str) -> dict[str, Any]:
    """One known base PID and one suggested release."""
    return {
        "product": {"basePID": product_id, "productName": "synthetic product"},
        "suggestions": [{"relDispName": release, "isSuggested": "Y"}],
    }


def _reply(document: object) -> HttpResponse:
    return HttpResponse(
        status=200,
        headers=(("Content-Type", "application/json"),),
        body=json.dumps(document).encode(),
    )


def _refused(status: int, code: str = "") -> HttpResponse:
    document = {} if not code else {"errorCode": code, "errorMessage": "synthetic"}
    return HttpResponse(
        status=status,
        headers=(("Content-Type", "application/json"),),
        body=json.dumps(document).encode(),
    )


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


def eox_paths(cisco: FakeCisco) -> list[str]:
    """Every EoX path asked, in order."""
    return [path for path in cisco.paths() if path.startswith(EOX)]


def suggestion_paths(cisco: FakeCisco) -> list[str]:
    """Every Software Suggestion release path asked, in order."""
    return [path for path in cisco.paths() if path.startswith(SUGGESTION)]


def test_a_4xx_on_a_two_value_eox_batch_splits_it_and_keeps_the_value_that_answers() -> None:
    cisco = FakeCisco()
    cisco.scripted.extend(
        [
            (EOX, _refused(400)),
            (EOX, eox_reply(eox_record(SWITCH))),
            (EOX, _refused(400, "SSA_ERR_026")),
        ]
    )

    answers = lookup(cisco, LookupQuestions(hardware_pids=(SWITCH, OTHER_SWITCH)))

    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [record.product_id for record in answers.hardware_eox.records] == [SWITCH]
    assert [(item.input_value, item.reason) for item in answers.hardware_eox.unanswered] == [
        (OTHER_SWITCH, "SSA_ERR_026")
    ]
    paths = eox_paths(cisco)
    assert len(paths) == 3  # the refused batch, then one call per value
    assert paths[-2].endswith(f"/1/{SWITCH}")
    assert paths[-1].endswith(f"/1/{OTHER_SWITCH}")


def test_a_refused_value_with_no_cisco_code_says_http_and_the_status() -> None:
    cisco = FakeCisco()
    cisco.scripted.extend(
        [
            (EOX, _refused(400)),
            (EOX, eox_reply(eox_record(SWITCH))),
            (EOX, _refused(404)),
        ]
    )

    answers = lookup(cisco, LookupQuestions(hardware_pids=(SWITCH, OTHER_SWITCH)))

    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert [(item.input_value, item.reason) for item in answers.hardware_eox.unanswered] == [
        (OTHER_SWITCH, "HTTP 404")
    ]


def test_a_refused_one_value_eox_batch_is_that_values_answer_without_a_split() -> None:
    cisco = FakeCisco()
    cisco.scripted.append((EOX, _refused(400, "INVALID_PRODUCT_ID")))

    answers = lookup(cisco, LookupQuestions(hardware_pids=(SWITCH,)))

    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert answers.hardware_eox.records == ()
    assert [(item.input_value, item.reason) for item in answers.hardware_eox.unanswered] == [
        (SWITCH, "INVALID_PRODUCT_ID")
    ]
    assert len(eox_paths(cisco)) == 1


def test_a_4xx_on_a_two_pid_suggestion_batch_splits_it_and_keeps_the_pid_that_answers() -> None:
    cisco = FakeCisco()
    cisco.scripted.extend(
        [
            (SUGGESTION, _refused(400)),
            (SUGGESTION, suggestion_reply(suggestion_entry(SWITCH, "17.9.5"))),
            (SUGGESTION, _refused(400, "S3_INV_BASEPID")),
        ]
    )

    answers = lookup(cisco, LookupQuestions(suggestion_pids=(SWITCH, OTHER_SWITCH)))

    assert isinstance(answers.suggestions, SuggestionsAnswer)
    (known,) = answers.suggestions.answers
    assert known.product_id == SWITCH
    assert [(item.product_id, item.reason) for item in answers.suggestions.unanswered] == [
        (OTHER_SWITCH, "S3_INV_BASEPID")
    ]
    paths = suggestion_paths(cisco)
    assert len(paths) == 3
    assert paths[-2].endswith(f"/{SWITCH}")
    assert paths[-1].endswith(f"/{OTHER_SWITCH}")


def test_a_401_on_an_eox_batch_stops_every_call_and_is_never_split() -> None:
    cisco = FakeCisco()
    cisco.scripted.append((EOX, _refused(401)))

    answers = lookup(
        cisco,
        LookupQuestions(
            hardware_pids=(SWITCH, OTHER_SWITCH),
            suggestion_pids=(SWITCH, OTHER_SWITCH),
        ),
    )

    assert answers.hardware_eox == SourceUnavailable("Cisco's token expired")
    assert isinstance(answers.suggestions, SourceUnavailable)
    assert eox_paths(cisco) == [f"{EOX}/eox/rest/5/EOXByProductID/1/{SWITCH},{OTHER_SWITCH}"]
    assert suggestion_paths(cisco) == []


@pytest.mark.parametrize(
    "code",
    ["ERR_403_NOT_AUTHORIZED", "ERR_403_DEVELOPER_INACTIVE"],
)
def test_an_auth_coded_403_on_a_batch_stops_every_call_and_is_never_split(code: str) -> None:
    cisco = FakeCisco()
    cisco.scripted.append(
        (
            EOX,
            HttpResponse(status=403, headers=(("X-Mashery-Error-Code", code),), body=b""),
        )
    )

    answers = lookup(
        cisco,
        LookupQuestions(
            hardware_pids=(SWITCH, OTHER_SWITCH),
            suggestion_pids=(SWITCH, OTHER_SWITCH),
        ),
    )

    assert answers.hardware_eox == SourceUnavailable("Cisco rejected the API key")
    assert isinstance(answers.suggestions, SourceUnavailable)
    assert len(eox_paths(cisco)) == 1
    assert suggestion_paths(cisco) == []


def test_a_5xx_that_holds_after_the_one_retry_still_makes_the_whole_source_unavailable() -> None:
    cisco = FakeCisco()
    down = HttpResponse(status=500, body=b"")
    cisco.scripted.extend([(EOX, down), (EOX, down)])

    answers = lookup(cisco, LookupQuestions(hardware_pids=(SWITCH, OTHER_SWITCH)))

    assert answers.hardware_eox == SourceUnavailable("Cisco returned HTTP 500")
    assert len(eox_paths(cisco)) == 2  # the call and its one retry; no split


def test_a_4xx_on_a_later_eox_page_leaves_the_page_one_records_in_place() -> None:
    cisco = FakeCisco()
    cisco.scripted.extend(
        [
            (EOX, eox_reply(eox_record(SWITCH), last_page=2)),
            (EOX, _refused(400)),
        ]
    )

    answers = lookup(cisco, LookupQuestions(hardware_pids=(SWITCH, OTHER_SWITCH)))

    assert answers.hardware_eox == SourceUnavailable("Cisco returned HTTP 400")
    assert len(eox_paths(cisco)) == 2  # the batch's two pages; no per-value split


def test_the_split_sends_only_the_pids_and_counts_the_calls() -> None:
    cisco = FakeCisco()
    cisco.scripted.extend(
        [
            (EOX, _refused(400)),
            (EOX, eox_reply(eox_record(SWITCH))),
            (EOX, eox_reply(eox_record(OTHER_SWITCH))),
        ]
    )

    answers = lookup(cisco, LookupQuestions(hardware_pids=(SWITCH, OTHER_SWITCH)))

    assert isinstance(answers.hardware_eox, EoxAnswer)
    assert all(is_plain_pid_path(path) for path in eox_paths(cisco))
    use = next(item for item in answers.tally.endpoints if item.endpoint.value == "EoX")
    assert use.calls == 3
    assert use.retries == 0


def is_plain_pid_path(path: str) -> bool:
    """Whether a path carries only the two synthetic PIDs, and no other value."""
    prefix, _, rest = path.partition("/EOXByProductID/")
    if not prefix:
        return False
    page, _, values = rest.partition("/")
    return page.isdigit() and set(values.split(",")) <= {SWITCH, OTHER_SWITCH}
