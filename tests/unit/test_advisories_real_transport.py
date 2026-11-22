"""The real online path on in-memory sockets: token, request, reply, parsed answer (#149).

Every other Cisco test swaps in `FakeCisco` at the `Transport` seam, so the real `Session`
and the real `HttpsTransport` never meet a real `http.client`. Here only `socket.create_connection`
and the TLS handshake are faked (`tests/support/fake_cisco.py`: `FakeNetwork`), so the tool's
own request line, headers, fencing, reply reading and `ask_cisco` parsing all run. All data is
synthetic.
"""

import base64
import json
import socket

import pytest

from network_analyser.advisories import HttpsTransport, Pacer, ask_cisco
from network_analyser.advisories.proxy import ProxyConfig
from network_analyser.credentials import Secret
from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoOsType,
    CompatibleAnswers,
    EoxAnswer,
    LookupQuestions,
    ReleaseQuestion,
    SuggestionsAnswer,
    TokenOutcome,
)
from tests.support import fake_cisco
from tests.support.fake_cisco import FakeNetwork

PID = "C9300-48P"
RELEASE = "17.9.4a"


def http_reply(document: object, status: int = 200) -> bytes:
    """Return one raw HTTP reply with a JSON body, as Cisco would send it."""
    body = json.dumps(document).encode()
    head = (
        f"HTTP/1.1 {status} OK\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    )
    return head.encode() + body


def network(monkeypatch: pytest.MonkeyPatch) -> FakeNetwork:
    """Put in-memory sockets and an in-memory TLS handshake under the real transport."""
    fake = FakeNetwork(
        replies=[
            (
                fake_cisco.TOKEN_PATH,
                http_reply(
                    {
                        "access_token": fake_cisco.TOKEN,
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }
                ),
            ),
            (
                fake_cisco.ADVISORY_PREFIX,
                http_reply(
                    {
                        "advisories": [
                            {
                                "advisoryId": "cisco-sa-test-149",
                                "advisoryTitle": "Synthetic advisory",
                                "sir": "High",
                                "cvssBaseScore": "8.6",
                                "cves": ["CVE-2026-0149"],
                                "firstPublished": "2026-01-01T00:00:00",
                                "lastUpdated": "2026-02-01T00:00:00",
                                "firstFixed": ["17.9.5"],
                            }
                        ]
                    }
                ),
            ),
            (
                f"{fake_cisco.EOX_PREFIX}EOXByProductID/",
                http_reply(
                    {
                        "EOXRecord": [
                            {
                                "EOLProductID": PID,
                                "EOXInputValue": PID,
                                "EOXInputType": "PID",
                                "LastDateOfSupport": {"value": "2099-01-01"},
                            }
                        ],
                        "PaginationResponseRecord": {"LastIndex": 1},
                    }
                ),
            ),
            (
                f"{fake_cisco.EOX_PREFIX}EOXBySWReleaseString/",
                http_reply(
                    {
                        "EOXRecord": [
                            {
                                "EOLProductID": RELEASE,
                                "EOXInputValue": RELEASE,
                                "EOXInputType": "Software",
                                "LastDateOfSupport": {"value": "2099-01-01"},
                            }
                        ],
                        "PaginationResponseRecord": {"LastIndex": 1},
                    }
                ),
            ),
            (
                fake_cisco.SUGGESTION_PREFIX,
                http_reply(
                    {
                        "productList": [
                            {
                                "product": {"basePID": PID, "productName": "Synthetic product"},
                                "suggestions": [
                                    {
                                        "relDispName": "17.9.5",
                                        "isSuggested": "Y",
                                        "releaseDate": "2026-03-01",
                                        "trainDispName": "17.9",
                                    }
                                ],
                            }
                        ]
                    }
                ),
            ),
            (
                fake_cisco.COMPATIBLE_PREFIX,
                http_reply(
                    {
                        "suggestions": [
                            {
                                "releaseFormat1": "17.12.8",
                                "isSuggested": "N",
                                "releaseTrain": "17.12",
                                "releaseLifeCycle": "MD",
                            }
                        ],
                        "paginationResponseRecord": {"pageIndex": 1, "lastIndex": 1},
                    }
                ),
            ),
        ]
    )
    monkeypatch.setattr(socket, "create_connection", fake.create_connection)
    monkeypatch.setattr(
        "network_analyser.advisories.transport.client_context", lambda: fake.context
    )
    return fake


def real_transport() -> HttpsTransport:
    """Return the real transport with a direct connection and no registry read."""
    return HttpsTransport(proxy=ProxyConfig.direct(), system_proxy=lambda: None)


def questions() -> LookupQuestions:
    return LookupQuestions(
        releases=(ReleaseQuestion(CiscoOsType.IOS_XE, RELEASE),),
        hardware_pids=(PID,),
        software_releases=(RELEASE,),
        suggestion_pids=(PID,),
        compatible_pids=(PID,),
    )


def test_ask_cisco_runs_the_real_transport_from_the_token_to_each_parsed_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = network(monkeypatch)

    answers = ask_cisco(
        questions(),
        Secret(fake_cisco.CLIENT_ID),
        Secret(fake_cisco.CLIENT_SECRET),
        transport=real_transport(),
    )

    assert answers.tally.token.outcome is TokenOutcome.OK
    (advisory,) = answers.advisories
    assert isinstance(advisory, AdvisoriesAnswer)
    assert advisory.advisories[0].advisory_id == "cisco-sa-test-149"
    hardware = answers.hardware_eox
    software = answers.software_eox
    assert isinstance(hardware, EoxAnswer)
    assert hardware.records[0].product_id == PID
    assert isinstance(software, EoxAnswer)
    assert software.records[0].input_value == RELEASE
    suggestions = answers.suggestions
    assert isinstance(suggestions, SuggestionsAnswer)
    assert suggestions.answers[0].product_id == PID
    compatible = answers.compatible
    assert isinstance(compatible, CompatibleAnswers)
    assert [(item.release, item.lifecycle) for item in compatible.answers[0].releases] == [
        ("17.12.8", "MD")
    ]
    assert fake.context.server_names == [
        "id.cisco.com",
        "apix.cisco.com",
        "apix.cisco.com",
        "apix.cisco.com",
        "apix.cisco.com",
        "apix.cisco.com",
    ]


def test_the_real_transport_sends_the_token_envelope_and_the_bearer_on_every_api_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = network(monkeypatch)

    ask_cisco(
        questions(),
        Secret(fake_cisco.CLIENT_ID),
        Secret(fake_cisco.CLIENT_SECRET),
        transport=real_transport(),
        pacer=Pacer(clock=lambda: 0.0, wait=lambda _seconds: None),
    )

    requests = [bytes(sock.sent) for sock in fake.context.tls_sockets]
    (token_request, *api_requests) = requests
    assert token_request.startswith(b"POST /oauth2/default/v1/token HTTP/1.1\r\n")
    basic = base64.b64encode(f"{fake_cisco.CLIENT_ID}:{fake_cisco.CLIENT_SECRET}".encode()).decode(
        "ascii"
    )
    assert f"Authorization: Basic {basic}\r\n".encode() in token_request
    assert b"grant_type=client_credentials&scope=customscope" in token_request
    assert api_requests
    for request in api_requests:
        assert f"Authorization: Bearer {fake_cisco.TOKEN}\r\n".encode() in request
        assert fake_cisco.CLIENT_ID.encode() not in request
        assert fake_cisco.CLIENT_SECRET.encode() not in request
        assert b"currentRelease" not in request
    assert fake.sent_in_clear() == b""
