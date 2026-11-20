"""The threat model at the `advisories` seam: no secret in an answer, no reply text trusted,
and a redirect or an odd value going nowhere (#95, stories 13, 16, 22, 40, 117).

The fake Cisco already refuses an out-of-pattern value or a request without the token, so
these tests concentrate on what comes back: the keys, the token, the counts and Cisco's own
text.
"""

from network_analyser.advisories import Pacer, ask_cisco
from network_analyser.advisories.transport import HttpResponse
from network_analyser.credentials import BLOCKED, Secret, SecretScan
from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoAnswers,
    CiscoEndpoint,
    CiscoOsType,
    LookupQuestions,
    ReleaseQuestion,
    SourceUnavailable,
    TokenOutcome,
)
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, TOKEN, FakeCisco


def advisory_text() -> dict[str, object]:
    return {
        "advisoryId": "cisco-sa-test\x1b[31m",
        "advisoryTitle": "Synthetic\r\nadvisory\x00 \x1b]0;title\x07 " + "A" * 600,
        "sir": "High\x1b",
        "cvssBaseScore": "9.8",
        "cves": ["CVE-2026-0001"],
        "firstPublished": "2026-01-01",
        "lastUpdated": "2026-02-01",
        "firstFixed": ["17.9.5"],
    }


def fast_pacer() -> Pacer:
    now = [0.0]

    def wait(seconds: float) -> None:
        now[0] += seconds

    return Pacer(clock=lambda: now[0], wait=wait)


def questions() -> LookupQuestions:
    return LookupQuestions(releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a"),))


def full_fake() -> FakeCisco:
    return FakeCisco(
        advisories={("iosxe", "17.9.4a", None): [advisory_text()]},
        eox_pid={
            "C9300-48P": {
                "EOLProductID": "C9300-48P",
                "ProductIDDescription": "Synthetic\x1b switch",
                "ProductBulletinNumber": "EOL-1",
                "LinkToProductBulletinURL": "https://cisco.example/b",
                "EndOfSaleDate": {"value": "2025-01-01"},
                "EndOfSecurityVulSupportDate": {"value": "2026-01-01"},
                "LastDateOfSupport": {"value": "2027-01-01"},
                "EOXMigrationDetails": {"MigrationProductId": "C9300-24P"},
                "EOXInputType": "PID",
                "EOXInputValue": "C9300-48P",
            }
        },
        suggestions={"C9300-48P": [{"relDispName": "17.9.5", "isSuggested": "Y"}]},
    )


def answers_with(scan: SecretScan | None = None) -> CiscoAnswers:
    fake = full_fake()
    return ask_cisco(
        LookupQuestions(
            releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a"),),
            hardware_pids=("C9300-48P",),
            software_releases=("17.9.4a",),
            suggestion_pids=("C9300-48P",),
        ),
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=fake,
        pacer=fast_pacer(),
        scan=scan,
    )


def test_no_answer_carries_the_client_id_the_secret_or_the_token() -> None:
    answers = answers_with()

    text = repr(answers)

    assert CLIENT_ID not in text
    assert CLIENT_SECRET not in text
    assert TOKEN not in text
    assert answers.tally.token.outcome is TokenOutcome.OK


def test_the_three_secrets_join_the_scan_as_soon_as_they_exist() -> None:
    scan = SecretScan()

    answers_with(scan)

    blocked, hits = scan.contains_secret(f"{CLIENT_ID} {CLIENT_SECRET} {TOKEN}")
    assert blocked == f"{BLOCKED} {BLOCKED} {BLOCKED}"
    assert hits == 3


def test_the_tally_is_counts_only() -> None:
    answers = answers_with()

    assert {use.endpoint for use in answers.tally.endpoints} == set(CiscoEndpoint)
    for use in answers.tally.endpoints:
        assert type(use.calls) is int
        assert type(use.values) is int
        assert type(use.retries) is int
    assert answers.tally.token.status == 200
    assert answers.tally.token.error_code is None


def test_ciscos_text_is_flattened_and_bounded_before_it_crosses_the_boundary() -> None:
    answers = answers_with()

    first = answers.advisories[0]
    assert isinstance(first, AdvisoriesAnswer)
    advisory = first.advisories[0]
    for text in (
        advisory.advisory_id,
        advisory.title,
        advisory.sir,
        *advisory.first_fixed,
    ):
        assert "\x1b" not in text
        assert "\x00" not in text
        assert "\x07" not in text
        assert "\r" not in text
        assert "\n" not in text
    assert len(advisory.title) <= 300


def test_a_redirect_reply_is_never_followed() -> None:
    fake = FakeCisco()
    fake.scripted.append(
        (
            "/security",
            HttpResponse(
                status=302,
                headers=(("Location", "https://evil.example/"),),
                body=b"follow me",
            ),
        )
    )

    answers = ask_cisco(
        questions(),
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=fake,
        pacer=fast_pacer(),
    )

    # One advisory request: the token, then this one. A redirect is not retried or followed.
    assert len(fake.api_requests()) == 1
    assert isinstance(answers.advisories[0], SourceUnavailable)
    assert answers.advisories[0].reason == "Cisco returned HTTP 302"


def test_a_refused_value_sends_nothing_at_all() -> None:
    fake = FakeCisco()

    answers = ask_cisco(
        LookupQuestions(releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a\r\nX-Evil: 1"),)),
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=fake,
        pacer=fast_pacer(),
    )

    assert fake.requests == []
    assert answers.tally.token.outcome is TokenOutcome.NOT_REQUESTED
    assert isinstance(answers.advisories[0], SourceUnavailable)


def test_a_source_that_is_down_never_reads_as_nothing_found() -> None:
    fake = FakeCisco(outage=True)

    answers = ask_cisco(
        questions(),
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=fake,
        pacer=fast_pacer(),
    )

    assert isinstance(answers.advisories[0], SourceUnavailable)
    assert isinstance(answers.hardware_eox, SourceUnavailable)
    assert isinstance(answers.software_eox, SourceUnavailable)
    assert isinstance(answers.suggestions, SourceUnavailable)


def test_the_fake_sees_only_a_pattern_checked_path() -> None:
    # The fake raises on an out-of-pattern value, so a plain successful run proves the path.
    fake = full_fake()

    ask_cisco(
        LookupQuestions(releases=(ReleaseQuestion(CiscoOsType.IOS_XE, "17.9.4a"),)),
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=fake,
        pacer=fast_pacer(),
    )

    assert fake.paths() == [
        "/oauth2/default/v1/token",
        "/security/advisories/v2/OSType/iosxe?version=17.9.4a",
    ]
