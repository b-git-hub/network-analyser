"""`ask_cisco`: the lookup questions in, Cisco's answers out (#95; story 18; ADR 0007).

One request per distinct question. EoX takes 20 values per call and Software Suggestion 10;
openVuln takes one release at a time. Every value is de-duplicated again here, and every value
is checked against its pattern before a Session is made. A value out of pattern refuses the
whole lookup with nothing sent: the questions are built from pattern-checked device data
(ticket #104), so one that arrives here is a bug or an attack, and either way it must not
leave the PC (story 13).

`check_api_key` is the same token request on its own, for `cisco-key set` (ticket #103).
"""

from collections.abc import Iterable, Iterator, Sequence
from typing import Final

from network_analyser.advisories.pacing import Pacer
from network_analyser.advisories.patterns import (
    is_safe_pid,
    is_safe_platform_alias,
    is_safe_release,
)
from network_analyser.advisories.proxy import ProxyConfig
from network_analyser.advisories.replies import (
    advisories_answer,
    eox_answer,
    eox_last_page,
    suggestion_answer,
)
from network_analyser.advisories.session import REJECTED, CallOutcome, Session
from network_analyser.advisories.transport import Transport
from network_analyser.credentials import Secret, SecretScan
from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoAnswers,
    CiscoCallTally,
    CiscoEndpoint,
    CiscoOsType,
    EndpointUse,
    EoxAnswer,
    EoxRecord,
    EoxUnanswered,
    LookupQuestions,
    ReleaseQuestion,
    SourceUnavailable,
    SuggestionAnswer,
    SuggestionsAnswer,
    SuggestionUnanswered,
    TokenOutcome,
    TokenResult,
)

EOX_BATCH_SIZE: Final = 20
"""Cisco's EoX limit: 20 PIDs or release strings per call (story 18)."""

SUGGESTION_BATCH_SIZE: Final = 10
"""Cisco's Software Suggestion limit: 10 base PIDs per call (story 18)."""

REFUSED: Final = "Cisco was not asked: a lookup value did not match its safe pattern"
"""Fixed text when an outbound value is refused (story 13)."""

UNAVAILABLE: Final = "Cisco did not answer"
"""Fixed text for a call that brought back nothing at all."""


def ask_cisco(  # noqa: PLR0913 (the one Run call, every dependency explicit)
    questions: LookupQuestions,
    client_id: Secret,
    client_secret: Secret,
    *,
    transport: Transport | None = None,
    proxy: ProxyConfig | None = None,
    pacer: Pacer | None = None,
    scan: SecretScan | None = None,
) -> CiscoAnswers:
    """Ask Cisco everything `questions` names and return the answers with the call counts.

    `transport` is the test seam (the real fenced HTTPS transport by default). `scan` is the
    Run's secret scan: the client ID, the secret and the token join it as soon as they exist.
    An auth rejection stops all further calls, and every source still to be asked is
    `SourceUnavailable`, so a rejected key never reads as "nothing found".
    """
    distinct = _distinct(questions)
    if not _all_safe(distinct):
        return _refused(distinct)
    if _is_empty(distinct):
        return _nothing_asked()
    session = Session(
        client_id,
        client_secret,
        transport=transport,
        proxy=proxy,
        pacer=pacer,
        scan=scan,
    )
    result = session.token()
    if result.outcome is not TokenOutcome.OK:
        reason = session.token_reason or UNAVAILABLE
        return _unavailable(distinct, reason, session.tally())
    return CiscoAnswers(
        advisories=tuple(_advisory(session, question) for question in distinct.releases),
        hardware_eox=_eox(session, "EOXByProductID", distinct.hardware_pids),
        software_eox=_eox(session, "EOXBySWReleaseString", distinct.software_releases),
        suggestions=_suggestions(session, distinct.suggestion_pids),
        tally=session.tally(),
    )


def check_api_key(  # noqa: PLR0913 (the token-only check, every dependency explicit)
    client_id: Secret,
    client_secret: Secret,
    *,
    transport: Transport | None = None,
    proxy: ProxyConfig | None = None,
    pacer: Pacer | None = None,
    scan: SecretScan | None = None,
) -> TokenResult:
    """Send one token-only request to `id.cisco.com` and return its result (ticket #103).

    No API call and no device data is sent. The token itself is never returned.
    """
    session = Session(
        client_id,
        client_secret,
        transport=transport,
        proxy=proxy,
        pacer=pacer,
        scan=scan,
    )
    return session.token()


def _advisory(session: Session, question: ReleaseQuestion) -> AdvisoriesAnswer | SourceUnavailable:
    if session.auth_rejected:
        return SourceUnavailable(REJECTED)
    call = session.get(CiscoEndpoint.OPENVULN, _advisory_path(question), values=1)
    if call.outcome is CallOutcome.OK and call.response is not None:
        return advisories_answer(question, call.response.body)
    return SourceUnavailable(call.reason or UNAVAILABLE)


def _eox(session: Session, kind: str, values: Sequence[str]) -> EoxAnswer | SourceUnavailable:
    if session.auth_rejected:
        return SourceUnavailable(REJECTED)
    records: list[EoxRecord] = []
    unanswered: list[EoxUnanswered] = []
    for batch in _batches(values, EOX_BATCH_SIZE):
        page = 1
        while True:
            path = f"/supporttools/eox/rest/5/{kind}/{page}/{','.join(batch)}"
            call = session.get(CiscoEndpoint.EOX, path, values=len(batch))
            if call.outcome is not CallOutcome.OK or call.response is None:
                return SourceUnavailable(call.reason or UNAVAILABLE)
            answer = eox_answer(call.response.body)
            if isinstance(answer, SourceUnavailable):
                return answer
            records.extend(answer.records)
            unanswered.extend(answer.unanswered)
            last = eox_last_page(call.response.body)
            if page >= last:
                break
            page += 1
    return EoxAnswer(records=tuple(records), unanswered=tuple(unanswered))


def _suggestions(session: Session, values: Sequence[str]) -> SuggestionsAnswer | SourceUnavailable:
    if session.auth_rejected:
        return SourceUnavailable(REJECTED)
    answers: list[SuggestionAnswer] = []
    unanswered: list[SuggestionUnanswered] = []
    for batch in _batches(values, SUGGESTION_BATCH_SIZE):
        path = f"/software/suggestion/v2/suggestions/releases/productIds/{','.join(batch)}"
        call = session.get(CiscoEndpoint.SUGGESTION, path, values=len(batch))
        if call.outcome is not CallOutcome.OK or call.response is None:
            return SourceUnavailable(call.reason or UNAVAILABLE)
        answer = suggestion_answer(call.response.body)
        if isinstance(answer, SourceUnavailable):
            return answer
        answers.extend(answer.answers)
        unanswered.extend(answer.unanswered)
    return SuggestionsAnswer(answers=tuple(answers), unanswered=tuple(unanswered))


def _advisory_path(question: ReleaseQuestion) -> str:
    path = f"/security/advisories/v2/OSType/{question.os_type.value}?version={question.release}"
    if question.platform_alias is not None:
        return f"{path}&platformAlias={question.platform_alias}"
    return path


def _batches(values: Sequence[str], size: int) -> Iterator[tuple[str, ...]]:
    for start in range(0, len(values), size):
        yield tuple(values[start : start + size])


def _distinct(questions: LookupQuestions) -> LookupQuestions:
    """Return the questions with every repeated value removed, in the order given."""
    return LookupQuestions(
        releases=tuple(dict.fromkeys(questions.releases)),
        hardware_pids=_distinct_values(questions.hardware_pids),
        software_releases=_distinct_values(questions.software_releases),
        suggestion_pids=_distinct_values(questions.suggestion_pids),
    )


def _distinct_values(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _all_safe(questions: LookupQuestions) -> bool:
    return (
        all(_release_is_safe(question) for question in questions.releases)
        and all(is_safe_pid(pid) for pid in questions.hardware_pids)
        and all(is_safe_release(release) for release in questions.software_releases)
        and all(is_safe_pid(pid) for pid in questions.suggestion_pids)
    )


def _release_is_safe(question: ReleaseQuestion) -> bool:
    if not is_safe_release(question.release):
        return False
    if question.os_type is CiscoOsType.NX_OS:
        return question.platform_alias is not None and is_safe_platform_alias(
            question.platform_alias
        )
    return question.platform_alias is None


def _refused(questions: LookupQuestions) -> CiscoAnswers:
    """Nothing was sent, so every source is unavailable and the tally is empty."""
    empty = CiscoCallTally(
        token=TokenResult(TokenOutcome.NOT_REQUESTED),
        endpoints=tuple(
            EndpointUse(endpoint=endpoint, calls=0, values=0, retries=0)
            for endpoint in CiscoEndpoint
        ),
    )
    return _unavailable(questions, REFUSED, empty)


def _is_empty(questions: LookupQuestions) -> bool:
    return not (
        questions.releases
        or questions.hardware_pids
        or questions.software_releases
        or questions.suggestion_pids
    )


def _nothing_asked() -> CiscoAnswers:
    """No question means no connection at all: an empty Run does not ask for a token."""
    return CiscoAnswers(
        advisories=(),
        hardware_eox=EoxAnswer(records=(), unanswered=()),
        software_eox=EoxAnswer(records=(), unanswered=()),
        suggestions=SuggestionsAnswer(answers=(), unanswered=()),
        tally=CiscoCallTally(
            token=TokenResult(TokenOutcome.NOT_REQUESTED),
            endpoints=tuple(
                EndpointUse(endpoint=endpoint, calls=0, values=0, retries=0)
                for endpoint in CiscoEndpoint
            ),
        ),
    )


def _unavailable(questions: LookupQuestions, reason: str, tally: CiscoCallTally) -> CiscoAnswers:
    return CiscoAnswers(
        advisories=tuple(SourceUnavailable(reason) for _ in questions.releases),
        hardware_eox=SourceUnavailable(reason),
        software_eox=SourceUnavailable(reason),
        suggestions=SourceUnavailable(reason),
        tally=tally,
    )
