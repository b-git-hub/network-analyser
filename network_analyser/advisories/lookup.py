"""`ask_cisco`: the lookup questions in, Cisco's answers out (#95; story 18; ADR 0007).

One request per distinct question. EoX takes 20 values per call and Software Suggestion 10;
openVuln takes one release at a time, and the compatible list one chassis PID at a time, paged
(#127). Software EoX goes in Cisco's query form, `input1` to `input20` as `<release>,<OSType>`;
hardware EoX stays in the path (#165). Every value is de-duplicated again here, and every value
is checked against its pattern before a Session is made. A value out of pattern is dropped
on its own and never sent, and the rest of the lookup is still asked: the questions are built
from pattern-checked device data (ticket #104), so one that arrives here is a bug or an
attack, and either way it must not leave the PC (story 13, #130). Only when no value is left
is the call refused whole, with nothing sent.

`check_api_key` is the same token request on its own, for `cisco-key set` (ticket #103).
"""

from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Final

from network_analyser.advisories.pacing import Pacer
from network_analyser.advisories.patterns import (
    is_safe_pid,
    is_safe_platform_alias,
    is_safe_release,
)
from network_analyser.advisories.proxy import ProxyConfig
from network_analyser.advisories.replies import (
    NOT_UNDERSTOOD,
    advisories_answer,
    advisories_error_answer,
    compatible_answer,
    compatible_error_answer,
    compatible_last_page,
    eox_answer,
    eox_error_answer,
    eox_last_page,
    suggestion_answer,
    suggestion_error_answer,
)
from network_analyser.advisories.session import TOKEN_EXPIRED, Call, CallOutcome, Session
from network_analyser.advisories.transport import Transport
from network_analyser.credentials import Secret, SecretScan
from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoAnswers,
    CiscoCallTally,
    CiscoEndpoint,
    CiscoOsType,
    CompatibleAnswer,
    CompatibleAnswers,
    CompatibleRelease,
    CompatibleUnanswered,
    EndpointUse,
    EoxAnswer,
    EoxRecord,
    EoxUnanswered,
    LookupQuestions,
    ReleaseQuestion,
    SoftwareEoxQuestion,
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

EOX_BY_PID: Final = "EOXByProductID"
EOX_BY_RELEASE: Final = "EOXBySWReleaseString"

SOFTWARE_OS_TYPE: Final = {
    CiscoOsType.IOS: "IOS",
    CiscoOsType.IOS_XE: "IOS-XE",
}
"""The `OSType` names Cisco's software EoX query takes, for the families we know.

NX-OS is left out on purpose: its `OSType` name is not confirmed (#165), and a guessed name
would send a value we cannot stand behind.
"""

SOFTWARE_OS_UNVERIFIED: Final = (
    "NX-OS software EoX was not asked: its Cisco OSType name is unverified"
)
"""Fixed reason for an NX-OS release left out of the software EoX query (#165)."""

EOX_MAX_PAGES: Final = 20
"""The most pages one EoX batch may take: a reply naming more is refused, not chased."""

COMPATIBLE_MAX_PAGES: Final = 20
"""The most pages one chassis PID's compatible list may take; past it, `page cap` (#127)."""

PAGE_CAP: Final = "page cap"
"""Fixed text for a compatible list that ran past its page cap (#127)."""

REFUSED: Final = "Cisco was not asked: a lookup value did not match its safe pattern"
"""Fixed text when an outbound value is refused (story 13)."""

UNAVAILABLE: Final = "Cisco did not answer"
"""Fixed text for a call that brought back nothing at all."""

_UNREADABLE: Final = (
    ValueError,
    TypeError,
    ArithmeticError,
    LookupError,
    AttributeError,
    RecursionError,
)
"""What reading one odd reply can raise; only that reply's source is then not understood."""


class LookupInterrupted(Exception):  # noqa: N818 (a stop, not an error: it carries the counts)
    """The lookup stopped on something unexpected, after some calls were already made.

    Attributes:
        tally: what was sent before it stopped, as counts only, so the Audit log still proves
            what left the PC (#133).
    """

    def __init__(self, tally: CiscoCallTally) -> None:
        """Hold the counts; the cause is chained, and never shown."""
        super().__init__("Cisco lookups did not finish")
        self.tally = tally


def _understood[**P, T](
    read: Callable[P, T], *args: P.args, **kwargs: P.kwargs
) -> T | SourceUnavailable:
    """Return `read(...)`, or the fixed "not understood" when the reply cannot be read (#133)."""
    try:
        return read(*args, **kwargs)
    except _UNREADABLE:
        return SourceUnavailable(NOT_UNDERSTOOD)


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
    `SourceUnavailable`, so a rejected key never reads as "nothing found". A token that runs out
    does the same with its own fixed reason, and keeps every answer already received (#133). A reply
    that cannot be read makes only its own source "not understood"; anything unexpected raises
    `LookupInterrupted` with the counts of what was sent.
    """
    distinct = _distinct(questions)
    if _is_empty(distinct):
        return _nothing_asked()
    sendable = _sendable(distinct)
    if _is_empty(sendable):
        return _refused(distinct)
    session = Session(
        client_id,
        client_secret,
        transport=transport,
        proxy=proxy,
        pacer=pacer,
        scan=scan,
    )
    try:
        return _answers(session, distinct, sendable)
    except Exception as error:
        raise LookupInterrupted(session.tally()) from error


def _answers(
    session: Session, distinct: LookupQuestions, sendable: LookupQuestions
) -> CiscoAnswers:
    result = session.token()
    if result.outcome is not TokenOutcome.OK:
        reason = session.token_reason or UNAVAILABLE
        return _unavailable(sendable, reason, session.tally())
    return CiscoAnswers(
        advisories=tuple(_advisory(session, question) for question in sendable.releases),
        compatible=(
            _all_refused(distinct.compatible_pids, sendable.compatible_pids)
            or _compatible(session, sendable.compatible_pids)
        ),
        hardware_eox=(
            _all_refused(distinct.hardware_pids, sendable.hardware_pids)
            or _eox(
                session,
                EOX_BY_PID,
                tuple(_EoxValue(pid, pid) for pid in sendable.hardware_pids),
            )
        ),
        software_eox=(
            _all_refused(distinct.software_releases, sendable.software_releases)
            or _software_eox(session, sendable.software_releases)
        ),
        suggestions=(
            _all_refused(distinct.suggestion_pids, sendable.suggestion_pids)
            or _suggestions(session, sendable.suggestion_pids)
        ),
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
    if (stop := session.stop_reason) is not None:
        return SourceUnavailable(stop)
    if (refusing := session.source_stopped(CiscoEndpoint.OPENVULN)) is not None:
        return AdvisoriesAnswer(question=question, advisories=(), unavailable=refusing)
    call = session.get(CiscoEndpoint.OPENVULN, _advisory_path(question), values=1)
    if call.outcome is CallOutcome.OK and call.response is not None:
        return _understood(advisories_answer, question, call.response.body)
    if call.outcome is CallOutcome.CALL_FAILED and call.response is not None:
        return advisories_error_answer(question, call.response.status, call.response.body)
    return SourceUnavailable(call.reason or UNAVAILABLE)


@dataclass(frozen=True, slots=True)
class _EoxValue:
    """One EoX input: the value the Run knows it by, and the text Cisco receives.

    They differ for software EoX, whose query form sends `<release>,<OSType>` while the Run
    keeps and answers by the release alone.
    """

    key: str
    wire: str


def _software_eox(
    session: Session, questions: Sequence[SoftwareEoxQuestion]
) -> EoxAnswer | SourceUnavailable:
    """Ask software EoX in Cisco's query form, one `<release>,<OSType>` per input.

    The OS type is sent by its Cisco name; a family whose name is not confirmed is not sent,
    and that release is `unanswered` with a fixed reason (#165). Batches stay at 20 inputs.
    """
    unsent = tuple(
        EoxUnanswered(question.release, SOFTWARE_OS_UNVERIFIED)
        for question in questions
        if (os_type := SOFTWARE_OS_TYPE.get(question.os_type)) is None
    )
    values = tuple(
        _EoxValue(question.release, f"{question.release},{os_type}")
        for question in questions
        if (os_type := SOFTWARE_OS_TYPE.get(question.os_type)) is not None
    )
    if not values:
        return EoxAnswer(records=(), unanswered=unsent)
    answer = _eox(session, EOX_BY_RELEASE, values)
    if isinstance(answer, SourceUnavailable):
        return answer
    return EoxAnswer(records=answer.records, unanswered=unsent + answer.unanswered)


def _eox(session: Session, kind: str, values: Sequence[_EoxValue]) -> EoxAnswer | SourceUnavailable:
    """Ask every EoX batch, splitting a refused one so only its failing values are unanswered.

    A batch Cisco refuses with a 4xx that is not an auth failure is asked again one value at a
    time (#153), within the same Session and its pacing, so one bad value never costs its
    batch's others the answer. Only a value whose own call still fails is `unanswered`; the
    values that answer are kept. A source the breaker stopped is not asked again: every value
    still to ask is `unanswered` with its fixed reason (#154). An auth rejection, a token
    failure, no reply at all or a reply that cannot be read makes the whole source
    `SourceUnavailable`, as #131 and #133 decided.
    """
    if (stop := session.stop_reason) is not None:
        return SourceUnavailable(stop)
    records: list[EoxRecord] = []
    unanswered: list[EoxUnanswered] = []
    batches = tuple(_batches(values, EOX_BATCH_SIZE))
    for index, batch in enumerate(batches):
        if (refusing := session.source_stopped(CiscoEndpoint.EOX)) is not None:
            unanswered.extend(
                EoxUnanswered(value.key, refusing) for rest in batches[index:] for value in rest
            )
            break
        answer = _eox_batch(session, kind, batch)
        if isinstance(answer, SourceUnavailable):
            if (stopped := session.source_stopped(CiscoEndpoint.EOX)) is None:
                return answer
            unanswered.extend(EoxUnanswered(value.key, answer.reason) for value in batch)
            unanswered.extend(
                EoxUnanswered(value.key, stopped) for rest in batches[index + 1 :] for value in rest
            )
            break
        records.extend(answer.records)
        unanswered.extend(answer.unanswered)
    return EoxAnswer(records=tuple(records), unanswered=tuple(unanswered))


def _eox_batch(
    session: Session, kind: str, batch: tuple[_EoxValue, ...]
) -> EoxAnswer | SourceUnavailable:
    """Ask one EoX batch's pages, or split the batch when its first page is refused (#153)."""
    records: list[EoxRecord] = []
    unanswered: list[EoxUnanswered] = []
    page = 1
    while True:
        path = _eox_path(kind, page, batch)
        call = session.get(CiscoEndpoint.EOX, path, values=len(batch) if page == 1 else 0, pages=1)
        if call.outcome is not CallOutcome.OK or call.response is None:
            if _splits_on_its_own(call, page=page, count=len(batch)):
                return _eox_values_one_at_a_time(session, kind, batch)
            if _is_one_values_own_failure(call, page=page, count=len(batch)):
                return _eox_value_failure(batch[0].key, call)
            return SourceUnavailable(call.reason or UNAVAILABLE)
        answer = _understood(eox_answer, call.response.body, tuple(value.key for value in batch))
        if isinstance(answer, SourceUnavailable):
            return answer
        records.extend(answer.records)
        unanswered.extend(_named_unanswered(answer.unanswered, batch))
        last = eox_last_page(call.response.body, ceiling=EOX_MAX_PAGES + 1)
        if last > EOX_MAX_PAGES:
            return SourceUnavailable("Cisco's reply named too many pages")
        if page >= last:
            return EoxAnswer(records=tuple(records), unanswered=tuple(unanswered))
        page += 1


def _eox_values_one_at_a_time(
    session: Session, kind: str, batch: tuple[_EoxValue, ...]
) -> EoxAnswer | SourceUnavailable:
    """Ask each value of a refused batch on its own, keeping every value that answers (#153).

    A source the breaker stopped is not asked again: the values still to ask are `unanswered`
    with its fixed reason (#154).
    """
    records: list[EoxRecord] = []
    unanswered: list[EoxUnanswered] = []
    for index, value in enumerate(batch):
        if (stop := session.stop_reason) is not None:
            return SourceUnavailable(stop)
        if (refusing := session.source_stopped(CiscoEndpoint.EOX)) is not None:
            unanswered.extend(EoxUnanswered(left.key, refusing) for left in batch[index:])
            break
        answer = _eox_batch(session, kind, (value,))
        if isinstance(answer, SourceUnavailable):
            if (stopped := session.source_stopped(CiscoEndpoint.EOX)) is None:
                return answer
            unanswered.append(EoxUnanswered(value.key, answer.reason))
            unanswered.extend(EoxUnanswered(left.key, stopped) for left in batch[index + 1 :])
            break
        records.extend(answer.records)
        unanswered.extend(answer.unanswered)
    return EoxAnswer(records=tuple(records), unanswered=tuple(unanswered))


def _eox_path(kind: str, page: int, batch: tuple[_EoxValue, ...]) -> str:
    """Build one EoX path: hardware in the path, software as `input1..inputN` (#165)."""
    base = f"/supporttools/eox/rest/5/{kind}/{page}"
    if kind == EOX_BY_RELEASE:
        inputs = "&".join(
            f"input{index}={value.wire}" for index, value in enumerate(batch, start=1)
        )
        return f"{base}?{inputs}"
    return f"{base}/{','.join(value.wire for value in batch)}"


def _named_unanswered(
    unanswered: Sequence[EoxUnanswered], batch: tuple[_EoxValue, ...]
) -> tuple[EoxUnanswered, ...]:
    """Name each unanswered value by the key the Run knows it by, never by our wire form."""
    keys = {value.wire: value.key for value in batch}
    return tuple(
        EoxUnanswered(
            keys.get(item.input_value, item.input_value) if item.input_value is not None else None,
            item.reason,
        )
        for item in unanswered
    )


def _eox_value_failure(value: str, call: Call) -> EoxAnswer:
    """The answer when one value's own call is refused: that value alone is unanswered (#153)."""
    if call.response is None:
        return EoxAnswer(records=(), unanswered=(EoxUnanswered(value, call.reason or UNAVAILABLE),))
    return EoxAnswer(
        records=(),
        unanswered=(eox_error_answer(value, call.response.status, call.response.body),),
    )


def _compatible(session: Session, values: Sequence[str]) -> CompatibleAnswers | SourceUnavailable:
    """Ask one PID at a time, paged by `pageIndex` to the reply's `lastIndex` (#127).

    A PID the reply refuses, a call Cisco refuses with a 4xx, an entry that is not understood
    and a long `Retry-After` are each `unanswered` for that PID alone (#131). At the page cap
    the PID's answer is `unanswered: page cap`, so a list that never ends cannot make a Run
    page forever. Only an auth rejection, a token failure or no connection at all makes the
    whole source `SourceUnavailable`. A token that expired part-way keeps every PID already
    answered and leaves the PID it stopped on, and every PID after it, `unanswered` (#133). A
    source the breaker stopped is not asked again: the PIDs still to ask are `unanswered` with
    its fixed reason (#154).
    """
    if (stop := session.stop_reason) is not None:
        return SourceUnavailable(stop)
    answers: list[CompatibleAnswer] = []
    unanswered: list[CompatibleUnanswered] = []
    for index, pid in enumerate(values):
        if (refusing := session.source_stopped(CiscoEndpoint.COMPATIBLE)) is not None:
            unanswered.extend(
                CompatibleUnanswered(product_id=left, reason=refusing) for left in values[index:]
            )
            break
        result = _compatible_pid(session, pid)
        if isinstance(result, CompatibleAnswer):
            answers.append(result)
        elif isinstance(result, CompatibleUnanswered):
            unanswered.append(result)
        elif result.outcome is CallOutcome.TOKEN_EXPIRED:
            unanswered.extend(
                CompatibleUnanswered(product_id=left, reason=TOKEN_EXPIRED)
                for left in values[index:]
            )
            break
        else:
            return SourceUnavailable(result.reason or UNAVAILABLE)
    return CompatibleAnswers(answers=tuple(answers), unanswered=tuple(unanswered))


def _compatible_pid(session: Session, pid: str) -> CompatibleAnswer | CompatibleUnanswered | Call:
    """Ask for one chassis PID's pages; a `Call` comes back only when the whole source fails."""
    releases: list[CompatibleRelease] = []
    for page in range(1, COMPATIBLE_MAX_PAGES + 1):
        path = f"/software/suggestion/v2/suggestions/compatible/productId/{pid}?pageIndex={page}"
        call = session.get(CiscoEndpoint.COMPATIBLE, path, values=1 if page == 1 else 0, pages=1)
        if call.outcome is not CallOutcome.OK or call.response is None:
            if _fails_this_pid_only(call):
                return _unanswered_pid(pid, call)
            return call
        answer = _understood(compatible_answer, pid, call.response.body)
        if isinstance(answer, SourceUnavailable):
            return CompatibleUnanswered(product_id=pid, reason=answer.reason)
        if isinstance(answer, CompatibleUnanswered):
            return answer
        releases.extend(answer.releases)
        last = compatible_last_page(call.response.body, ceiling=COMPATIBLE_MAX_PAGES + 1)
        if page >= last:
            return CompatibleAnswer(pid, tuple(releases))
    return CompatibleUnanswered(product_id=pid, reason=PAGE_CAP)


def _fails_this_pid_only(call: Call) -> bool:
    """Whether a failed compatible call spares the other PIDs (#131).

    A refused call and a reply that did come but could not be used (a long `Retry-After`, a
    limit or a 5xx that held after the one retry) leave that PID `unanswered`. No reply at all
    means the connection or token is down, so the whole source is unavailable.
    """
    if call.outcome is CallOutcome.CALL_FAILED:
        return True
    return call.outcome is CallOutcome.UNAVAILABLE and call.response is not None


def _is_one_values_refusal(call: Call) -> bool:
    """Whether a failed batch call is a value-level 4xx refusal, not an auth or transport stop.

    `CALL_FAILED` is what `Session` gives a 4xx from `apix.cisco.com` that is not an auth-coded
    403; a 401 comes back as an expired token and auth failures as `REJECTED`, so neither is
    ever split into more calls (#131, #153).
    """
    return call.outcome is CallOutcome.CALL_FAILED and call.response is not None


def _splits_on_its_own(call: Call, *, page: int, count: int) -> bool:
    """Whether a refused batch should be retried one value at a time (#153).

    Only a batch's first page, and only when it carries more than one value: a refusal after a
    page was read would lose that page's records, so it still makes the source unavailable.
    """
    return page == 1 and count > 1 and _is_one_values_refusal(call)


def _is_one_values_own_failure(call: Call, *, page: int, count: int) -> bool:
    """Whether a refused one-value batch is that value's own answer (#153)."""
    return page == 1 and count == 1 and _is_one_values_refusal(call)


def _unanswered_pid(pid: str, call: Call) -> CompatibleUnanswered:
    if call.outcome is CallOutcome.CALL_FAILED and call.response is not None:
        return compatible_error_answer(pid, call.response.status, call.response.body)
    return CompatibleUnanswered(product_id=pid, reason=call.reason or UNAVAILABLE)


def _suggestions(session: Session, values: Sequence[str]) -> SuggestionsAnswer | SourceUnavailable:
    """Ask every Software Suggestion batch, splitting a refused one (#153).

    As for EoX, a 4xx that is not an auth failure is retried one PID at a time, and only a PID
    whose own call still fails is `unanswered`; an auth rejection, a token failure, no reply or
    an unreadable reply makes the whole source `SourceUnavailable`. A source the breaker stopped
    is not asked again: the PIDs still to ask are `unanswered` with its fixed reason (#154).
    """
    if (stop := session.stop_reason) is not None:
        return SourceUnavailable(stop)
    answers: list[SuggestionAnswer] = []
    unanswered: list[SuggestionUnanswered] = []
    batches = tuple(_batches(values, SUGGESTION_BATCH_SIZE))
    for index, batch in enumerate(batches):
        if (refusing := session.source_stopped(CiscoEndpoint.SUGGESTION)) is not None:
            unanswered.extend(
                SuggestionUnanswered(value, refusing) for rest in batches[index:] for value in rest
            )
            break
        answer = _suggestion_batch(session, batch)
        if isinstance(answer, SourceUnavailable):
            if (stopped := session.source_stopped(CiscoEndpoint.SUGGESTION)) is None:
                return answer
            unanswered.extend(SuggestionUnanswered(value, answer.reason) for value in batch)
            unanswered.extend(
                SuggestionUnanswered(value, stopped)
                for rest in batches[index + 1 :]
                for value in rest
            )
            break
        answers.extend(answer.answers)
        unanswered.extend(answer.unanswered)
    return SuggestionsAnswer(answers=tuple(answers), unanswered=tuple(unanswered))


def _suggestion_batch(
    session: Session, batch: tuple[str, ...]
) -> SuggestionsAnswer | SourceUnavailable:
    """Ask one Software Suggestion batch, or split it when Cisco refuses it (#153)."""
    path = f"/software/suggestion/v2/suggestions/releases/productIds/{','.join(batch)}"
    call = session.get(CiscoEndpoint.SUGGESTION, path, values=len(batch))
    if call.outcome is not CallOutcome.OK or call.response is None:
        if _splits_on_its_own(call, page=1, count=len(batch)):
            return _suggestion_values_one_at_a_time(session, batch)
        if _is_one_values_own_failure(call, page=1, count=len(batch)):
            return _suggestion_value_failure(batch[0], call)
        return SourceUnavailable(call.reason or UNAVAILABLE)
    return _understood(suggestion_answer, call.response.body, batch)


def _suggestion_values_one_at_a_time(
    session: Session, batch: tuple[str, ...]
) -> SuggestionsAnswer | SourceUnavailable:
    """Ask each PID of a refused batch on its own, keeping every PID that answers (#153).

    A source the breaker stopped is not asked again: the PIDs still to ask are `unanswered`
    with its fixed reason (#154).
    """
    answers: list[SuggestionAnswer] = []
    unanswered: list[SuggestionUnanswered] = []
    for index, value in enumerate(batch):
        if (stop := session.stop_reason) is not None:
            return SourceUnavailable(stop)
        if (refusing := session.source_stopped(CiscoEndpoint.SUGGESTION)) is not None:
            unanswered.extend(SuggestionUnanswered(left, refusing) for left in batch[index:])
            break
        answer = _suggestion_batch(session, (value,))
        if isinstance(answer, SourceUnavailable):
            if (stopped := session.source_stopped(CiscoEndpoint.SUGGESTION)) is None:
                return answer
            unanswered.append(SuggestionUnanswered(value, answer.reason))
            unanswered.extend(SuggestionUnanswered(left, stopped) for left in batch[index + 1 :])
            break
        answers.extend(answer.answers)
        unanswered.extend(answer.unanswered)
    return SuggestionsAnswer(answers=tuple(answers), unanswered=tuple(unanswered))


def _suggestion_value_failure(value: str, call: Call) -> SuggestionsAnswer:
    """The answer when one PID's own call is refused: that PID alone is unanswered (#153)."""
    if call.response is None:
        return SuggestionsAnswer(
            answers=(), unanswered=(SuggestionUnanswered(value, call.reason or UNAVAILABLE),)
        )
    return SuggestionsAnswer(
        answers=(),
        unanswered=(suggestion_error_answer(value, call.response.status, call.response.body),),
    )


def _advisory_path(question: ReleaseQuestion) -> str:
    path = f"/security/advisories/v2/OSType/{question.os_type.value}?version={question.release}"
    if question.platform_alias is not None:
        return f"{path}&platformAlias={question.platform_alias}"
    return path


def _batches[T](values: Sequence[T], size: int) -> Iterator[tuple[T, ...]]:
    for start in range(0, len(values), size):
        yield tuple(values[start : start + size])


def _distinct(questions: LookupQuestions) -> LookupQuestions:
    """Return the questions with every repeated value removed, in the order given."""
    return LookupQuestions(
        releases=tuple(dict.fromkeys(questions.releases)),
        hardware_pids=_distinct_values(questions.hardware_pids),
        software_releases=tuple(dict.fromkeys(questions.software_releases)),
        suggestion_pids=_distinct_values(questions.suggestion_pids),
        compatible_pids=_distinct_values(questions.compatible_pids),
    )


def _distinct_values(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _sendable(questions: LookupQuestions) -> LookupQuestions:
    """Return the questions with every value out of pattern removed, and nothing else changed.

    Each value is judged alone: one odd PID or release is dropped, never sent and never
    echoed, and the others are still asked (#130).
    """
    return LookupQuestions(
        releases=tuple(question for question in questions.releases if _release_is_safe(question)),
        hardware_pids=tuple(pid for pid in questions.hardware_pids if is_safe_pid(pid)),
        software_releases=tuple(
            question
            for question in questions.software_releases
            if is_safe_release(question.release)
        ),
        suggestion_pids=tuple(pid for pid in questions.suggestion_pids if is_safe_pid(pid)),
        compatible_pids=tuple(pid for pid in questions.compatible_pids if is_safe_pid(pid)),
    )


def _all_refused[T](asked: Sequence[T], sendable: Sequence[T]) -> SourceUnavailable | None:
    """Say so when a source was asked about values and none of them could be sent.

    An empty answer would read as "Cisco named nothing", so the source says why it has none.
    """
    return SourceUnavailable(REFUSED) if asked and not sendable else None


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
        or questions.compatible_pids
    )


def _nothing_asked() -> CiscoAnswers:
    """No question means no connection at all: an empty Run does not ask for a token."""
    return CiscoAnswers(
        advisories=(),
        hardware_eox=EoxAnswer(records=(), unanswered=()),
        software_eox=EoxAnswer(records=(), unanswered=()),
        suggestions=SuggestionsAnswer(answers=(), unanswered=()),
        compatible=CompatibleAnswers(),
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
        compatible=SourceUnavailable(reason),
        tally=tally,
    )
