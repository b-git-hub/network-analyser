"""Cisco's three replies as plain answer records, or a fixed reason they were not understood.

The envelope is checked strictly: a reply without `advisories`, `EOXRecord` or the suggestion
list is *not understood*, never "nothing found", so a changed API can never read as "safe"
(story 52). Inside a good envelope, a missing field becomes empty or None, and a malformed
entry makes the whole reply not understood rather than quietly dropping a record. An entry
that carries one of Cisco's own codes is *unanswered* for the one value it names, so a value
Cisco has no data for never costs its batch the other values (#166).

Cisco's text is untrusted: control characters are flattened and every value is bounded before
it crosses the module boundary. What shows it escapes it again (story 117).
"""

import json
import re
from collections.abc import Sequence
from typing import Any, Final

from network_analyser.advisories.numbers import last_page
from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoAdvisory,
    CiscoPlatform,
    CompatibleAnswer,
    CompatibleRelease,
    CompatibleUnanswered,
    EoxAnswer,
    EoxRecord,
    EoxUnanswered,
    ReleaseQuestion,
    SourceUnavailable,
    SuggestedRelease,
    SuggestionAnswer,
    SuggestionsAnswer,
    SuggestionUnanswered,
)

NOT_JSON: Final = "Cisco's reply was not JSON"
NOT_UNDERSTOOD: Final = "Cisco's reply was not understood"

_CODE = re.compile(r"[A-Z][A-Z0-9_]{1,63}")
_ERROR_KEY = re.compile(r"(?:SSA_ERR|S3)_[A-Za-z0-9_]{1,60}")
_DATE_LIMIT: Final = 40
_ID_LIMIT: Final = 96
_LIFECYCLE_LIMIT: Final = 16
_TITLE_LIMIT: Final = 300


def advisories_answer(
    question: ReleaseQuestion, body: bytes
) -> AdvisoriesAnswer | SourceUnavailable:
    """Return openVuln's advisories for `question`, or why the reply cannot be used."""
    document = _document(body)
    if document is None:
        return SourceUnavailable(NOT_JSON)
    entries = document.get("advisories")
    if not isinstance(entries, list):
        code = _reply_error(document)
        return SourceUnavailable(NOT_UNDERSTOOD) if code is None else _coded_answer(question, code)
    advisories = tuple(_advisory(entry) for entry in entries)
    if any(advisory is None for advisory in advisories):
        return SourceUnavailable(NOT_UNDERSTOOD)
    return AdvisoriesAnswer(
        question=question,
        advisories=tuple(advisory for advisory in advisories if advisory is not None),
    )


NO_DATA_FOUND: Final = "NO_DATA_FOUND"
"""openVuln's code for a release that has no Advisories: an answer, not a failure (#131)."""

_NO_DATA_STATUSES: Final = frozenset({200, 404})
"""The statuses #148 confirmed carry `NO_DATA_FOUND` as an empty answer. Until it confirms
more, any other status is that release's failure, never "no Advisories" (#155)."""


def advisories_error_answer(
    question: ReleaseQuestion, status: int, body: bytes
) -> AdvisoriesAnswer:
    """Return the answer for a release whose one call failed with HTTP `status` (#131).

    Cisco's `errorCode` is kept when the reply has one; otherwise the reason is the fixed text
    `HTTP <status>`. `NO_DATA_FOUND` is an empty answer only on the statuses #148 confirmed,
    200 and 404; on any other status the release reads unavailable with its HTTP status (#155).
    """
    document = _document(body)
    code = None if document is None else _reply_error(document)
    return _coded_answer(question, code or f"HTTP {status}", status)


def _coded_answer(question: ReleaseQuestion, code: str, status: int = 200) -> AdvisoriesAnswer:
    if code == NO_DATA_FOUND:
        if status in _NO_DATA_STATUSES:
            return AdvisoriesAnswer(question=question, advisories=())
        return AdvisoriesAnswer(question=question, advisories=(), unavailable=f"HTTP {status}")
    return AdvisoriesAnswer(question=question, advisories=(), unavailable=code)


def eox_answer(body: bytes, values: Sequence[str] = ()) -> EoxAnswer | SourceUnavailable:
    """Return EoX's records for whatever was asked, or why the reply cannot be used.

    `values` are the values this batch asked about, in the order they were sent. Cisco's entry
    for a value it has no EoX data for names neither its `EOXInputValue` nor an
    `EOLProductID`, and carries the code in a nested `EOXError` (#166). Such an entry is that
    value at the same position, but only when the reply is one page and holds exactly one entry
    per value; anything else leaves it unnamed, and the reply's other entries are still
    answered.
    """
    document = _document(body)
    if document is None:
        return SourceUnavailable(NOT_JSON)
    entries = document.get("EOXRecord")
    if not isinstance(entries, list):
        code = _reply_error(document)
        return SourceUnavailable(f"Cisco returned {code}" if code else NOT_UNDERSTOOD)
    one_per_value = _single_page(document) and len(entries) == len(values)
    records: list[EoxRecord] = []
    unanswered: list[EoxUnanswered] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return SourceUnavailable(NOT_UNDERSTOOD)
        code = _reply_error(entry)
        if code is not None:
            unanswered.append(
                EoxUnanswered(
                    input_value=_optional_text(entry.get("EOXInputValue"))
                    or (_named_by_position(values, index) if one_per_value else None),
                    reason=code,
                )
            )
            continue
        record = _eox_record(entry)
        if record is None:
            return SourceUnavailable(NOT_UNDERSTOOD)
        records.append(record)
    return EoxAnswer(records=tuple(records), unanswered=tuple(unanswered))


def suggestion_answer(
    body: bytes, values: Sequence[str] = ()
) -> SuggestionsAnswer | SourceUnavailable:
    """Return Software Suggestion's releases per PID, or why the reply cannot be used.

    `values` are the base PIDs this batch asked about, in the order they were sent. Cisco's
    entry for a PID it does not know names no `basePID` and carries the code in its
    `suggestions[].errorDetailsResponse` (#166): that entry is the PID at the same position
    when the reply holds exactly one entry per PID, and it is `unanswered` with Cisco's code,
    so the batch's other PIDs are still answered. An entry that cannot be named either way
    leaves the reply not understood.
    """
    document = _document(body)
    if document is None:
        return SourceUnavailable(NOT_JSON)
    entries = _suggestion_entries(document)
    if entries is None:
        code = _reply_error(document)
        return SourceUnavailable(f"Cisco returned {code}" if code else NOT_UNDERSTOOD)
    one_per_pid = len(entries) == len(values)
    answers: list[SuggestionAnswer] = []
    unanswered: list[SuggestionUnanswered] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return SourceUnavailable(NOT_UNDERSTOOD)
        product = entry.get("product")
        product = product if isinstance(product, dict) else entry
        product_id = (
            _optional_text(product.get("basePID"))
            or _optional_text(entry.get("basePID"))
            or (_named_by_position(values, index) if one_per_pid else None)
        )
        if product_id is None:
            return SourceUnavailable(NOT_UNDERSTOOD)
        code = _reply_error(entry)
        if code is not None:
            unanswered.append(SuggestionUnanswered(product_id=product_id, reason=code))
            continue
        releases = _suggested_releases(entry)
        if releases is None:
            return SourceUnavailable(NOT_UNDERSTOOD)
        answers.append(
            SuggestionAnswer(
                product_id=product_id,
                product_name=_optional_text(product.get("productName")) or product_id,
                releases=releases,
            )
        )
    return SuggestionsAnswer(answers=tuple(answers), unanswered=tuple(unanswered))


def compatible_answer(  # noqa: PLR0911 (one return per reply shape, each named)
    product_id: str, body: bytes
) -> CompatibleAnswer | CompatibleUnanswered | SourceUnavailable:
    """Return the compatible releases for `product_id`, or why the reply cannot be used.

    The entries sit under `suggestions`, each with `releaseFormat1`, `isSuggested`,
    `releaseTrain` and `releaseLifeCycle`. A reply naming Cisco's error code is `unanswered`
    for that one PID, never an outage of the source (#127).
    """
    document = _document(body)
    if document is None:
        return SourceUnavailable(NOT_JSON)
    entries = document.get("suggestions")
    if not isinstance(entries, list):
        code = _reply_error(document)
        if code is not None:
            return CompatibleUnanswered(product_id=product_id, reason=code)
        return SourceUnavailable(NOT_UNDERSTOOD)
    releases: list[CompatibleRelease] = []
    for entry in entries:
        if not isinstance(entry, dict):
            return SourceUnavailable(NOT_UNDERSTOOD)
        code = _reply_error(entry)
        if code is not None:
            return CompatibleUnanswered(product_id=product_id, reason=code)
        release = _compatible_release(entry)
        if release is None:
            return SourceUnavailable(NOT_UNDERSTOOD)
        releases.append(release)
    return CompatibleAnswer(product_id=product_id, releases=tuple(releases))


def compatible_error_answer(product_id: str, status: int, body: bytes) -> CompatibleUnanswered:
    """Return the `unanswered` record for a PID whose one call failed with HTTP `status` (#131).

    Cisco's `errorCode` is kept when the reply has one; otherwise the reason is `HTTP <status>`.
    """
    document = _document(body)
    code = None if document is None else _reply_error(document)
    return CompatibleUnanswered(product_id=product_id, reason=code or f"HTTP {status}")


def compatible_last_page(body: bytes, *, ceiling: int) -> int:
    """Return the last `pageIndex` Cisco's compatible reply names, at most `ceiling`.

    1 when the reply names none or names something that is not a page number (#133).
    """
    document = _document(body)
    record = document.get("paginationResponseRecord") if document is not None else None
    value = record.get("lastIndex") if isinstance(record, dict) else None
    return last_page(value, ceiling=ceiling)


def eox_last_page(body: bytes, *, ceiling: int) -> int:
    """Return the last page Cisco's EoX reply says there is, at most `ceiling`.

    1 when the reply names none or names something that is not a page number (#133).
    """
    document = _document(body)
    record = document.get("PaginationResponseRecord") if document is not None else None
    value = record.get("LastIndex") if isinstance(record, dict) else None
    return last_page(value, ceiling=ceiling)


def _document(body: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(body)
    except ValueError, RecursionError:
        return None
    return value if isinstance(value, dict) else None


def _suggestion_entries(document: dict[str, Any]) -> list[Any] | None:
    for key in ("suggestions", "productList", "products"):
        value = document.get(key)
        if isinstance(value, list):
            return value
    return None


def _advisory(entry: object) -> CiscoAdvisory | None:
    if not isinstance(entry, dict):
        return None
    advisory_id = _optional_text(entry.get("advisoryId"))
    if advisory_id is None:
        return None
    platforms = _platforms(entry.get("platforms"))
    if platforms is None:
        return None
    return CiscoAdvisory(
        advisory_id=advisory_id,
        title=_optional_text(entry.get("advisoryTitle")) or advisory_id,
        sir=_optional_text(entry.get("sir")) or "",
        cvss_base_score=_score(entry.get("cvssBaseScore")),
        cves=_texts(entry.get("cves")),
        first_published=_optional_text(entry.get("firstPublished")) or "",
        last_updated=_optional_text(entry.get("lastUpdated")) or "",
        first_fixed=_texts(entry.get("firstFixed")),
        platforms=platforms,
    )


def _platforms(value: object) -> tuple[CiscoPlatform, ...] | None:
    """The named `platforms[]` entries and their first fixes; None when the shape is odd.

    NX-OS replies give first fixes per platform rather than per Advisory (#126). An entry with
    no name is ignored, as Cisco's 2026 replies carry one (#120): it can never be a device's
    series. A malformed entry makes the whole reply not understood, as everywhere else.
    """
    if value is None:
        return ()
    if not isinstance(value, list):
        return None
    platforms: list[CiscoPlatform] = []
    for entry in value:
        if not isinstance(entry, dict):
            return None
        raw_name = entry.get("name")
        if raw_name is not None and not isinstance(raw_name, str):
            return None
        name = _optional_text(raw_name, limit=_ID_LIMIT)
        if name is None:
            continue
        first_fixed = _platform_fixes(entry.get("firstFixes"))
        if first_fixed is None:
            return None
        platforms.append(CiscoPlatform(name=name, first_fixed=first_fixed))
    return tuple(platforms)


def _platform_fixes(value: object) -> tuple[str, ...] | None:
    """The releases in one platform's `firstFixes[]`; None when the shape is odd."""
    if value is None:
        return ()
    if not isinstance(value, list):
        return None
    fixes: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            return None
        name = _optional_text(item.get("name"), limit=_ID_LIMIT)
        if name is None:
            return None
        fixes.append(name)
    return tuple(fixes)


def _eox_record(entry: dict[str, Any]) -> EoxRecord | None:
    product_id = _optional_text(entry.get("EOLProductID"))
    if product_id is None:
        return None
    migration = entry.get("EOXMigrationDetails")
    migration = migration if isinstance(migration, dict) else {}
    return EoxRecord(
        input_value=_optional_text(entry.get("EOXInputValue")) or product_id,
        input_type=_optional_text(entry.get("EOXInputType")) or "",
        product_id=product_id,
        description=_optional_text(entry.get("ProductIDDescription")) or "",
        bulletin=_optional_text(entry.get("ProductBulletinNumber")) or "",
        bulletin_url=_optional_text(entry.get("LinkToProductBulletinURL")) or "",
        end_of_sale=_date(entry.get("EndOfSaleDate")),
        end_of_sw_maintenance=_date(entry.get("EndOfSWMaintenanceReleases")),
        end_of_security_vul_support=_date(entry.get("EndOfSecurityVulSupportDate")),
        last_date_of_support=_date(entry.get("LastDateOfSupport")),
        migration_product_id=_optional_text(migration.get("MigrationProductId")),
        migration_url=_optional_text(migration.get("MigrationProductInfoURL")),
    )


def _suggested_releases(entry: dict[str, Any]) -> tuple[SuggestedRelease, ...] | None:
    entries: list[Any] | None = None
    for key in ("suggestions", "suggestedReleases", "releases"):
        value = entry.get(key)
        if isinstance(value, list):
            entries = value
            break
    if entries is None:
        entries = [entry]
    releases: list[SuggestedRelease] = []
    for item in entries:
        if not isinstance(item, dict):
            return None
        name = (
            _optional_text(item.get("relDispName"))
            or _optional_text(item.get("releaseFormat1"))
            or _optional_text(item.get("releaseFormat2"))
            or _optional_text(item.get("release"))
        )
        if name is None:
            return None
        releases.append(
            SuggestedRelease(
                release=name,
                suggested=_suggested(item.get("isSuggested")),
                release_date=_optional_text(item.get("releaseDate")),
                train=_optional_text(item.get("trainDispName"))
                or _optional_text(item.get("releaseTrain")),
            )
        )
    return tuple(releases)


def _compatible_release(entry: dict[str, Any]) -> CompatibleRelease | None:
    """One entry of a compatible list, or None when it names no release."""
    release = _optional_text(entry.get("releaseFormat1")) or _optional_text(
        entry.get("releaseFormat2")
    )
    if release is None:
        return None
    return CompatibleRelease(
        release=release,
        suggested=_suggested(entry.get("isSuggested")),
        train=_optional_text(entry.get("releaseTrain")),
        lifecycle=_optional_text(entry.get("releaseLifeCycle"), limit=_LIFECYCLE_LIMIT),
    )


def _reply_error(entry: dict[str, Any]) -> str | None:
    """Return Cisco's error code in this object or a top-level `SSA_ERR_`/`S3_` key.

    The code sits in a plain field, in an `error`/`errorDetailsResponse`/`EOXError` object, in
    the `suggestions[]` entry of a Software Suggestion product, or in the bare key itself.
    `EOXError` is how an EoX entry and a refused EoX call report a value with no data (#166).
    """
    for key in ("ErrorCode", "errorCode", "error", "errorDetailsResponse", "EOXError"):
        code = _code(entry.get(key))
        if code is not None:
            return code
    return _suggestion_error(entry) or next(
        (key for key in entry if _ERROR_KEY.fullmatch(key)), None
    )


def _suggestion_error(entry: dict[str, Any]) -> str | None:
    """Cisco's code inside a Software Suggestion product's `suggestions[]` entry (#166)."""
    entries = entry.get("suggestions")
    if not isinstance(entries, list):
        return None
    for item in entries:
        if isinstance(item, dict):
            code = _code(item.get("errorDetailsResponse"))
            if code is not None:
                return code
    return None


def _code(value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("errorCode") or value.get("code") or value.get("ErrorID")
    text = _optional_text(value)
    return text if text is not None and _CODE.fullmatch(text) else None


def _single_page(document: dict[str, Any]) -> bool:
    """Whether the EoX reply says it is the only page, of one value per record (#166)."""
    record = document.get("PaginationResponseRecord")
    value = record.get("LastIndex") if isinstance(record, dict) else None
    return last_page(value, ceiling=2) == 1


def _named_by_position(values: Sequence[str], index: int) -> str | None:
    """The value sent at `index`, or None when the batch has no such position (#166)."""
    return values[index] if index < len(values) else None


def _score(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _date(value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("value")
    return _optional_text(value, limit=_DATE_LIMIT)


def _suggested(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() in {"y", "yes", "true"}


def _texts(value: object, *, limit: int = _ID_LIMIT) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return ()
    texts = (_optional_text(item, limit=limit) for item in value)
    return tuple(text for text in texts if text is not None)


def _optional_text(value: object, *, limit: int = _TITLE_LIMIT) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(" " if not character.isprintable() else character for character in value)
    text = cleaned.strip()[:limit].strip()
    return text or None
