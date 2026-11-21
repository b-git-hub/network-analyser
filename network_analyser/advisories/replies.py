"""Cisco's three replies as plain answer records, or a fixed reason they were not understood.

The envelope is checked strictly: a reply without `advisories`, `EOXRecord` or the suggestion
list is *not understood*, never "nothing found", so a changed API can never read as "safe"
(story 52). Inside a good envelope, a missing field becomes empty or None, and a malformed
entry makes the whole reply not understood rather than quietly dropping a record.

Cisco's text is untrusted: control characters are flattened and every value is bounded before
it crosses the module boundary. What shows it escapes it again (story 117).
"""

import json
import re
from typing import Any, Final

from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoAdvisory,
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
        return SourceUnavailable(NOT_UNDERSTOOD)
    advisories = tuple(_advisory(entry) for entry in entries)
    if any(advisory is None for advisory in advisories):
        return SourceUnavailable(NOT_UNDERSTOOD)
    return AdvisoriesAnswer(
        question=question,
        advisories=tuple(advisory for advisory in advisories if advisory is not None),
    )


def eox_answer(body: bytes) -> EoxAnswer | SourceUnavailable:
    """Return EoX's records for whatever was asked, or why the reply cannot be used."""
    document = _document(body)
    if document is None:
        return SourceUnavailable(NOT_JSON)
    entries = document.get("EOXRecord")
    if not isinstance(entries, list):
        code = _reply_error(document)
        return SourceUnavailable(f"Cisco returned {code}" if code else NOT_UNDERSTOOD)
    records: list[EoxRecord] = []
    unanswered: list[EoxUnanswered] = []
    for entry in entries:
        if not isinstance(entry, dict):
            return SourceUnavailable(NOT_UNDERSTOOD)
        code = _reply_error(entry)
        if code is not None:
            unanswered.append(
                EoxUnanswered(input_value=_optional_text(entry.get("EOXInputValue")), reason=code)
            )
            continue
        record = _eox_record(entry)
        if record is None:
            return SourceUnavailable(NOT_UNDERSTOOD)
        records.append(record)
    return EoxAnswer(records=tuple(records), unanswered=tuple(unanswered))


def suggestion_answer(body: bytes) -> SuggestionsAnswer | SourceUnavailable:
    """Return Software Suggestion's releases per PID, or why the reply cannot be used."""
    document = _document(body)
    if document is None:
        return SourceUnavailable(NOT_JSON)
    entries = _suggestion_entries(document)
    if entries is None:
        code = _reply_error(document)
        return SourceUnavailable(f"Cisco returned {code}" if code else NOT_UNDERSTOOD)
    answers: list[SuggestionAnswer] = []
    unanswered: list[SuggestionUnanswered] = []
    for entry in entries:
        if not isinstance(entry, dict):
            return SourceUnavailable(NOT_UNDERSTOOD)
        product = entry.get("product")
        product = product if isinstance(product, dict) else entry
        product_id = _optional_text(product.get("basePID")) or _optional_text(entry.get("basePID"))
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


def compatible_last_page(body: bytes) -> int:
    """Return the last `pageIndex` Cisco's compatible reply names; 1 when it does not say."""
    document = _document(body)
    record = document.get("paginationResponseRecord") if document is not None else None
    value = record.get("lastIndex") if isinstance(record, dict) else None
    if isinstance(value, bool):
        return 1
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdigit() and int(value) > 0:
        return int(value)
    return 1


def eox_last_page(body: bytes) -> int:
    """Return the last page Cisco's EoX reply says there is; 1 when it does not say."""
    document = _document(body)
    record = document.get("PaginationResponseRecord") if document is not None else None
    value = record.get("LastIndex") if isinstance(record, dict) else None
    if isinstance(value, bool):
        return 1
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdigit() and int(value) > 0:
        return int(value)
    return 1


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
    return CiscoAdvisory(
        advisory_id=advisory_id,
        title=_optional_text(entry.get("advisoryTitle")) or advisory_id,
        sir=_optional_text(entry.get("sir")) or "",
        cvss_base_score=_score(entry.get("cvssBaseScore")),
        cves=_texts(entry.get("cves")),
        first_published=_optional_text(entry.get("firstPublished")) or "",
        last_updated=_optional_text(entry.get("lastUpdated")) or "",
        first_fixed=_texts(entry.get("firstFixed")),
    )


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
    """Return Cisco's error code in this object or a top-level `SSA_ERR_`/`S3_` key."""
    for key in ("ErrorCode", "errorCode", "error", "errorDetailsResponse"):
        code = _code(entry.get(key))
        if code is not None:
            return code
    return next((key for key in entry if _ERROR_KEY.fullmatch(key)), None)


def _code(value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("errorCode") or value.get("code")
    text = _optional_text(value)
    return text if text is not None and _CODE.fullmatch(text) else None


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
