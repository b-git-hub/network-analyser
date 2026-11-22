"""The Lifecycle Checks: hardware and software EoX, and the Suggested Release (#106).

Three Checks read Cisco's EoX and Software Suggestion answers plus the hardware PIDs `show
inventory` gave (stories 73-77):

- **Hardware EoX** checks the chassis, stack members, supervisors and line cards. One Finding
  per device at its worst level lists every affected item with its dates and Cisco's
  replacement PID: Last Date of Support or End of Security/Vulnerability Support passed is
  High, End of SW Maintenance passed is Medium and End of Sale passed is Low (story 74).
- **Software EoX** checks the device's release: End of Vulnerability Support passed is High and
  End of SW Maintenance passed is Medium (story 75).
- **Suggested Release** raises a Low Finding when the release is not one of its PID's Suggested
  Releases, and a Low "could not check" when Cisco returned nothing for the PID (story 77).

An EoX date still in the future is advice attached to the device, never a Finding (story 76).
Only the `EoxItem.kind` tells a hardware answer from a software one, so a mixed or odd reply
can never make a Check read the other's dates (stories 74-75). A date Cisco did not give, or one
that cannot be read, is never guessed at: it raises no level and no advice.

A source marked unavailable raises no per-device Finding for it; its Check is skipped with the
reason, so an outage reads as one problem rather than hundreds (story 118).
"""

from dataclasses import replace
from datetime import UTC, date, datetime
from typing import Final

from network_analyser.analysis.ids import finding_id
from network_analyser.analysis.releases import (
    normalise_listed_release,
    normalise_release,
    release_key,
    release_token,
)
from network_analyser.records.analysis import (
    AnalysisInput,
    HardwareItem,
    SoftwareEox,
    SourceUnavailable,
)
from network_analyser.records.lookup_values import is_safe_pid
from network_analyser.records.topology import (
    Check,
    CheckType,
    CiscoDetailKind,
    EoxDetail,
    EoxItem,
    EoxKind,
    Finding,
    FindingLevel,
    VisitedDevice,
)

HARDWARE_EOX_CHECK: Final = Check(
    "lifecycle-hardware-eox",
    "Hardware EoX",
    CheckType.LIFECYCLE,
)
"""Story 74: one Finding per device at its worst hardware end-of-life level."""

SOFTWARE_EOX_CHECK: Final = Check(
    "lifecycle-software-eox",
    "Software EoX",
    CheckType.LIFECYCLE,
)
"""Story 75: one Finding per device for its release's end-of-life dates."""

SUGGESTED_RELEASE_CHECK: Final = Check(
    "lifecycle-suggested-release",
    "Suggested Release",
    CheckType.LIFECYCLE,
)
"""Story 77: a Low Finding when the release is not one Cisco suggests for its PID."""

_PID_NOT_SENT: Final = "the PID was not sent to Cisco because it does not match the safe pattern"
_EOX_SOURCE: Final = "Cisco EoX"
_SUGGESTION_SOURCE: Final = "Cisco Software Suggestion"
_REPLACE: Final = (
    "Replace each item past end-of-life, or move to Cisco's replacement PID where one is named."
)
_UPGRADE: Final = "Upgrade the device to a supported release."
_SUGGESTED_TODO: Final = "Move the device onto one of Cisco's Suggested Releases for its PID."
_SUGGESTION_UNAVAILABLE: Final = (
    "Run the tool with Cisco lookups on so the Suggested Releases can be read."
)


def hardware_eox(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return one Finding per device for its passed hardware end-of-life dates (story 74).

    Only PIDs `show inventory` gave are checked, and only `EoxKind.HARDWARE` items are read, so
    an optics, PSU or fan PID never reaches Cisco and a software answer never decides a
    hardware level.
    """
    answers = _hardware_answers(data)
    if not answers:
        return ()
    today = _today(data)
    findings: list[Finding] = []
    for device in data.topology.devices:
        items = _passed_hardware_items(data, device, answers, today)
        if not items:
            continue
        level = _hardware_level(items[0])
        for item in items[1:]:
            level = _worst(level, _hardware_level(item))
        what = _eox_text("Hardware", items)
        findings.append(
            Finding(
                id=finding_id(HARDWARE_EOX_CHECK.id, f"device:{device.id}"),
                devices=(device.id,),
                items=(),
                evidence=(),
                level=level,
                check=HARDWARE_EOX_CHECK,
                what_was_found=what,
                what_to_do=_REPLACE,
                source=_EOX_SOURCE,
                summary=what,
                cisco_detail=EoxDetail(kind=CiscoDetailKind.EOX, items=items),
            )
        )
    return tuple(findings)


def software_eox(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return one Finding per device for its release's passed end-of-life dates (story 75).

    Only `EoxKind.SOFTWARE` items are read, and only the two dates story 75 names decide the
    level: an End of Sale or Last Date of Support Cisco happens to return for a release is not
    turned into a level the story did not give it.
    """
    answers = _software_answers(data)
    if not answers:
        return ()
    today = _today(data)
    findings: list[Finding] = []
    for device in data.topology.devices:
        release = device.software_version
        if not isinstance(release, str):
            continue
        items = _passed_software_items(answers, release, today)
        if not items:
            continue
        level = _software_level(items[0])
        for item in items[1:]:
            level = _worst(level, _software_level(item))
        what = _eox_text("Software", items)
        findings.append(
            Finding(
                id=finding_id(SOFTWARE_EOX_CHECK.id, f"device:{device.id}"),
                devices=(device.id,),
                items=(),
                evidence=(),
                level=level,
                check=SOFTWARE_EOX_CHECK,
                what_was_found=what,
                what_to_do=_UPGRADE,
                source=_EOX_SOURCE,
                summary=what,
                cisco_detail=EoxDetail(kind=CiscoDetailKind.EOX, items=items),
            )
        )
    return tuple(findings)


def suggested_release(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return the Suggested Release Finding for each device, or its could-not-check (story 77).

    Cisco returning nothing for the PID is a Low "could not check", never a pass. An unreadable
    model or release is the same, because the comparison cannot be made without them.
    """
    source = data.answers.suggestions
    if isinstance(source, SourceUnavailable):
        return ()
    by_pid = {answer.pid: answer for answer in source}
    findings: list[Finding] = []
    for device in data.topology.devices:
        model = device.model
        if not isinstance(model, str) or not model:
            findings.append(_suggested_could_not_check(device, "the model is not readable"))
            continue
        if not is_safe_pid(model):
            findings.append(_suggested_could_not_check(device, _PID_NOT_SENT))
            continue
        answer = by_pid.get(model)
        if answer is None or not answer.releases:
            findings.append(
                _suggested_could_not_check(
                    device,
                    f"Cisco returned nothing for PID {model}",
                )
            )
            continue
        release = device.software_version
        if not isinstance(release, str) or not release:
            findings.append(
                _suggested_could_not_check(
                    device,
                    f"the release for PID {model} is not readable",
                )
            )
            continue
        if _is_suggested(release, answer.releases):
            continue
        findings.append(_suggested_finding(device, model, release, answer.releases))
    return tuple(findings)


def eox_skip_reason(data: AnalysisInput) -> str | None:
    """Why the EoX Checks cannot run: the EoX source's outage reason, or None (story 118)."""
    source = data.answers.eox
    return source.reason if isinstance(source, SourceUnavailable) else None


def suggestions_skip_reason(data: AnalysisInput) -> str | None:
    """Why the Suggested Release Check cannot run: the source's reason, or None (story 118)."""
    source = data.answers.suggestions
    return source.reason if isinstance(source, SourceUnavailable) else None


def upcoming_eox(data: AnalysisInput) -> dict[str, tuple[EoxItem, ...]]:
    """Return each device's EoX dates still in the future, for its advice (story 76).

    An item is kept with only its future dates, so a date that has already passed and raised a
    Finding is not repeated as advice. The same item may appear in both when some of its dates
    have passed and others have not.
    """
    source = data.answers.eox
    if isinstance(source, SourceUnavailable):
        return {}
    hardware = _hardware_answers(data)
    software = _software_answers(data)
    today = _today(data)
    return {
        device.id: _device_upcoming(data, device, hardware, software, today)
        for device in data.topology.devices
    }


def _device_upcoming(
    data: AnalysisInput,
    device: VisitedDevice,
    hardware: dict[str, tuple[EoxItem, ...]],
    software: tuple[SoftwareEox, ...],
    today: date,
) -> tuple[EoxItem, ...]:
    """One device's future EoX dates, hardware first and then its release."""
    upcoming: list[EoxItem] = []
    for hardware_item in _inventory_for(data, device.id):
        for answer_item in hardware.get(hardware_item.pid, ()):
            if answer_item.kind is not EoxKind.HARDWARE:
                continue
            kept = _upcoming_item(answer_item, today)
            if kept is not None:
                upcoming.append(kept)
    release = device.software_version
    if isinstance(release, str):
        for answer_item in _software_for(software, release):
            if answer_item.kind is not EoxKind.SOFTWARE:
                continue
            kept = _upcoming_item(answer_item, today)
            if kept is not None:
                upcoming.append(kept)
    return _unique(upcoming)


def _today(data: AnalysisInput) -> date:
    """The day EoX dates are judged against: the Run's pinned moment, or now."""
    return (data.as_of or datetime.now(UTC)).date()


def _inventory_for(data: AnalysisInput, device: str) -> tuple[HardwareItem, ...]:
    """A device's inventory PIDs, once each, in the order `show inventory` reported them."""
    seen: set[str] = set()
    items: list[HardwareItem] = []
    for inventory in data.inventory:
        if inventory.device != device:
            continue
        for item in inventory.items:
            if item.pid in seen:
                continue
            seen.add(item.pid)
            items.append(item)
    return tuple(items)


def _hardware_answers(data: AnalysisInput) -> dict[str, tuple[EoxItem, ...]]:
    """Every hardware EoX item Cisco gave, by the PID it answered for."""
    source = data.answers.eox
    if isinstance(source, SourceUnavailable):
        return {}
    answers: dict[str, list[EoxItem]] = {}
    for entry in source:
        for hardware in entry.hardware:
            answers.setdefault(hardware.pid, []).extend(hardware.items)
    return {pid: tuple(items) for pid, items in answers.items()}


def _software_answers(data: AnalysisInput) -> tuple[SoftwareEox, ...]:
    """Every software EoX answer Cisco gave, one per release asked about."""
    source = data.answers.eox
    if isinstance(source, SourceUnavailable):
        return ()
    return tuple(software for entry in source for software in entry.software)


def _software_for(answers: tuple[SoftwareEox, ...], release: str) -> tuple[EoxItem, ...]:
    """Every software EoX item for `release`, compared after normalisation (story 45)."""
    normalised = normalise_release(release)
    items: list[EoxItem] = []
    for answer in answers:
        if normalise_release(answer.release) == normalised:
            items.extend(answer.items)
    return tuple(items)


def _passed_hardware_items(
    data: AnalysisInput,
    device: VisitedDevice,
    answers: dict[str, tuple[EoxItem, ...]],
    today: date,
) -> tuple[EoxItem, ...]:
    """The hardware items with a passed date, trimmed to the dates that passed."""
    items: list[EoxItem] = []
    for hardware_item in _inventory_for(data, device.id):
        for answer_item in answers.get(hardware_item.pid, ()):
            if answer_item.kind is not EoxKind.HARDWARE:
                continue
            kept = _passed_hardware_item(answer_item, today)
            if kept is not None:
                items.append(kept)
    return _unique(items)


def _passed_software_items(
    answers: tuple[SoftwareEox, ...], release: str, today: date
) -> tuple[EoxItem, ...]:
    """The software items for `release` with a passed date story 75 names."""
    items: list[EoxItem] = []
    for answer_item in _software_for(answers, release):
        if answer_item.kind is not EoxKind.SOFTWARE:
            continue
        kept = _passed_software_item(answer_item, today)
        if kept is not None:
            items.append(kept)
    return _unique(items)


def _passed_hardware_item(item: EoxItem, today: date) -> EoxItem | None:
    """`item` with only its passed hardware dates, or None when none passed (story 74)."""
    last = item.last_date_of_support if _passed(item.last_date_of_support, today) else None
    security = (
        item.end_of_security_support if _passed(item.end_of_security_support, today) else None
    )
    maintenance = item.end_of_sw_maintenance if _passed(item.end_of_sw_maintenance, today) else None
    sale = item.end_of_sale if _passed(item.end_of_sale, today) else None
    if last is None and security is None and maintenance is None and sale is None:
        return None
    return replace(
        item,
        last_date_of_support=last,
        end_of_security_support=security,
        end_of_sw_maintenance=maintenance,
        end_of_sale=sale,
    )


def _passed_software_item(item: EoxItem, today: date) -> EoxItem | None:
    """`item` with only the passed software dates story 75 names, or None (story 75)."""
    security = (
        item.end_of_security_support if _passed(item.end_of_security_support, today) else None
    )
    maintenance = item.end_of_sw_maintenance if _passed(item.end_of_sw_maintenance, today) else None
    if security is None and maintenance is None:
        return None
    return replace(
        item,
        last_date_of_support=None,
        end_of_security_support=security,
        end_of_sw_maintenance=maintenance,
        end_of_sale=None,
    )


def _upcoming_item(item: EoxItem, today: date) -> EoxItem | None:
    """`item` with only its future dates, or None when every date has passed (story 76)."""
    last = item.last_date_of_support if _upcoming(item.last_date_of_support, today) else None
    security = (
        item.end_of_security_support if _upcoming(item.end_of_security_support, today) else None
    )
    maintenance = (
        item.end_of_sw_maintenance if _upcoming(item.end_of_sw_maintenance, today) else None
    )
    sale = item.end_of_sale if _upcoming(item.end_of_sale, today) else None
    if last is None and security is None and maintenance is None and sale is None:
        return None
    return replace(
        item,
        last_date_of_support=last,
        end_of_security_support=security,
        end_of_sw_maintenance=maintenance,
        end_of_sale=sale,
    )


def _hardware_level(item: EoxItem) -> FindingLevel:
    """The worst hardware level `item` has reached, from story 74's table."""
    if item.last_date_of_support is not None or item.end_of_security_support is not None:
        return FindingLevel.HIGH
    if item.end_of_sw_maintenance is not None:
        return FindingLevel.MEDIUM
    return FindingLevel.LOW


def _software_level(item: EoxItem) -> FindingLevel:
    """The worst software level `item` has reached, from story 75's table."""
    if item.end_of_security_support is not None:
        return FindingLevel.HIGH
    return FindingLevel.MEDIUM


def _worst(first: FindingLevel, second: FindingLevel) -> FindingLevel:
    """The worse of two levels, where Critical is worst."""
    return first if first.rank <= second.rank else second


def _passed(value: str | None, today: date) -> bool:
    """True when Cisco gave a readable date that is before `today`."""
    when = _as_date(value)
    return when is not None and when < today


def _upcoming(value: str | None, today: date) -> bool:
    """True when Cisco gave a readable date that is after `today`."""
    when = _as_date(value)
    return when is not None and when > today


def _as_date(value: str | None) -> date | None:
    """Cisco's date as a day, or None when it did not give a readable one.

    Cisco's EoX dates are ISO 8601, sometimes with a time; a value the tool cannot read is
    never guessed at, so it decides no level and adds no advice.
    """
    if value is None:
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def _eox_text(kind: str, items: tuple[EoxItem, ...]) -> str:
    """One line naming every affected item, its passed dates and its replacement PID."""
    described = "; ".join(_item_text(item) for item in items)
    return f"{kind} end-of-life: {described}."


def _item_text(item: EoxItem) -> str:
    """One EoX item: its name, every passed date it still carries and its replacement."""
    security = (
        "End of Security/Vulnerability Support"
        if item.kind is EoxKind.HARDWARE
        else "End of Vulnerability Support"
    )
    parts: list[str] = []
    for value, label in (
        (item.last_date_of_support, "Last Date of Support"),
        (item.end_of_security_support, security),
        (item.end_of_sw_maintenance, "End of SW Maintenance"),
        (item.end_of_sale, "End of Sale"),
    ):
        if value is not None:
            parts.append(f"{label} passed ({value})")
    replacement = (
        f"replacement {item.replacement}"
        if item.replacement is not None
        else "no replacement PID named"
    )
    parts.append(replacement)
    return f"{item.name}: {', '.join(parts)}"


def _suggested_finding(
    device: VisitedDevice,
    model: str,
    release: str,
    suggested: tuple[str, ...],
) -> Finding:
    """The Low Finding for a release Cisco does not suggest for the device's PID."""
    releases = ", ".join(suggested)
    what = (
        f"Release {release} is not one of Cisco's Suggested Releases for PID {model}: {releases}."
    )
    return Finding(
        id=finding_id(SUGGESTED_RELEASE_CHECK.id, f"device:{device.id}"),
        devices=(device.id,),
        items=(),
        evidence=(),
        level=FindingLevel.LOW,
        check=SUGGESTED_RELEASE_CHECK,
        what_was_found=what,
        what_to_do=_SUGGESTED_TODO,
        source=_SUGGESTION_SOURCE,
        summary=what,
    )


def _suggested_could_not_check(device: VisitedDevice, reason: str) -> Finding:
    """The Low Finding that keeps a Suggested Release gap from reading as a pass."""
    what = f"Could not check the release against Cisco's Suggested Releases: {reason}."
    return Finding(
        id=finding_id(SUGGESTED_RELEASE_CHECK.id, f"device:{device.id}"),
        devices=(device.id,),
        items=(),
        evidence=(),
        level=FindingLevel.LOW,
        check=SUGGESTED_RELEASE_CHECK,
        what_was_found=what,
        what_to_do=_SUGGESTION_UNAVAILABLE,
        source=_SUGGESTION_SOURCE,
        summary=what,
    )


def _is_suggested(release: str, suggested: tuple[str, ...]) -> bool:
    """True when `release` is one of `suggested`, compared after normalisation (story 45).

    A Suggested Release named with a codename, such as `Dublin-17.12.4`, is read by its release
    token, and both sides are compared by release order, not by raw text (#138).
    """
    running = release_key(normalise_listed_release(release))
    return any(
        release_key(normalise_listed_release(release_token(value))) == running
        for value in suggested
    )


def _unique(items: list[EoxItem]) -> tuple[EoxItem, ...]:
    """The items once each, in the order they were found."""
    seen: set[EoxItem] = set()
    kept: list[EoxItem] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        kept.append(item)
    return tuple(kept)
