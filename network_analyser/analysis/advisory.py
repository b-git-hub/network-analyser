"""The Advisory Check: openVuln's answers in, Advisory Findings and advice out (#105).

Matching is on the software release only, within the family `show version` names (stories 44,
47). One Finding is raised per Visited Device per Advisory, covering the whole Advisory rather
than one per CVE (story 48), and only Critical and High Advisories raise one. A device whose
release cannot be checked ends with exactly one "could not check" Low Finding and one Advisory
outcome, so silence never reads as safe (stories 52-53).

Advice is attached to the device, never a Finding (story 58): the Advisory outcome, the Upgrade
Target (the highest first-fixed release for its Critical and High Advisories, within its Train,
stories 55-56) and the Latest Release (story 57). The Latest Release and the NX-OS Upgrade
Target stay `not available` until #89 settles their sources; Analysis never guesses them.
"""

import re
from dataclasses import dataclass, replace
from typing import Final

from network_analyser.analysis.ids import finding_id
from network_analyser.analysis.releases import (
    family_of,
    family_reason,
    hardware_family,
    normalise_release,
    release_key,
    train_of,
)
from network_analyser.records.analysis import (
    AdvisoryAnswer,
    AnalysisInput,
    CiscoAnswer,
    OsType,
    ReleaseAdvisories,
    SourceUnavailable,
    SuggestedReleases,
)
from network_analyser.records.topology import (
    ADVISORY_FIXED_LINE,
    ADVISORY_STATUS,
    NOT_AVAILABLE,
    AdvisoryDetail,
    AdvisoryOutcome,
    AdvisoryOutcomeKind,
    Check,
    CheckType,
    DeviceAdvice,
    Finding,
    FindingLevel,
    VisitedDevice,
)
from network_analyser.records.unknown import Unknown

ADVISORY_CHECK: Check = Check("advisory-openvuln", "Cisco Advisory", CheckType.ADVISORY)
"""The shipped Check that matches every release against openVuln (stories 43-50)."""

COULD_NOT_CHECK_CHECK: Check = Check(
    "advisory-could-not-check",
    "Advisory could not check",
    CheckType.ADVISORY,
)
"""The shipped Check that raises the four "could not check" cases (story 53)."""

_SOURCE: Final = "Cisco openVuln"
_FLAGGED: Final = frozenset({FindingLevel.CRITICAL, FindingLevel.HIGH})
_NOT_READ: Final = "show version not read"
"""The fixed reason `topology` gives a device whose `show version` was never read."""
_ADVISORY_ID: Final = re.compile(r"cisco-sa-[A-Za-z0-9._-]{1,160}")
"""What an Advisory id must match to keep a Check's stable id safe (story 51)."""
_WHAT_TO_DO: Final = (
    "Make sure show version is readable and that the release is one Cisco openVuln knows."
)


@dataclass(frozen=True, slots=True)
class Match:
    """One Critical or High Advisory that names the device's release.

    Attributes:
        answer: Cisco's answer, with the Advisory's own detail.
        first_fixed: the Advisory's highest first-fixed release in the device's Train; None
            when Cisco names no fix there.
    """

    answer: AdvisoryAnswer
    first_fixed: str | None


@dataclass(frozen=True, slots=True)
class DeviceAdvisory:
    """Everything the Advisory Check decides for one Visited Device.

    Attributes:
        device: the device.
        outcome: its one Advisory outcome.
        os_type: the family matched, when one was worked out.
        release: the normalised release looked up, when there is one.
        matches: its Critical or High Advisories, in Cisco's order.
        hardware_family_not_confirmed: True when an NX-OS match rests on release alone.
        train: the device's Train, when one was worked out.
    """

    device: VisitedDevice
    outcome: AdvisoryOutcome
    os_type: OsType | None = None
    release: str | None = None
    matches: tuple[Match, ...] = ()
    hardware_family_not_confirmed: bool = False
    train: str | None = None

    @property
    def checked(self) -> bool:
        """Say whether Cisco gave a usable answer for this device."""
        return self.outcome.kind is not AdvisoryOutcomeKind.COULD_NOT_CHECK


def advisory_findings(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return one Finding per Visited Device per matching Critical or High Advisory."""
    findings: list[Finding] = []
    for device in data.topology.devices:
        resolved = _resolve(data, device)
        findings.extend(_advisory_finding(resolved, match) for match in resolved.matches)
    return tuple(findings)


def could_not_check_findings(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return one Low Finding for each Visited Device whose Advisories could not be checked."""
    findings: list[Finding] = []
    for device in data.topology.devices:
        resolved = _resolve(data, device)
        if not resolved.checked:
            findings.append(_could_not_check_finding(resolved))
    return tuple(findings)


def advice_for(data: AnalysisInput) -> tuple[DeviceAdvice, ...]:
    """Return one advice record per Visited Device, in device id order (stories 52-58)."""
    advice: list[DeviceAdvice] = []
    for device in data.topology.devices:
        resolved = _resolve(data, device)
        latest_in_train, latest = _latest(data.answers.suggestions, device)
        advice.append(
            DeviceAdvice(
                device=device.id,
                advisory_outcome=resolved.outcome,
                upgrade_target=_upgrade_target(resolved),
                latest_release_in_train=latest_in_train,
                latest_release=latest,
            )
        )
    return tuple(advice)


def _resolve(data: AnalysisInput, device: VisitedDevice) -> DeviceAdvisory:
    """Return the device's Advisory result: its outcome, matches and Train.

    A source marked unavailable gives the outcome "could not check: reason" and no matches; a
    release that cannot be read, a family the table does not hold and an unknown release
    (`INVALID_IOS_VERSION`) do the same, each with its own reason (stories 52-53, 118).
    """
    source = data.answers.advisories
    if isinstance(source, SourceUnavailable):
        return _unchecked(device, source.reason)
    release = _readable_release(device)
    if isinstance(release, str):
        return _resolve_release(data, device, release)
    return _unchecked(device, release.reason)


def _unchecked(device: VisitedDevice, reason: str) -> DeviceAdvisory:
    return DeviceAdvisory(
        device=device,
        outcome=AdvisoryOutcome(AdvisoryOutcomeKind.COULD_NOT_CHECK, reason=reason),
    )


def _readable_release(device: VisitedDevice) -> str | Unknown:
    """The release to look up, or the fixed reason it cannot be read (story 53)."""
    release = device.software_version
    if isinstance(release, Unknown):
        if release.reason == _NOT_READ:
            return Unknown("show version was not read")
        return Unknown(f"the release is unreadable ({release.reason})")
    if not release:
        return Unknown("the release is unreadable (show version named no release)")
    return release


def _resolve_release(data: AnalysisInput, device: VisitedDevice, release: str) -> DeviceAdvisory:
    os_type = family_of(device.platform, release)
    if os_type is None:
        return _unchecked(device, family_reason(release))
    normalised = normalise_release(release)
    family = hardware_family(device.model) if os_type is OsType.NX_OS else None
    answer = _answer_for(data.answers.advisories, os_type, normalised, family)
    if answer is None:
        return _unchecked(device, f"Cisco openVuln gave no answer for release {normalised}")
    if answer.unavailable is not None:
        return _unchecked(
            device,
            f"Cisco openVuln does not know release {normalised} ({answer.unavailable})",
        )
    train = train_of(normalised, os_type)
    matches = tuple(_match(advisory, train) for advisory in _flagged(answer.advisories))
    kind = AdvisoryOutcomeKind.MATCHES if matches else AdvisoryOutcomeKind.NONE
    return DeviceAdvisory(
        device=device,
        outcome=AdvisoryOutcome(kind, matched=len(matches), release=normalised),
        os_type=os_type,
        release=normalised,
        matches=matches,
        hardware_family_not_confirmed=os_type is OsType.NX_OS and family is None,
        train=train,
    )


def _answer_for(
    answers: CiscoAnswer[ReleaseAdvisories],
    os_type: OsType,
    release: str,
    family: str | None,
) -> ReleaseAdvisories | None:
    """Return the answer to this exact question, or None when Cisco was not asked it."""
    if isinstance(answers, SourceUnavailable):
        return None
    for answer in answers:
        if (
            answer.os_type is os_type
            and answer.release == release
            and answer.hardware_family == family
        ):
            return answer
    return None


def _flagged(advisories: tuple[AdvisoryAnswer, ...]) -> tuple[AdvisoryAnswer, ...]:
    """The Critical and High Advisories, once each, in Cisco's order (stories 47-48)."""
    seen: set[str] = set()
    kept: list[AdvisoryAnswer] = []
    for answer in advisories:
        if answer.detail.sir not in _FLAGGED or answer.detail.id in seen:
            continue
        seen.add(answer.detail.id)
        kept.append(answer)
    return tuple(kept)


def _match(answer: AdvisoryAnswer, train: str) -> Match:
    """Keep the Advisory and its highest first-fixed release in `train`, if it has one."""
    fixes = [
        entry.release
        for entry in answer.first_fixed
        if entry.release is not None and entry.train.casefold() == train.casefold()
    ]
    fixed = max(fixes, key=release_key) if fixes else None
    return Match(answer=answer, first_fixed=fixed)


def _advisory_finding(resolved: DeviceAdvisory, match: Match) -> Finding:
    detail = match.answer.detail
    check = _advisory_check(detail)
    what = _what_was_found(resolved, detail, match.first_fixed)
    return Finding(
        id=finding_id(check.id, f"{resolved.device.id}:{detail.id}"),
        devices=(resolved.device.id,),
        items=(),
        evidence=(),
        level=detail.sir,
        check=check,
        what_was_found=what,
        what_to_do=_what_to_do(resolved, match.first_fixed),
        source=_SOURCE,
        summary=(
            f"{detail.id}: {detail.title} (SIR {detail.sir.value}) "
            f"affects release {resolved.release}."
        ),
        cisco_detail=replace(
            detail,
            first_fixed=match.first_fixed,
            status=ADVISORY_STATUS,
            fixed_line=ADVISORY_FIXED_LINE,
            hardware_family_not_confirmed=resolved.hardware_family_not_confirmed,
        ),
    )


def _advisory_check(detail: AdvisoryDetail) -> Check:
    """A stable Check per Advisory, so every surface shows one row per Advisory (story 87)."""
    if _ADVISORY_ID.fullmatch(detail.id):
        return Check(f"advisory-{detail.id}", detail.title or detail.id, CheckType.ADVISORY)
    return Check("advisory-unnamed", detail.title or "Advisory", CheckType.ADVISORY)


def _what_was_found(
    resolved: DeviceAdvisory, detail: AdvisoryDetail, first_fixed: str | None
) -> str:
    cves = ", ".join(detail.cves) if detail.cves else "no CVEs named"
    fit = (
        f"First fixed in Train {resolved.train}: {first_fixed}."
        if first_fixed is not None
        else f"No fix in Train {resolved.train}."
    )
    what = (
        f"{detail.id} ({detail.title}) affects release {resolved.release}: "
        f"SIR {detail.sir.value}, CVSS {detail.cvss or 'not given'}, {cves}. {fit}"
    )
    if resolved.hardware_family_not_confirmed:
        what = f"{what} Software-release match only: hardware family not confirmed."
    return what


def _what_to_do(resolved: DeviceAdvisory, first_fixed: str | None) -> str:
    if first_fixed is not None:
        return f"Upgrade to {first_fixed} or later."
    if resolved.os_type is OsType.NX_OS:
        return "See Cisco's page for the first fixed release: openVuln names none for NX-OS."
    return (
        f"No fix in Train {resolved.train}: move to a newer Train after checking that your "
        "hardware supports it."
    )


def _could_not_check_finding(resolved: DeviceAdvisory) -> Finding:
    what = f"Could not check the release's Advisories: {resolved.outcome.reason}."
    return Finding(
        id=finding_id(COULD_NOT_CHECK_CHECK.id, resolved.device.id),
        devices=(resolved.device.id,),
        items=(),
        evidence=(),
        level=FindingLevel.LOW,
        check=COULD_NOT_CHECK_CHECK,
        what_was_found=what,
        what_to_do=_WHAT_TO_DO,
        source=_SOURCE,
        summary=what,
    )


def _upgrade_target(resolved: DeviceAdvisory) -> str:
    """The highest first-fixed release in the device's Train, or the fixed reason it has none.

    The tool never picks another Train (story 56). NX-OS stays `not available` because openVuln
    names no first-fixed release for it and #89 has not settled another source (spec, Further
    Notes).
    """
    if not resolved.checked:
        return NOT_AVAILABLE
    if not resolved.matches:
        return "no Critical/High Advisories"
    if resolved.os_type is OsType.NX_OS:
        return NOT_AVAILABLE
    fixes = [match.first_fixed for match in resolved.matches if match.first_fixed is not None]
    if not fixes:
        return f"no fix in Train {resolved.train}"
    return max(fixes, key=release_key)


def _latest(suggestions: CiscoAnswer[SuggestedReleases], device: VisitedDevice) -> tuple[str, str]:
    """The Latest Release in the device's Train and overall, or `not available` (#89)."""
    if isinstance(suggestions, SourceUnavailable) or not isinstance(device.model, str):
        return NOT_AVAILABLE, NOT_AVAILABLE
    for answer in suggestions:
        if answer.pid == device.model:
            return (
                answer.latest_release_in_train or NOT_AVAILABLE,
                answer.latest_release or NOT_AVAILABLE,
            )
    return NOT_AVAILABLE, NOT_AVAILABLE
