"""The Advisory Check: openVuln's answers in, Advisory Findings and advice out (#105).

Matching is on the software release only, within the family `show version` names (stories 44,
47). One Finding is raised per Visited Device per Advisory, covering the whole Advisory rather
than one per CVE (story 48), and only Critical and High Advisories raise one. A device whose
release cannot be checked ends with exactly one "could not check" Low Finding and one Advisory
outcome, so silence never reads as safe (stories 52-53).

Advice is attached to the device, never a Finding (story 58): the Advisory outcome, the Upgrade
Target (the highest of each Advisory's first fix above the running release in its Train, with
how many Advisories it leaves open, stories 20-24) and the Latest Release (#127, stories 1-13).
NX-OS takes its fixes from the `platforms[]` entry for the device's Nexus series (#126); without
exactly one such entry the target is `not available`, never a guess. The Latest Release is the
highest release on Cisco's compatible list for the device's chassis PID, in its Train and
overall, with Cisco's lifecycle code beside each value.
"""

import re
from dataclasses import dataclass, replace
from typing import Final

from network_analyser.analysis.chassis import chassis_pid, nexus_series
from network_analyser.analysis.ids import finding_id
from network_analyser.analysis.releases import (
    family_of,
    family_reason,
    normalise_listed_release,
    normalise_release,
    platform_name,
    release_key,
    train_of,
)
from network_analyser.records.analysis import (
    AdvisoryAnswer,
    AdvisoryPlatform,
    AnalysisInput,
    CiscoAnswer,
    CompatibleRelease,
    CompatibleReleases,
    FixedRelease,
    OsType,
    ReleaseAdvisories,
    SourceUnavailable,
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
_LIFECYCLE: Final = re.compile(r"[A-Z][A-Z0-9]{1,7}")
"""Cisco's lifecycle code shape: two to eight upper-case letters or digits, such as `ED`."""
NEWER_THAN_LIST: Final = "running release is newer than Cisco's list"
"""What a Latest Release value becomes when the device already runs something above it (#127)."""
FAMILY_NOT_CONFIRMED: Final = (
    "hardware family not confirmed: the Nexus hardware family could not be worked out, "
    "so Cisco openVuln was not asked"
)
"""Why an NX-OS device's Advisories were not checked when its Nexus series is unknown (#134)."""
_WHAT_TO_DO: Final = (
    "Make sure show version is readable and that the release is one Cisco openVuln knows."
)
_WHAT_TO_DO_FAMILY: Final = (
    "Make sure show inventory | json is readable (the Device Role must allow it) and names the "
    "chassis, so the Nexus series can be worked out."
)


@dataclass(frozen=True, slots=True)
class Match:
    """One Critical or High Advisory that names the device's release.

    Attributes:
        answer: Cisco's answer, with the Advisory's own detail.
        first_fixed: the Advisory's lowest first-fixed release in the device's Train that is
            above the running release; None when it has no fix there (#124).
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
        platform_unresolved: True when an NX-OS Advisory's `platforms[]` did not hold exactly
            one entry for the device's series, so the target is `not available` (#126).
    """

    device: VisitedDevice
    outcome: AdvisoryOutcome
    os_type: OsType | None = None
    release: str | None = None
    matches: tuple[Match, ...] = ()
    hardware_family_not_confirmed: bool = False
    train: str | None = None
    platform_unresolved: bool = False

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
        latest = _latest(data.answers.compatible, device, chassis_pid(data, device))
        target, not_cleared = _upgrade_target(resolved)
        advice.append(
            DeviceAdvice(
                device=device.id,
                advisory_outcome=resolved.outcome,
                upgrade_target=target,
                latest_release_in_train=latest.in_train,
                latest_release=latest.overall,
                latest_in_train_lifecycle=latest.in_train_lifecycle,
                latest_release_lifecycle=latest.overall_lifecycle,
                train=resolved.train,
                not_cleared=not_cleared,
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
    family = nexus_series(data, device) if os_type is OsType.NX_OS else None
    answer = _answer_for(data.answers.advisories, os_type, normalised, family)
    if answer is None and os_type is OsType.NX_OS and family is None:
        return _unchecked(device, FAMILY_NOT_CONFIRMED)
    if answer is None:
        return _unchecked(device, f"Cisco openVuln gave no answer for release {normalised}")
    if answer.unavailable is not None:
        return _unchecked(
            device,
            f"Cisco openVuln does not know release {normalised} ({answer.unavailable})",
        )
    train = train_of(normalised, os_type)
    series = platform_name(family)
    matches, unresolved = _matches(
        _flagged(answer.advisories), os_type=os_type, series=series, train=train, running=normalised
    )
    kind = AdvisoryOutcomeKind.MATCHES if matches else AdvisoryOutcomeKind.NONE
    return DeviceAdvisory(
        device=device,
        outcome=AdvisoryOutcome(kind, matched=len(matches), release=normalised),
        os_type=os_type,
        release=normalised,
        matches=matches,
        hardware_family_not_confirmed=os_type is OsType.NX_OS and family is None,
        train=train,
        platform_unresolved=unresolved,
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


def _matches(
    advisories: tuple[AdvisoryAnswer, ...],
    *,
    os_type: OsType,
    series: str | None,
    train: str,
    running: str,
) -> tuple[tuple[Match, ...], bool]:
    """Match each Advisory using the fixes its Platform or NX-OS series names.

    The second value is True when an NX-OS Advisory's `platforms[]` did not hold exactly one
    entry for the device's series, so the device's target must read `not available` (#126).
    """
    matches: list[Match] = []
    unresolved = False
    for advisory in advisories:
        fixes = advisory.first_fixed
        if os_type is OsType.NX_OS:
            selected = _platform_fixes(advisory.platforms, series)
            if selected is None:
                unresolved = True
                fixes = ()
            else:
                fixes = selected
        matches.append(_match(advisory, fixes, train, running))
    return tuple(matches), unresolved


def _platform_fixes(
    platforms: tuple[AdvisoryPlatform, ...], series: str | None
) -> tuple[FixedRelease, ...] | None:
    """The one `platforms[]` entry's fixes for the device's series; None unless exactly one.

    An entry with no name never matches a series (#126). Zero or several matching entries leave
    the device's series undecided, so the target is `not available`, never a guess.
    """
    if series is None:
        return None
    entries = [entry for entry in platforms if entry.name == series]
    if len(entries) != 1:
        return None
    return entries[0].first_fixed


def _match(
    answer: AdvisoryAnswer,
    fixes: tuple[FixedRelease, ...],
    train: str,
    running: str,
) -> Match:
    """Keep the Advisory and its lowest first fix in `train` above the running release.

    A fix at or below the running release does not clear the Advisory (story 22): it is
    ignored, so the Advisory reads as having no fix in the Train when none is left (#124).
    """
    above = [
        entry.release
        for entry in fixes
        if entry.release is not None
        and entry.train.casefold() == train.casefold()
        and release_key(entry.release) > release_key(running)
    ]
    fixed = min(above, key=release_key) if above else None
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
        what_to_do=(
            _WHAT_TO_DO_FAMILY if resolved.outcome.reason == FAMILY_NOT_CONFIRMED else _WHAT_TO_DO
        ),
        source=_SOURCE,
        summary=what,
    )


def _upgrade_target(resolved: DeviceAdvisory) -> tuple[str, int]:
    """The highest per-Advisory first fix, and how many Advisories it leaves open (#124).

    Each Advisory's fix is the lowest release in the device's Train that is above the running
    release (story 20). The target is the highest of those (story 21), and `not_cleared` counts
    the Advisories with no fix in the Train, so a partial target says what it leaves open
    (story 23). With none cleared the advice is `no fix in Train T` (story 24).

    The tool never picks another Train (story 26). An NX-OS device takes its fixes from the
    one `platforms[]` entry for its series (#126); with no series, or no single entry, the
    target is `not available` rather than a guess.
    """
    if not resolved.checked:
        return NOT_AVAILABLE, 0
    if not resolved.matches:
        return "no Critical/High Advisories", 0
    if resolved.os_type is OsType.NX_OS and (
        resolved.hardware_family_not_confirmed or resolved.platform_unresolved
    ):
        return NOT_AVAILABLE, 0
    fixes = [match.first_fixed for match in resolved.matches if match.first_fixed is not None]
    not_cleared = len(resolved.matches) - len(fixes)
    if not fixes:
        return f"no fix in Train {resolved.train}", not_cleared
    return max(fixes, key=release_key), not_cleared


@dataclass(frozen=True, slots=True)
class LatestRelease:
    """A device's two Latest Release values and the lifecycle code beside each (#127).

    Attributes:
        in_train: the newest listed release in the device's Train, the running-release text,
            or `not available`.
        in_train_lifecycle: the lifecycle code beside `in_train`; None when there is none.
        overall: the newest listed release overall, the running-release text, or `not
            available`.
        overall_lifecycle: the lifecycle code beside `overall`; None when there is none.
    """

    in_train: str = NOT_AVAILABLE
    in_train_lifecycle: str | None = None
    overall: str = NOT_AVAILABLE
    overall_lifecycle: str | None = None


def _latest(
    answers: CiscoAnswer[CompatibleReleases], device: VisitedDevice, pid: str | None
) -> LatestRelease:
    """The Latest Release in the device's Train and overall (#127, stories 1-13).

    Overall is the highest release on Cisco's compatible list by the tool's own release order;
    in Train is the highest listed release whose Train, by the same rule, is the device's.
    Cisco's `releaseTrain` text is never used. Only list entries the family table can place
    count, so a codename or free-text entry never wins (#138). A device running above a value
    reads `running release is newer than Cisco's list` instead of being shown an older release
    (story 7), but only when its own release is in the family table: an ACI-mode device is
    never compared with a standalone list. An unanswered or rejected PID, an empty list, the
    page cap and an outage all read `not available` (stories 9, 11-13).
    """
    missing = LatestRelease()
    if isinstance(answers, SourceUnavailable) or pid is None:
        return missing
    answer = next((item for item in answers if item.pid == pid), None)
    if answer is None or answer.unanswered is not None or not answer.releases:
        return missing
    listed = _placed_releases(answer.releases, device)
    if not listed:
        return missing
    overall, overall_lifecycle = max(listed, key=lambda pair: release_key(pair[0]))
    running = _running_release(device)
    if (
        running is not None
        and family_of(device.platform, running) is not None
        and release_key(running) > release_key(overall)
    ):
        overall, overall_lifecycle = NEWER_THAN_LIST, None
    in_train, in_train_lifecycle = _latest_in_train(listed, device, running)
    return LatestRelease(
        in_train=in_train,
        in_train_lifecycle=in_train_lifecycle,
        overall=overall,
        overall_lifecycle=overall_lifecycle,
    )


def _placed_releases(
    releases: tuple[CompatibleRelease, ...], device: VisitedDevice
) -> tuple[tuple[str, str | None], ...]:
    """The list's releases the family table can place, each in the shape a device prints (#138).

    An entry that is not a release, such as a codename or free text, never wins a Latest
    Release; neither does one that names no family for the device's Platform. A dotted classic
    IOS entry and a zero-padded entry are normalised first, so they order and match a Train
    like the running release does.
    """
    placed: list[tuple[str, str | None]] = []
    for item in releases:
        release = normalise_listed_release(item.release)
        if family_of(device.platform, release) is not None:
            placed.append((release, _lifecycle(item.lifecycle)))
    return tuple(placed)


def _latest_in_train(
    listed: tuple[tuple[str, str | None], ...],
    device: VisitedDevice,
    running: str | None,
) -> tuple[str, str | None]:
    """The highest listed release in the device's Train, or `not available` (#127)."""
    if running is None:
        return NOT_AVAILABLE, None
    os_type = family_of(device.platform, device.software_version)
    if os_type is None:
        return NOT_AVAILABLE, None
    train = train_of(running, os_type)
    candidates = tuple(pair for pair in listed if train_of(pair[0], os_type) == train)
    if not candidates:
        return NOT_AVAILABLE, None
    release, lifecycle = max(candidates, key=lambda pair: release_key(pair[0]))
    if release_key(running) > release_key(release):
        return NEWER_THAN_LIST, None
    return release, lifecycle


def _running_release(device: VisitedDevice) -> str | None:
    """The device's normalised release, or None when `show version` named none."""
    if not isinstance(device.software_version, str) or not device.software_version:
        return None
    return normalise_release(device.software_version)


def _lifecycle(code: str | None) -> str | None:
    """Cisco's lifecycle code when it passes the strict short pattern; None otherwise."""
    if code is None or _LIFECYCLE.fullmatch(code) is None:
        return None
    return code
