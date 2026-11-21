"""The shipped Checks, and the machinery that always runs every one of them (#94, #102).

A Check is a stable `Check` record and two functions over the Run's plain records: one for its
Findings and one for the Visited Devices it could not run for. Every shipped Check runs on
every Run (story 4). A Check whose feature is not in use returns nothing for that device
(story 5); it is not skipped. A Check is skipped for a device only when the show output it
needs was refused (a Device Role out of date, story 80) or was never collected, and then the
reason is recorded (`CheckRun.skipped`), never passed (story 6).

A Check is skipped for the whole Run only when it cannot decide anything at all: a source it
needs was unavailable (story 10), or a built-in classification, such as the Train support
table, does not cover what it found. The reason is then recorded and shown, so a skip never
passes for a clean result.

New Checks are added to `CHECKS`; nothing else in `analysis` needs to change. The one
exception is Cisco's insecure-configuration list: its Check needs every other Check's Findings
to mark a match, so `analysis.cisco_list.apply` runs after the loop in `core.analyse`.
"""

import re
from collections.abc import Sequence
from ipaddress import IPv4Address
from typing import Final

from network_analyser.analysis import advisory
from network_analyser.analysis.catalogue import MODEL_DRIFT_CHECK
from network_analyser.analysis.definition import CheckDefinition
from network_analyser.analysis.hardening import HARDENING_CHECKS
from network_analyser.analysis.ids import finding_id
from network_analyser.records.analysis import AnalysisInput, SourceUnavailable
from network_analyser.records.collected import StackMember, VpcState
from network_analyser.records.platform import Platform
from network_analyser.records.topology import (
    Check,
    CheckType,
    Finding,
    FindingLevel,
    LinkRole,
    VisitedDevice,
)
from network_analyser.records.unknown import Unknown

__all__ = ["CHECKS", "CheckDefinition", "model_drift"]

MINIMUM_DRIFT_RELEASES: Final = 2
"""Two releases of one model is drift; one is not (story 70)."""

STACK_MISMATCH_CHECK: Check = Check(
    "consistency-stack-mismatch",
    "Stack or StackWise Virtual members on different releases or modes",
    CheckType.CONSISTENCY,
)
"""Story 71: one Medium Finding per stack or StackWise Virtual whose members differ."""

VPC_MISMATCH_CHECK: Check = Check(
    "consistency-vpc-mismatch",
    "vPC peers on different releases",
    CheckType.CONSISTENCY,
)
"""Story 71: one Medium Finding per vPC pair whose peers differ."""

BUNDLE_MODE_CHECK: Check = Check(
    "consistency-bundle-mode",
    "Catalyst 9000 in bundle mode",
    CheckType.CONSISTENCY,
)
"""Story 72: one Low Finding per Catalyst 9000 running bundle mode."""

TRAIN_SUPPORT_CHECK: Check = Check(
    "consistency-standard-support-train",
    "IOS-XE on a Standard-Support Train",
    CheckType.CONSISTENCY,
)
"""Story 72: one Low Finding per IOS-XE device on a Standard-Support Train."""

STANDARD_SUPPORT_TRAINS: Final = frozenset({"17.13", "17.14", "17.16", "17.17"})
"""The IOS-XE Trains Cisco gives 12 months of support, from the #76 research.

Cisco's "Recommended Releases for Catalyst 9200/9300/9400/9500/9600" (as of September 2026)
makes 17.12, 17.15 and 17.18 Extended-Support Trains (48 months) and 17.13, 17.14, 17.16 and
17.17 Standard-Support Trains (12 months). Every other Train is left unclassified rather than
guessed at: older Trains are already past either support window, and the Lifecycle Checks
judge them.
"""

EXTENDED_SUPPORT_TRAINS: Final = frozenset({"17.12", "17.15", "17.18"})
"""The IOS-XE Extended-Support Trains, from the same table."""

_SUPPORT_TRAINS: Final = STANDARD_SUPPORT_TRAINS | EXTENDED_SUPPORT_TRAINS
"""Every IOS-XE Train the table classifies, either way."""

_IOS_XE_TRAINS: Final = frozenset({"16", "17", "26"})
"""The major release numbers of IOS-XE's 16.x, 17.x and 26.x Trains.

Classic IOS shares this Platform, and its own Trains (12.x, 15.x) are not in Cisco's IOS-XE
support table, so they are outside this Check rather than an unclassified Train.
"""

_CATALYST_9000: Final = re.compile(r"C9[2-6]\d{2}")
_TRAIN: Final = re.compile(r"^(\d{1,2})\.(\d{1,2})(?:[.(]|$)")
_LEADING_ZERO: Final = re.compile(r"(?<!\d)0+(\d)")
_BUNDLE: Final = "BUNDLE"


def model_drift(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return one Low Finding for each model that Visited Devices run on two or more releases.

    It is tool policy, not a Cisco rule, so it says so. The Finding names every Visited
    Device of that model, which is what the diagram lights when the Check is picked (story 92).
    A device whose model or release is `Unknown` takes no part: Analysis never guesses.
    """
    by_model: dict[str, list[tuple[str, str, str]]] = {}
    for device in data.topology.devices:
        if not isinstance(device.model, str) or not isinstance(device.software_version, str):
            continue
        if not device.model:
            continue
        by_model.setdefault(device.model, []).append(
            (device.id, device.software_version, _name(device))
        )

    findings: list[Finding] = []
    for model, devices in sorted(by_model.items()):
        releases = sorted({release for _, release, _ in devices})
        if len(releases) < MINIMUM_DRIFT_RELEASES:
            continue
        names: dict[str, list[str]] = {release: [] for release in releases}
        for _, release, name in devices:
            names[release].append(name)
        runs = "; ".join(
            f"{release} on {', '.join(sorted(names[release]))}" for release in releases
        )
        what = (
            f"Model {model} runs {len(releases)} releases: {runs}. "
            "This is tool policy, not a Cisco rule."
        )
        findings.append(
            Finding(
                id=finding_id(MODEL_DRIFT_CHECK.id, f"model:{model}"),
                devices=tuple(sorted(device_id for device_id, _, _ in devices)),
                items=(),
                evidence=(),
                level=FindingLevel.LOW,
                check=MODEL_DRIFT_CHECK,
                what_was_found=what,
                what_to_do="Bring every device of this model onto one release.",
                source="tool policy, not a Cisco rule",
                summary=what,
            )
        )
    return tuple(findings)


def stack_mismatch(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return one Medium Finding for each stack or StackWise Virtual whose members differ.

    A stack or a StackWise Virtual pair appears in `stack_members` as its members. Its
    members must run one release and one boot mode; Cisco calls mixed releases on stack
    members incompatible and a vPC-style mismatch unsupported. Only the members that were
    actually read can be compared: an `Unknown` release or mode is never guessed at.
    """
    findings: list[Finding] = []
    for device in data.topology.devices:
        members = device.stack_members
        if isinstance(members, Unknown) or len(members) < MINIMUM_DRIFT_RELEASES:
            continue
        releases = {
            _release_key(member.software_version)
            for member in members
            if isinstance(member.software_version, str)
        }
        modes = {member.mode.upper() for member in members if isinstance(member.mode, str)}
        if len(releases) < MINIMUM_DRIFT_RELEASES and len(modes) < MINIMUM_DRIFT_RELEASES:
            continue
        described = "; ".join(_member_text(member) for member in members)
        what = f"{_name(device)} stack or StackWise Virtual members differ: {described}."
        findings.append(
            Finding(
                id=finding_id(STACK_MISMATCH_CHECK.id, f"device:{device.id}"),
                devices=(device.id,),
                items=(),
                evidence=(),
                level=FindingLevel.MEDIUM,
                check=STACK_MISMATCH_CHECK,
                what_was_found=what,
                what_to_do=(
                    "Bring every stack or StackWise Virtual member onto one release and one mode."
                ),
                source="device reports",
                summary=what,
            )
        )
    return tuple(findings)


def vpc_mismatch(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return one Medium Finding for each vPC pair whose peers run different releases.

    The peers come from facts the Run already holds: each device's vPC domain and
    peer-keepalive, and the Topology's vPC peer-link or peer-keepalive Links. Both devices
    must be Visited and in the same vPC domain; a peer whose release was not read is never
    guessed at.
    """
    devices = data.topology.devices
    by_id = {device.id: device for device in devices}
    findings: list[Finding] = []
    for first, second in _vpc_pairs(data):
        peer = by_id[first]
        other = by_id[second]
        release = peer.software_version
        other_release = other.software_version
        if not isinstance(release, str) or not isinstance(other_release, str):
            continue
        if _release_key(release) == _release_key(other_release):
            continue
        what = (
            f"vPC peers {_name(peer)} and {_name(other)} run different releases: "
            f"{_name(peer)} {release}, {_name(other)} {other_release}."
        )
        findings.append(
            Finding(
                id=finding_id(VPC_MISMATCH_CHECK.id, f"vpc:{first}:{second}"),
                devices=(first, second),
                items=(),
                evidence=(),
                level=FindingLevel.MEDIUM,
                check=VPC_MISMATCH_CHECK,
                what_was_found=what,
                what_to_do=(
                    "Upgrade both vPC peers to the same NX-OS release before the next change."
                ),
                source="device reports",
                summary=what,
            )
        )
    return tuple(findings)


def bundle_mode(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return one Low Finding for each Catalyst 9000 running bundle mode (story 72).

    Cisco recommends install mode on Catalyst 9000. The boot mode is the one `show version`'s
    member table already reports; a mode that was not read raises nothing.
    """
    findings: list[Finding] = []
    for device in data.topology.devices:
        if not _is_catalyst_9000(device.model):
            continue
        members = device.stack_members
        if isinstance(members, Unknown):
            continue
        bundled = [
            member
            for member in members
            if isinstance(member.mode, str) and member.mode.upper() == _BUNDLE
        ]
        if not bundled:
            continue
        described = "; ".join(_member_text(member) for member in bundled)
        what = f"Catalyst 9000 {device.model} is in bundle mode: {described}."
        findings.append(
            Finding(
                id=finding_id(BUNDLE_MODE_CHECK.id, f"device:{device.id}"),
                devices=(device.id,),
                items=(),
                evidence=(),
                level=FindingLevel.LOW,
                check=BUNDLE_MODE_CHECK,
                what_was_found=what,
                what_to_do=(
                    "Move it to install mode; Cisco recommends install mode on Catalyst 9000."
                ),
                source="device reports",
                summary=what,
            )
        )
    return tuple(findings)


def train_support(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return one Low Finding per IOS-XE device on a Standard-Support Train (story 72).

    Only a Train the #76 research classifies as Standard-Support raises a Finding. A Train it
    does not classify is never guessed at; when no applicable device's Train is classified,
    `train_support_skip_reason` skips the Check instead.
    """
    findings: list[Finding] = []
    for device in data.topology.devices:
        if not _train_applies(device):
            continue
        release = device.software_version
        if not isinstance(release, str):
            continue
        train = _train(release)
        if train not in STANDARD_SUPPORT_TRAINS:
            continue
        what = (
            f"{_name(device)} runs IOS-XE {release} on Standard-Support Train {train}; "
            "Cisco recommends an Extended-Support Train (17.12, 17.15 or 17.18)."
        )
        findings.append(
            Finding(
                id=finding_id(TRAIN_SUPPORT_CHECK.id, f"device:{device.id}"),
                devices=(device.id,),
                items=(),
                evidence=(),
                level=FindingLevel.LOW,
                check=TRAIN_SUPPORT_CHECK,
                what_was_found=what,
                what_to_do="Plan a move to an Extended-Support Train (17.12, 17.15 or 17.18).",
                source="device reports",
                summary=what,
            )
        )
    return tuple(findings)


def train_support_skip_reason(data: AnalysisInput) -> str | None:
    """Why the Train Check cannot run, or None when it can decide at least one device.

    The table classifies seven Trains. When every applicable device sits on a Train it does
    not classify, nothing can be decided and the Check is skipped with those Trains named,
    rather than letting silence pass for an Extended-Support Train. Once at least one device's
    Train is classified, the Check runs: a device on an unclassified Train gets no Finding,
    and the table's coverage is never guessed at.
    """
    trains = sorted(
        {
            train
            for device in data.topology.devices
            if _train_applies(device)
            for train in (_train(device.software_version),)
            if isinstance(train, str)
        }
    )
    if not trains or any(train in _SUPPORT_TRAINS for train in trains):
        return None
    return "Cisco's IOS-XE Train support table does not classify Train " + ", ".join(trains)


def _member_text(member: StackMember) -> str:
    """One stack member as a Finding names it: its number, release and mode."""
    release = member.software_version
    mode = member.mode
    shown_release = release if isinstance(release, str) else "an unknown release"
    shown_mode = f"{mode} mode" if isinstance(mode, str) else "an unknown mode"
    return f"member {member.number} runs {shown_release} in {shown_mode}"


def _release_key(release: str) -> str:
    """A release with IOS-XE's leading zeros stripped, for comparing two members.

    `17.09.04a` and `17.9.4a` are one release; the Finding still shows each as reported.
    """
    return _LEADING_ZERO.sub(r"\1", release)


def _train(release: str | Unknown) -> str | None:
    """The Train a release belongs to, such as `17.13`; None when it cannot be read."""
    if not isinstance(release, str):
        return None
    match = _TRAIN.match(_release_key(release))
    if match is None:
        return None
    return f"{int(match.group(1))}.{int(match.group(2))}"


def _is_catalyst_9000(model: object) -> bool:
    """True for a Catalyst 9200, 9300, 9400, 9500 or 9600 model."""
    return isinstance(model, str) and _CATALYST_9000.match(model) is not None


def _train_applies(device: VisitedDevice) -> bool:
    """The Train Check covers IOS-XE releases; classic IOS's Trains are outside its table."""
    release = device.software_version
    if device.platform is not Platform.IOS_XE or not isinstance(release, str):
        return False
    train = _train(release)
    return train is not None and train.split(".")[0] in _IOS_XE_TRAINS


def _vpc_pairs(data: AnalysisInput) -> tuple[tuple[str, str], ...]:
    """Every vPC pair the Run's own facts show, as sorted (first, second) device id pairs."""
    devices = data.topology.devices
    by_id = {device.id: device for device in devices}
    pairs = _vpc_keepalive_pairs(devices, by_id)
    for link in data.topology.links:
        if link.role not in {LinkRole.VPC_PEER_LINK, LinkRole.VPC_PEER_KEEPALIVE}:
            continue
        first, second = (end.device for end in link.ends)
        one = by_id.get(first)
        two = by_id.get(second)
        if one is None or two is None or first == second:
            continue
        one_state = _vpc_state(one)
        two_state = _vpc_state(two)
        if one_state is not None and two_state is not None and one_state.domain == two_state.domain:
            pairs.add(_pair(first, second))
    return tuple(sorted(pairs))


def _vpc_keepalive_pairs(
    devices: Sequence[VisitedDevice], by_id: dict[str, VisitedDevice]
) -> set[tuple[str, str]]:
    """Pair vPC peers whose keepalives reach each other, in the same domain."""
    owners: dict[IPv4Address, str] = {}
    for device in devices:
        owners[device.management_ip] = device.id
    for device in devices:
        for address in device.alias_ips:
            owners.setdefault(address, device.id)
    reaches: dict[str, str] = {}
    for device in devices:
        state = _vpc_state(device)
        if state is None or isinstance(state.keepalive, Unknown):
            continue
        other = by_id.get(owners.get(state.keepalive.destination, ""))
        other_state = None if other is None else _vpc_state(other)
        if other is not None and other_state is not None and other_state.domain == state.domain:
            reaches[device.id] = other.id
    return {
        _pair(first, second)
        for first, second in reaches.items()
        if reaches.get(second) == first and first != second
    }


def _vpc_state(device: VisitedDevice) -> VpcState | None:
    state = device.vpc
    return state if isinstance(state, VpcState) else None


def _pair(first: str, second: str) -> tuple[str, str]:
    return (first, second) if first < second else (second, first)


def advisories_unavailable(data: AnalysisInput) -> str | None:
    """Why the Advisory Checks could not run: openVuln's outage reason, or None (story 118)."""
    source = data.answers.advisories
    return source.reason if isinstance(source, SourceUnavailable) else None


def _name(device: VisitedDevice) -> str:
    """What a Finding calls a device: its hostname, else its id."""
    return device.hostname if isinstance(device.hostname, str) else device.id


CHECKS: tuple[CheckDefinition, ...] = (
    CheckDefinition(MODEL_DRIFT_CHECK, model_drift),
    *HARDENING_CHECKS,
    CheckDefinition(STACK_MISMATCH_CHECK, stack_mismatch),
    CheckDefinition(VPC_MISMATCH_CHECK, vpc_mismatch),
    CheckDefinition(BUNDLE_MODE_CHECK, bundle_mode),
    CheckDefinition(TRAIN_SUPPORT_CHECK, train_support, skip_reason=train_support_skip_reason),
    CheckDefinition(
        advisory.ADVISORY_CHECK,
        advisory.advisory_findings,
        skip_reason=advisories_unavailable,
    ),
    CheckDefinition(
        advisory.COULD_NOT_CHECK_CHECK,
        advisory.could_not_check_findings,
        skip_reason=advisories_unavailable,
    ),
)
"""Every shipped Check. Order does not matter: results are sorted by Check id."""
