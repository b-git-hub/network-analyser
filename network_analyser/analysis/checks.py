"""The shipped Checks, and the machinery that always runs every one of them (#94).

A Check is a stable `Check` record and a function from the Run's plain records to its
Findings. Every shipped Check runs on every Run (story 4). A Check whose feature is not in
use returns nothing for that device (story 5); it is not skipped. A Check is skipped only
when a source it needs was unavailable (story 10), and then the reason is recorded.

New Checks are added to `CHECKS`; nothing else in `analysis` needs to change.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from network_analyser.analysis.ids import finding_id
from network_analyser.records.analysis import AnalysisInput
from network_analyser.records.topology import (
    Check,
    CheckType,
    Finding,
    FindingLevel,
    VisitedDevice,
)

MINIMUM_DRIFT_RELEASES: Final = 2
"""Two releases of one model is drift; one is not (story 70)."""

MODEL_DRIFT_CHECK: Check = Check(
    "consistency-model-drift",
    "Same model on different releases",
    CheckType.CONSISTENCY,
)
"""Story 70: one network-wide Low Finding per model running more than one release."""


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    """One shipped Check and the function that raises its Findings.

    Attributes:
        check: its stable identity, shown on every Finding it raises.
        run: returns every Finding it raises for the Run.
    """

    check: Check
    run: Callable[[AnalysisInput], tuple[Finding, ...]]


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


def _name(device: VisitedDevice) -> str:
    """What a Finding calls a device: its hostname, else its id."""
    return device.hostname if isinstance(device.hostname, str) else device.id


CHECKS: tuple[CheckDefinition, ...] = (CheckDefinition(MODEL_DRIFT_CHECK, model_drift),)
"""Every shipped Check. Order does not matter: results are sorted by Check id."""
