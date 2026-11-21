"""The one deep call: run every shipped Check on the Run's plain records (#94, #102).

Analysis is deterministic for the same records and the same `as_of` moment: the same input
gives the same Findings and ids. It never reads a file, opens a connection or sees a live
session; only the Lifecycle Checks need the clock, and a Run pins it so a test can too (#106).

Every Check runs, in `CHECKS` order, and each says which Visited Devices it could not run for.
A Check skipped for every Visited Device is `ran=False` with a reason; one skipped for some is
`ran=True` with those devices in `skipped`, so a refused command never reads as a pass
(stories 6 and 80). Cisco's insecure-configuration list runs last, because marking "also
flagged by Cisco" needs every other Check's Findings (story 67).
"""

from collections.abc import Iterable
from dataclasses import replace
from typing import Final

from network_analyser.analysis.advisory import advice_for
from network_analyser.analysis.checks import CHECKS
from network_analyser.analysis.cisco_list import apply as apply_cisco_list
from network_analyser.analysis.definition import CheckDefinition
from network_analyser.analysis.lifecycle import upcoming_eox
from network_analyser.records.analysis import AnalysisInput
from network_analyser.records.topology import AnalysisResults, CheckRun, CheckSkip, Finding

__all__ = ["analyse"]

SKIPPED_EVERYWHERE: Final = "skipped on every Visited Device"
"""Why a Check's `CheckRun` says it did not run: each device's reason is in `skipped`."""


def analyse(data: AnalysisInput) -> AnalysisResults:
    """Return every Finding, one advice record per Visited Device, and every Check's result.

    v1's Topology Findings are already in `data.topology.findings`; they are returned with
    Analysis's own Findings, worst first, so callers and the Run's outputs see one list.
    A Check whose source was unavailable is skipped with its reason, and raises nothing.
    """
    findings: list[Finding] = list(data.topology.findings)
    runs: list[CheckRun] = []
    for definition in CHECKS:
        reason = definition.skip_reason(data) if definition.skip_reason is not None else None
        if reason is not None:
            runs.append(CheckRun(check=definition.check, ran=False, reason=reason))
            continue
        findings.extend(definition.run(data))
        runs.append(_run(definition, data))
    findings = list(apply_cisco_list(data, tuple(findings)))
    upcoming = upcoming_eox(data)
    advice = tuple(
        replace(record, upcoming_eox=upcoming.get(record.device, ())) for record in advice_for(data)
    )
    return AnalysisResults(
        findings=tuple(sorted(findings, key=lambda finding: finding.order)),
        advice=advice,
        checks=tuple(sorted(runs, key=lambda run: run.check.id)),
    )


def _run(definition: CheckDefinition, data: AnalysisInput) -> CheckRun:
    """Return the Check's `CheckRun`: it ran unless every Visited Device was skipped."""
    skipped = definition.skipped(data)
    visited = len(data.topology.devices)
    if visited and len(_devices(skipped)) == visited:
        return CheckRun(
            check=definition.check,
            ran=False,
            reason=SKIPPED_EVERYWHERE,
            skipped=skipped,
        )
    return CheckRun(check=definition.check, ran=True, skipped=skipped)


def _devices(skipped: Iterable[CheckSkip]) -> set[str]:
    """The distinct device ids in a Check's skips."""
    return {item.device for item in skipped}
