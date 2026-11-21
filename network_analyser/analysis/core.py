"""The one deep call: run every shipped Check on the Run's plain records (#94, #102).

Analysis is deterministic: the same records give the same Findings and ids. It never reads a
file, opens a connection or sees a live session.

Every Check runs, in `CHECKS` order, and each says which Visited Devices it could not run for.
A Check skipped for every Visited Device is `ran=False` with a reason; one skipped for some is
`ran=True` with those devices in `skipped`, so a refused command never reads as a pass
(stories 6 and 80). Cisco's insecure-configuration list runs last, because marking "also
flagged by Cisco" needs every other Check's Findings (story 67).
"""

from collections.abc import Iterable
from typing import Final

from network_analyser.analysis.advice import advice_for
from network_analyser.analysis.checks import CHECKS, CheckDefinition
from network_analyser.analysis.cisco_list import apply as apply_cisco_list
from network_analyser.records.analysis import AnalysisInput
from network_analyser.records.topology import AnalysisResults, CheckRun, CheckSkip, Finding

__all__ = ["analyse"]

SKIPPED_EVERYWHERE: Final = "skipped on every Visited Device"
"""Why a Check's `CheckRun` says it did not run: each device's reason is in `skipped`."""


def analyse(data: AnalysisInput) -> AnalysisResults:
    """Return every Finding, one advice record per Visited Device, and every Check's result.

    v1's Topology Findings are already in `data.topology.findings`; they are returned with
    Analysis's own Findings, worst first, so callers and the Run's outputs see one list.
    """
    findings: list[Finding] = list(data.topology.findings)
    runs: list[CheckRun] = []
    for definition in CHECKS:
        findings.extend(definition.run(data))
        runs.append(_run(definition, data))
    findings = list(apply_cisco_list(data, tuple(findings)))
    return AnalysisResults(
        findings=tuple(sorted(findings, key=lambda finding: finding.order)),
        advice=advice_for(data),
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
