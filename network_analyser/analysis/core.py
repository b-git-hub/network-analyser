"""The one deep call: run every shipped Check on the Run's plain records (#94).

Analysis is deterministic for the same records and the same `as_of` moment: the same input
gives the same Findings and ids. It never reads a file, opens a connection or sees a live
session; only the Lifecycle Checks need the clock, and a Run pins it so a test can too (#106).
"""

from dataclasses import replace

from network_analyser.analysis.advisory import advice_for
from network_analyser.analysis.checks import CHECKS
from network_analyser.analysis.lifecycle import upcoming_eox
from network_analyser.records.analysis import AnalysisInput
from network_analyser.records.topology import AnalysisResults, CheckRun


def analyse(data: AnalysisInput) -> AnalysisResults:
    """Return every Finding, one advice record per Visited Device, and every Check's result.

    v1's Topology Findings are already in `data.topology.findings`; they are returned with
    Analysis's own Findings, worst first, so callers and the Run's outputs see one list.
    A Check whose source was unavailable is skipped with its reason, and raises nothing.
    """
    findings = list(data.topology.findings)
    runs: list[CheckRun] = []
    for definition in CHECKS:
        reason = definition.skip_reason(data) if definition.skip_reason is not None else None
        if reason is not None:
            runs.append(CheckRun(check=definition.check, ran=False, reason=reason))
            continue
        findings.extend(definition.run(data))
        runs.append(CheckRun(check=definition.check, ran=True))
    upcoming = upcoming_eox(data)
    advice = tuple(
        replace(record, upcoming_eox=upcoming.get(record.device, ())) for record in advice_for(data)
    )
    return AnalysisResults(
        findings=tuple(sorted(findings, key=lambda finding: finding.order)),
        advice=advice,
        checks=tuple(sorted(runs, key=lambda run: run.check.id)),
    )
