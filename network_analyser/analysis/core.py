"""The one deep call: run every shipped Check on the Run's plain records (#94).

Analysis is deterministic: the same records give the same Findings and ids. It never reads a
file, opens a connection or sees a live session.
"""

from network_analyser.analysis.advice import advice_for
from network_analyser.analysis.checks import CHECKS
from network_analyser.records.analysis import AnalysisInput
from network_analyser.records.topology import AnalysisResults, CheckRun


def analyse(data: AnalysisInput) -> AnalysisResults:
    """Return every Finding, one advice record per Visited Device, and every Check's result.

    v1's Topology Findings are already in `data.topology.findings`; they are returned with
    Analysis's own Findings, worst first, so callers and the Run's outputs see one list.
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
    return AnalysisResults(
        findings=tuple(sorted(findings, key=lambda finding: finding.order)),
        advice=advice_for(data),
        checks=tuple(sorted(runs, key=lambda run: run.check.id)),
    )
