"""One shipped Check and the functions that raise its Findings and record its skips (#94, #96).

Kept apart from `checks.py` so both the v1 Checks and the hardening Checks can build one
without importing each other.
"""

from collections.abc import Callable
from dataclasses import dataclass

from network_analyser.records.analysis import AnalysisInput
from network_analyser.records.topology import Check, CheckSkip, Finding


def _no_skips(_data: AnalysisInput) -> tuple[CheckSkip, ...]:
    """A Check that runs for every Visited Device, such as the network-wide drift Check."""
    return ()


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    """One shipped Check and the functions that raise its Findings and record its skips.

    Attributes:
        check: its stable identity, shown on every Finding it raises.
        run: returns every Finding it raises for the Run.
        skip_reason: why this Run cannot run the Check, or None when it can. A Check whose
            source is unavailable (story 10, story 118), or whose built-in classification
            does not cover what it found, returns the reason here.
        skipped: returns one `CheckSkip` per Visited Device the Check could not run for, such
            as a show command the device refused (story 80); empty when it ran for them all.
    """

    check: Check
    run: Callable[[AnalysisInput], tuple[Finding, ...]]
    skip_reason: Callable[[AnalysisInput], str | None] | None = None
    skipped: Callable[[AnalysisInput], tuple[CheckSkip, ...]] = _no_skips
