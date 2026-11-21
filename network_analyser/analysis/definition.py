"""One shipped Check and the function that raises its Findings (#94, #96).

Kept apart from `checks.py` so both the v1 Checks and the hardening Checks can build one
without importing each other.
"""

from collections.abc import Callable
from dataclasses import dataclass

from network_analyser.records.analysis import AnalysisInput
from network_analyser.records.topology import Check, Finding


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    """One shipped Check and the function that raises its Findings.

    Attributes:
        check: its stable identity, shown on every Finding it raises.
        run: returns every Finding it raises for the Run.
    """

    check: Check
    run: Callable[[AnalysisInput], tuple[Finding, ...]]
