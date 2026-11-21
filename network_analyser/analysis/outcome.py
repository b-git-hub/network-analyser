"""What the show-output Checks share: skip reasons and the "could not decide" Finding (#102).

A Check that cannot run for one Visited Device hands back a `CheckSkip` with a fixed reason;
it must never read as a pass (stories 6 and 80). A value that was read but cannot be decided
is different: it raises the Low "could not decide" Finding, so the gap stays visible.
"""

from typing import Final

from network_analyser.analysis.ids import finding_id
from network_analyser.records.analysis import SHOW_OUTPUT_NOT_SUPPLIED
from network_analyser.records.topology import Check, Finding, FindingLevel
from network_analyser.records.unknown import Unknown

__all__ = [
    "DENIED_SUFFIX",
    "NOT_COLLECTED_REASON",
    "NOT_SUPPLIED_REASON",
    "could_not_decide",
    "denied",
    "missing_reason",
]

DENIED_SUFFIX: Final = ": denied"
"""What a refused command's `Unknown` reason ends with (`platforms.collection`)."""

NOT_SUPPLIED_REASON: Final = SHOW_OUTPUT_NOT_SUPPLIED
NOT_COLLECTED_REASON: Final = "the command's output was not collected"
"""Why a Check is skipped when a Platform that has this output gave none for it."""


def denied(value: object) -> bool:
    """Say whether `value` is an `Unknown` the device refused (a Device Role problem)."""
    return isinstance(value, Unknown) and value.reason.endswith(DENIED_SUFFIX)


def missing_reason(value: object) -> str | None:
    """Return why a show-output part cannot be read at all, or None when it may decide.

    A denied command, or output the Run never handed over, is a skip for the device, never a
    pass (stories 6 and 80). An unreadable reply is not: the Check raises "could not decide",
    because the output was read but does not decide the question.
    """
    if isinstance(value, Unknown) and (denied(value) or value.reason == NOT_SUPPLIED_REASON):
        return value.reason
    if value is None:
        return NOT_COLLECTED_REASON
    return None


def could_not_decide(check: Check, device: str, reason: str) -> Finding:
    """Return the Low "could not decide" Finding story 6 asks for, never a silent pass."""
    what = f"Could not decide: {reason}."
    return Finding(
        id=finding_id(check.id, f"{device}\x1f{could_not_decide.__name__}"),
        devices=(device,),
        items=(),
        evidence=(),
        level=FindingLevel.LOW,
        check=check,
        what_was_found=what,
        what_to_do="Read this device's output by hand, or update the tool to read it.",
        source="device reports",
        summary=what,
    )
