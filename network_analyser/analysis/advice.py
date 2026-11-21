"""Per-device advice: the shape is final, the Advisory and EoX answers arrive in #105/#106.

Until the Advisory Check ships, every device's outcome says it could not check, with the
reason the Cisco source gave. Upgrade Target and Latest Release stay `not available` rather
than guessing (spec #92, Further Notes).
"""

from network_analyser.records.analysis import AnalysisInput, CiscoAnswer, SourceUnavailable
from network_analyser.records.topology import (
    AdvisoryOutcome,
    AdvisoryOutcomeKind,
    DeviceAdvice,
)

_NOT_BUILT = "the Advisory Check is not in this build"
"""Why an answered source still gives no outcome yet; #105 replaces this placeholder."""


def advice_for(data: AnalysisInput) -> tuple[DeviceAdvice, ...]:
    """Return one advice record per Visited Device, in device id order."""
    reason = _unavailable_reason(data.answers.advisories)
    outcome = AdvisoryOutcome(AdvisoryOutcomeKind.COULD_NOT_CHECK, reason=reason)
    return tuple(
        DeviceAdvice(device=device.id, advisory_outcome=outcome) for device in data.topology.devices
    )


def _unavailable_reason[AnswerT](answer: CiscoAnswer[AnswerT]) -> str:
    """Why the Advisory source gave no outcome: its outage reason, or the placeholder."""
    if isinstance(answer, SourceUnavailable):
        return answer.reason
    return _NOT_BUILT
