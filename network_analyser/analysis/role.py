"""The one Medium "Device Role is out of date" Finding per device (#102, story 80).

A Device Role generated before release 0.2.0 has no permission for the new show commands, so
the device refuses them and the visit records each refusal as `<command>: denied`. This Check
turns those refusals into one Finding per device, naming the Checks that could not run and
pointing at `role-snippet`. The Checks those commands feed are skipped for that device
(`CheckRun.skipped`), never passed.

IOS answers `% Invalid input detected` both for a command its Device Role refuses and for a
command its image does not have, and the reply cannot tell them apart. The Finding therefore
names both causes rather than blaming the Role alone (operator decision on #142, 2026-11-22).

Only the 0.2.0 commands count: a denied v1 collection command is not blamed on the Role. The
per-command map is `CHECK_IDS_BY_DATA`, keyed by the `Collected` field the command fills, so
the same record works for IOS/IOS-XE and NX-OS without either Platform being imported here.
"""

from collections.abc import Mapping
from typing import Final

from network_analyser.analysis.catalogue import ROLE_CHECK, check_name
from network_analyser.analysis.ids import finding_id
from network_analyser.analysis.outcome import DENIED_SUFFIX
from network_analyser.records.analysis import DEVICE_ROLE_CHECKS_BY_DATA, AnalysisInput
from network_analyser.records.topology import CheckSkip, Finding, FindingLevel, SkippedCheck

__all__ = [
    "CHECK_IDS_BY_DATA",
    "ROLE_CHECK",
    "ROLE_LEVEL",
    "role_out_of_date",
    "role_skipped",
    "skips_for",
]

ROLE_LEVEL: Final = FindingLevel.MEDIUM
"""The level the spec's Levels table gives a Device Role that is out of date."""

CHECK_IDS_BY_DATA: Final[Mapping[str, tuple[str, ...]]] = DEVICE_ROLE_CHECKS_BY_DATA
"""The shared Device Role contract (`records.analysis`), keyed by the `Collected` field."""

_ROLE_POINTER: Final = "Re-apply the Device Role printed by role-snippet."
_ROLE_CAUSES: Final = "The Device Role may be out of date, or the image may not have the command"
"""Both causes of a refused command, because IOS's refusal cannot tell them apart."""


def role_out_of_date(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return one Medium Finding per device whose Device Role refused a 0.2.0 command."""
    findings: list[Finding] = []
    for device in data.topology.devices:
        refused = _refused(data, device.id)
        if not refused:
            continue
        checks = _checks(refused)
        noun = "Check" if len(checks) == 1 else "Checks"
        names = ", ".join(check_name(check_id) for check_id in checks)
        what = f"{_ROLE_CAUSES}: {len(checks)} {noun} could not run ({names}). {_ROLE_POINTER}"
        findings.append(
            Finding(
                id=finding_id(ROLE_CHECK.id, device.id),
                devices=(device.id,),
                items=(),
                evidence=(),
                level=ROLE_LEVEL,
                check=ROLE_CHECK,
                what_was_found=what,
                what_to_do=_ROLE_POINTER,
                source="device reports",
                summary=what,
            )
        )
    return tuple(findings)


def role_skipped(_data: AnalysisInput) -> tuple[CheckSkip, ...]:
    """The Role Check itself is never skipped: its record is the device's own refusals."""
    return ()


def skips_for(data: AnalysisInput, check_id: str) -> tuple[CheckSkip, ...]:
    """Return one skip per device whose refused data feeds `check_id`, for its `CheckRun`."""
    skips: list[CheckSkip] = []
    for device in data.topology.devices:
        reasons = tuple(
            skip.reason
            for skip in _refused(data, device.id)
            if check_id in CHECK_IDS_BY_DATA.get(skip.data, ())
        )
        if reasons:
            skips.append(CheckSkip(device.id, reasons[0]))
    return tuple(skips)


def _refused(data: AnalysisInput, device: str) -> tuple[SkippedCheck, ...]:
    """The 0.2.0 data parts `device` refused, from the Topology's skipped records."""
    return tuple(
        skip
        for skip in data.topology.skipped
        if skip.device == device
        and skip.data in CHECK_IDS_BY_DATA
        and skip.reason.endswith(DENIED_SUFFIX)
    )


def _checks(refused: tuple[SkippedCheck, ...]) -> tuple[str, ...]:
    """The distinct Checks those refusals stopped, in the order the data was denied."""
    return tuple(
        dict.fromkeys(
            check_id for skip in refused for check_id in CHECK_IDS_BY_DATA.get(skip.data, ())
        )
    )
