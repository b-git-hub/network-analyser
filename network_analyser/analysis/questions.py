"""The lookup questions Analysis hands the online step, with no device record in them (#94).

Only PIDs (chassis, stack members, supervisors and line cards) and OS type + release strings
leave Analysis. Every value is checked against a strict pattern, de-duplicated and sorted, so
a strange device string is dropped rather than sent (stories 12-14).

The release is normalised before it is a question, and its family comes from the table decided
on #78 (stories 44-45), so two devices that print the same release differently ask Cisco once.
An NX-OS device also asks about its Nexus hardware family, worked out from its chassis PID in
`show inventory | json` (#134); a family that cannot be worked out asks on release alone, and
the Finding says so (story 46). The PIDs asked about are the chassis PID, never the model
`show version` gives an NX-OS device.
"""

from network_analyser.analysis.chassis import chassis_pid, nexus_series
from network_analyser.analysis.releases import family_of, normalise_release
from network_analyser.records.analysis import (
    AnalysisInput,
    HardwareItem,
    HardwareKind,
    LookupQuestions,
    OsType,
    ReleaseQuestion,
)
from network_analyser.records.lookup_values import is_safe_pid, is_safe_release
from network_analyser.records.platform import Platform
from network_analyser.records.topology import VisitedDevice
from network_analyser.records.unknown import Unknown


def lookup_questions(data: AnalysisInput) -> LookupQuestions:
    """Return the de-duplicated, pattern-valid questions the Run may ask Cisco.

    It reads only Visited Devices. Unvisited Devices are never asked about (story 3).
    """
    pids: set[str] = set()
    compatible_pids: set[str] = set()
    releases: set[ReleaseQuestion] = set()
    for device in data.topology.devices:
        _add_device_pids(pids, data, device)
        _add_chassis_pid(compatible_pids, data, device)
        question = _release_question(data, device)
        if question is not None:
            releases.add(question)
    for inventory in data.inventory:
        for item in inventory.items:
            _add_pid(pids, item)
    return LookupQuestions(
        pids=tuple(sorted(pids)),
        releases=tuple(
            sorted(
                releases,
                key=lambda q: (q.os_type.value, q.release, q.hardware_family or ""),
            )
        ),
        compatible_pids=tuple(sorted(compatible_pids)),
    )


def _add_chassis_pid(pids: set[str], data: AnalysisInput, device: VisitedDevice) -> None:
    """Add a device's chassis PID only: never a line card, stack member or other part."""
    pid = chassis_pid(data, device)
    if pid is not None:
        _add_pid(pids, HardwareItem(pid, HardwareKind.CHASSIS))


def _add_device_pids(pids: set[str], data: AnalysisInput, device: VisitedDevice) -> None:
    """Add a device's chassis and stack-member PIDs, when they look like PIDs.

    An NX-OS device is one switch whose only "stack member" carries the `show version` model,
    which is not a PID Cisco knows, so only its chassis PID from `show inventory` is added.
    """
    _add_chassis_pid(pids, data, device)
    stack = device.stack_members
    if isinstance(stack, Unknown) or device.platform is Platform.NX_OS:
        return
    for member in stack:
        if isinstance(member.model, str):
            _add_pid(pids, HardwareItem(member.model, HardwareKind.STACK_MEMBER))


def _add_pid(pids: set[str], item: HardwareItem) -> None:
    if is_safe_pid(item.pid):
        pids.add(item.pid)


def _release_question(data: AnalysisInput, device: VisitedDevice) -> ReleaseQuestion | None:
    """The one question a device's release asks, or None when its family is not in the table."""
    os_type = family_of(device.platform, device.software_version)
    if os_type is None or not isinstance(device.software_version, str):
        return None
    release = normalise_release(device.software_version)
    if not is_safe_release(release):
        return None
    family = nexus_series(data, device) if os_type is OsType.NX_OS else None
    return ReleaseQuestion(os_type, release, family)
