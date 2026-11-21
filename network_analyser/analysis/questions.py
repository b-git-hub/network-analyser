"""The lookup questions Analysis hands the online step, with no device record in them (#94).

Only PIDs (chassis, stack members, supervisors and line cards) and OS type + release strings
leave Analysis. Every value is checked against a strict pattern, de-duplicated and sorted, so
a strange device string is dropped rather than sent (stories 12-14).

The release is normalised before it is a question, and its family comes from the table decided
on #78 (stories 44-45), so two devices that print the same release differently ask Cisco once.
An NX-OS device also asks about its Nexus hardware family; a family that cannot be worked out
asks on release alone, and the Finding says so (story 46).
"""

from network_analyser.analysis.patterns import valid_pid, valid_release
from network_analyser.analysis.releases import family_of, hardware_family, normalise_release
from network_analyser.records.analysis import (
    AnalysisInput,
    HardwareItem,
    HardwareKind,
    LookupQuestions,
    OsType,
    ReleaseQuestion,
)
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
        _add_device_pids(pids, device)
        _add_chassis_pid(compatible_pids, device)
        question = _release_question(device)
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


def _add_chassis_pid(pids: set[str], device: VisitedDevice) -> None:
    """Add a device's chassis model only: never a line card, stack member or other part."""
    if isinstance(device.model, str):
        _add_pid(pids, HardwareItem(device.model, HardwareKind.CHASSIS))


def _add_device_pids(pids: set[str], device: VisitedDevice) -> None:
    """Add a device's chassis and stack-member PIDs, when they look like PIDs."""
    if isinstance(device.model, str):
        _add_pid(pids, HardwareItem(device.model, HardwareKind.CHASSIS))
    stack = device.stack_members
    if isinstance(stack, Unknown):
        return
    for member in stack:
        if isinstance(member.model, str):
            _add_pid(pids, HardwareItem(member.model, HardwareKind.STACK_MEMBER))


def _add_pid(pids: set[str], item: HardwareItem) -> None:
    if valid_pid(item.pid):
        pids.add(item.pid)


def _release_question(device: VisitedDevice) -> ReleaseQuestion | None:
    """The one question a device's release asks, or None when its family is not in the table."""
    os_type = family_of(device.platform, device.software_version)
    if os_type is None or not isinstance(device.software_version, str):
        return None
    release = normalise_release(device.software_version)
    if not valid_release(release):
        return None
    family = hardware_family(device.model) if os_type is OsType.NX_OS else None
    return ReleaseQuestion(os_type, release, family)
