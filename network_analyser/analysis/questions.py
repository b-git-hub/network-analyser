"""The lookup questions Analysis hands the online step, with no device record in them (#94).

Only PIDs (chassis, stack members, supervisors and line cards) and OS type + release strings
leave Analysis. Every value is checked against a strict pattern, de-duplicated and sorted, so
a strange device string is dropped rather than sent (stories 12-14).
"""

from network_analyser.analysis.patterns import valid_pid, valid_release
from network_analyser.records.analysis import (
    AnalysisInput,
    HardwareItem,
    HardwareKind,
    LookupQuestions,
    OsType,
    ReleaseQuestion,
)
from network_analyser.records.platform import Platform
from network_analyser.records.topology import VisitedDevice
from network_analyser.records.unknown import Unknown


def lookup_questions(data: AnalysisInput) -> LookupQuestions:
    """Return the de-duplicated, pattern-valid questions the Run may ask Cisco.

    It reads only Visited Devices. Unvisited Devices are never asked about (story 3).
    """
    pids: set[str] = set()
    releases: set[ReleaseQuestion] = set()
    for device in data.topology.devices:
        _add_device_pids(pids, device)
        os_type = _os_type(device)
        release = device.software_version
        if os_type is not None and isinstance(release, str) and valid_release(release):
            releases.add(ReleaseQuestion(os_type, release))
    for inventory in data.inventory:
        for item in inventory.items:
            _add_pid(pids, item)
    return LookupQuestions(
        pids=tuple(sorted(pids)),
        releases=tuple(sorted(releases, key=lambda q: (q.os_type.value, q.release))),
    )


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


def _os_type(device: VisitedDevice) -> OsType | None:
    """The family a device's release is asked about, or None when the Platform is unknown.

    Classic IOS and IOS-XE share one Platform command set, so both are asked as IOS-XE until
    the family table decided on #78 can tell them apart (stories 44-45).
    """
    if device.platform is Platform.NX_OS:
        return OsType.NX_OS
    if device.platform is Platform.IOS_XE:
        return OsType.IOS_XE
    return None
