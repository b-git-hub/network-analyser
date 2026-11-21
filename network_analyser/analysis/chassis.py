"""A Visited Device's chassis PID: the one value EoX, Suggestion and compatible lookups use (#134).

Classic IOS and IOS-XE name their chassis in `show version`, so the model is the PID. NX-OS
does not: `show version` gives `C93180YC-EX`, while the real chassis PID is `N9K-C93180YC-EX`.
The NX-OS chassis PID is therefore the chassis entry of `show inventory | json`, and without
one there is no chassis PID, so nothing is looked up under a name Cisco does not know and the
Nexus series stays unconfirmed (story 46).
"""

from network_analyser.analysis.patterns import valid_pid
from network_analyser.analysis.releases import hardware_family
from network_analyser.records.analysis import AnalysisInput, HardwareKind
from network_analyser.records.collected import InventoryKind
from network_analyser.records.platform import Platform
from network_analyser.records.topology import VisitedDevice
from network_analyser.records.unknown import Unknown


def chassis_pid(data: AnalysisInput, device: VisitedDevice) -> str | None:
    """Return the device's chassis PID, or None when the Run did not learn one."""
    if device.platform is Platform.NX_OS:
        return _inventory_chassis(data, device)
    model = device.model
    return model if isinstance(model, str) and model else None


def nexus_series(data: AnalysisInput, device: VisitedDevice) -> str | None:
    """Return the device's Nexus series alias, or None when it cannot be worked out."""
    return hardware_family(chassis_pid(data, device))


def _inventory_chassis(data: AnalysisInput, device: VisitedDevice) -> str | None:
    """The first chassis PID `show inventory` gave, from either place the Run holds it."""
    for item in data.inventory:
        if item.device != device.id:
            continue
        for hardware in item.items:
            if hardware.kind is HardwareKind.CHASSIS and valid_pid(hardware.pid):
                return hardware.pid
    part = data.collected_for(device.management_ip).inventory
    if part is None or isinstance(part, Unknown):
        return None
    for entry in part.value:
        if (
            entry.kind is InventoryKind.CHASSIS
            and isinstance(entry.pid, str)
            and valid_pid(entry.pid)
        ):
            return entry.pid
    return None
