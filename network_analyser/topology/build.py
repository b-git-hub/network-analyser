"""`build(records)`: turn a Run's device records into its Topology (#52).

The order: Visited Devices and their addresses; which device each CDP and LLDP entry is
(Unvisited Devices merged); Links and Shared Segments; vPC labels and Bundles; then what was
not collected and the interface names the table did not know. VLAN Mismatches (#61) run
after Bundles. Later rules (#62 L3 Adjacency and inference) slot in beside them.
"""

from collections.abc import Iterable

from network_analyser.records.collected import Collected, Reading
from network_analyser.records.device import DeviceRecord
from network_analyser.records.interface_names import InterfaceName
from network_analyser.records.topology import SkippedCheck, Topology, UnknownInterfaceName
from network_analyser.records.unknown import Unknown
from network_analyser.topology.bundles import bundling
from network_analyser.topology.devices import (
    Claim,
    Known,
    known_devices,
    own_addresses,
    resolve,
    visited_device,
)
from network_analyser.topology.links import cabling
from network_analyser.topology.vlan import vlan_checks

_PARTS = tuple(Collected.__dataclass_fields__)


def build(records: Iterable[DeviceRecord]) -> Topology:
    """Return the Topology of every device record of a Run.

    `records` holds one record per device the tool tried, and one per Neighbour address the
    crawl chose not to try (`outcome` UNVISITED, with its reason). The order does not matter.
    """
    records = tuple(records)
    devices = known_devices(records)
    owners = own_addresses(devices)
    claims, unvisited = resolve(devices, records, owners)
    names = {d.id: d.name for d in devices} | {
        u.id: u.label if isinstance(u.label, str) else u.id for u in unvisited
    }
    cables = cabling(claims, lambda device: names.get(device, device))
    bundled = bundling(cables.links, devices, owners, lambda device: names.get(device, device))
    checked = vlan_checks(bundled.links, bundled.bundles, devices, unvisited)
    findings = (*cables.findings, *bundled.findings, *checked.findings)
    skipped = tuple(check for device in devices for check in _skipped(device))
    return Topology(
        devices=tuple(visited_device(d, owners) for d in devices),
        unvisited=tuple(unvisited),
        links=tuple(sorted(bundled.links, key=lambda link: link.id)),
        segments=cables.segments,
        bundles=bundled.bundles,
        findings=tuple(sorted(findings, key=lambda finding: finding.id)),
        skipped=(*skipped, *checked.skipped),
        unknown_interface_names=_unknown_names(devices, claims),
    )


def _skipped(device: Known) -> list[SkippedCheck]:
    """Each part of a device's collected data that is unknown, or has gaps (story 126)."""
    checks: list[SkippedCheck] = []
    for part in _PARTS:
        value = getattr(device.collected, part)
        if isinstance(value, Unknown):
            checks.append(SkippedCheck(device.id, part, value.reason))
        elif isinstance(value, Reading):
            checks.extend(SkippedCheck(device.id, part, gap.reason) for gap in value.gaps)
    return checks


def _unknown_names(devices: list[Known], claims: list[Claim]) -> tuple[UnknownInterfaceName, ...]:
    found: set[tuple[str, InterfaceName]] = set()
    for device in devices:
        found.update((device.id, i.name) for i in device.interfaces)
    for claim in claims:
        found.add((claim.reporter, claim.local))
        if not isinstance(claim.far_port, Unknown):
            found.add((claim.far, claim.far_port))
    return tuple(
        sorted(
            {
                UnknownInterfaceName(device, name.reported)
                for device, name in found
                if not name.known
            },
            key=lambda u: (u.device, u.reported),
        )
    )
