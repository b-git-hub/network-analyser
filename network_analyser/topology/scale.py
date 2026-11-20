"""v1's Finding kinds on the 0.2.0 scale (stories 83-85; #93).

The scale is fixed here, once, so the same kind is ranked and advised the same way in every
Run and on every surface. `scaled` is the one way `topology` builds a Finding: it keeps v1's
stable id, devices, items, evidence, kind and summary, and adds the level, the Check identity,
what was found, what to do and the source.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from network_analyser.records.topology import (
    Check,
    CheckType,
    Evidence,
    Finding,
    FindingKind,
    FindingLevel,
)

CONFIG: Final = "config"
"""The source of a Finding read from switchport or port-channel settings."""
REPORTS: Final = "device reports"
"""The source of a Finding read from CDP, LLDP, MAC or ARP reports."""


@dataclass(frozen=True, slots=True)
class FindingScale:
    """The fixed 0.2.0 scale for one v1 Finding kind.

    Attributes:
        level: Critical, High, Medium or Low.
        check: the Check that raises it.
        what_to_do: how to fix it, as fixed text.
        source: where it comes from.
    """

    level: FindingLevel
    check: Check
    what_to_do: str
    source: str


SCALE: Final = MappingProxyType(
    {
        FindingKind.CONFLICTING_EVIDENCE: FindingScale(
            FindingLevel.LOW,
            Check(
                "topology-conflicting-evidence",
                "Conflicting evidence",
                CheckType.TOPOLOGY,
            ),
            "Check both reports for the port and correct the cabling or the report that disagrees.",
            REPORTS,
        ),
        FindingKind.BUNDLE_MEMBER_MISMATCH: FindingScale(
            FindingLevel.MEDIUM,
            Check(
                "topology-bundle-member-mismatch",
                "Bundle member mismatch",
                CheckType.TOPOLOGY,
            ),
            "Put the member Link in the same port-channel at both ends, or remove it from "
            "the Bundle.",
            CONFIG,
        ),
        FindingKind.VLAN_ON_ONE_END: FindingScale(
            FindingLevel.LOW,
            Check(
                "topology-vlan-on-one-end",
                "VLAN on one end only",
                CheckType.TOPOLOGY,
                soft=True,
            ),
            "Add the VLAN to the other end, or prune it from this end.",
            CONFIG,
        ),
        FindingKind.DIFFERING_NATIVE_VLAN: FindingScale(
            FindingLevel.MEDIUM,
            Check(
                "topology-differing-native-vlan",
                "Differing native VLAN",
                CheckType.TOPOLOGY,
            ),
            "Set the same native VLAN on both ends.",
            CONFIG,
        ),
        FindingKind.TRUNK_FACING_ACCESS: FindingScale(
            FindingLevel.MEDIUM,
            Check(
                "topology-trunk-facing-access",
                "Trunk facing access",
                CheckType.TOPOLOGY,
            ),
            "Make both ends a trunk, or both an access port.",
            CONFIG,
        ),
        FindingKind.DIFFERING_ACCESS_VLANS: FindingScale(
            FindingLevel.MEDIUM,
            Check(
                "topology-differing-access-vlans",
                "Differing access VLANs",
                CheckType.TOPOLOGY,
            ),
            "Set the same access VLAN on both ends.",
            CONFIG,
        ),
    }
)


def scaled(  # noqa: PLR0913 (the Finding's v1 fields, each by name)
    kind: FindingKind,
    *,
    ident: str,
    summary: str,
    devices: tuple[str, ...],
    items: tuple[str, ...],
    evidence: tuple[Evidence, ...],
) -> Finding:
    """Return a v1 Finding carrying the fixed 0.2.0 scale for its kind."""
    rank = SCALE[kind]
    return Finding(
        id=ident,
        devices=devices,
        items=items,
        evidence=evidence,
        level=rank.level,
        check=rank.check,
        what_was_found=summary,
        what_to_do=rank.what_to_do,
        source=rank.source,
        kind=kind,
        summary=summary,
    )
