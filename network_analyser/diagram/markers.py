"""The Map's markers: a count badge and an Upgrade Target tag (#109, stories 96-98).

Every decision about what the Map shows on a device box is made here, from the read-only
`topology.json` content alone:

- The badge counts the Findings that name the device and takes the colour of its worst level
  (Critical, High, Medium or Low). A device with no Findings has no badge, not a `0`.
- The tag shows the device's upgrade path: its Upgrade Target, `no fix in Train` when its
  Advisory outcome reports matches but no release in its Train clears them, or
  `? could not check` when the Advisory outcome says so. A target that still leaves Advisories
  open adds `(no fix in Train)`, so the gap shows on the Map (#124, story 27). A device whose
  advice is absent, whose Upgrade Target is unknown, or whose outcome says there are no
  Critical or High Advisories, has no tag: the tool never guesses (story 97; spec #92,
  Further Notes).
- The legend explains every mark to someone reading the Map (story 98), the combined tag
  included (#124).

Positions stay in `layout.place`, so a badge or tag can never move a device.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from network_analyser.diagram.findings import LEVELS
from network_analyser.diagram.topology_file import (
    DeviceAdvice,
    Plain,
    TopologyFile,
    device_advice,
)

BADGE_LEGEND: Final = "Badge = number of Findings on the device, coloured by its worst level"
TARGET_LEGEND: Final = "\u2191 17.12.8 = the Upgrade Target to move to"
TARGET_PARTIAL_LEGEND: Final = (
    "\u2191 17.12.8 (no fix in Train) = the target still does not clear every Advisory"
)
NO_FIX_LEGEND: Final = "no fix in Train = no release in its Train clears its Advisories"
COULD_NOT_CHECK_LEGEND: Final = "? could not check = its Advisories could not be checked"
NO_FIX: Final = "no fix in Train"
PARTIAL_SUFFIX: Final = " (no fix in Train)"
COULD_NOT_CHECK: Final = "? could not check"
_COULD_NOT_CHECK_PREFIX: Final = "could not check"
_NO_FIX_PREFIX: Final = "no fix in Train"
_NO_ADVISORIES: Final = "no Critical/High Advisories"
_NO_ADVISORIES_PREFIXES: Final = ("no known Critical/High Advisories", _NO_ADVISORIES)
_NOT_AVAILABLE: Final = "not available"


@dataclass(frozen=True, slots=True)
class DeviceMarker:
    """The marks on one device's box.

    Attributes:
        device: the Visited Device's id.
        count: how many Findings name it; 0 when none do.
        level: its worst Finding level, or `""` when it has none.
        tag: the upgrade-path tag, or None when the Map shows none.
        tag_kind: `target`, `no-fix` or `could-not-check`, or `""` for no tag.
    """

    device: str
    count: int
    level: str
    tag: str | None
    tag_kind: str


@dataclass(frozen=True, slots=True)
class MarkerLegend:
    """What the Map's legend says about the badge and each tag (story 98).

    Attributes:
        target_partial: the combined tag for a target that still leaves Advisories open
            (#124), so the legend explains it.
    """

    badge: str
    levels: tuple[str, ...]
    target: str
    target_partial: str
    no_fix: str
    could_not_check: str


@dataclass(frozen=True, slots=True)
class MapMarkers:
    """Every device's marks and the legend that explains them."""

    legend: MarkerLegend
    devices: tuple[DeviceMarker, ...]


def map_markers(topology: TopologyFile) -> MapMarkers:
    """Return the Map's badges and tags for `topology`, without moving any device."""
    levels: dict[str, list[str]] = {}
    for finding in _records(topology.content.get("findings")):
        level = finding.get("level")
        if level not in LEVELS:
            continue
        for device in _device_ids(finding.get("devices")):
            levels.setdefault(device, []).append(level)
    markers = tuple(
        _marker(ident, device, levels)
        for device in _records(topology.content.get("devices"))
        if isinstance(ident := device.get("id"), str)
    )
    return MapMarkers(legend=_legend(), devices=markers)


def _device_ids(value: Plain) -> tuple[str, ...]:
    items = value if isinstance(value, tuple) else ()
    return tuple(dict.fromkeys(item for item in items if isinstance(item, str)))


def _marker(
    ident: str, device: Mapping[str, Plain], levels: Mapping[str, list[str]]
) -> DeviceMarker:
    found = levels.get(ident, [])
    tag, tag_kind = _tag(device_advice(device))
    return DeviceMarker(
        device=ident,
        count=len(found),
        level=next((level for level in LEVELS if level in found), ""),
        tag=tag,
        tag_kind=tag_kind,
    )


def _tag(advice: DeviceAdvice) -> tuple[str | None, str]:
    if not advice.known:
        return None, ""
    if advice.outcome is not None and advice.outcome.startswith(_COULD_NOT_CHECK_PREFIX):
        return COULD_NOT_CHECK, "could-not-check"
    target = advice.upgrade_target
    if target is not None and target.startswith(_NO_FIX_PREFIX):
        return NO_FIX, "no-fix"
    if target and target not in (_NO_ADVISORIES, _NOT_AVAILABLE):
        suffix = PARTIAL_SUFFIX if advice.not_cleared > 0 else ""
        return f"\u2191 {target}{suffix}", "target"
    if (
        target is None
        and advice.target_recorded
        and advice.outcome is not None
        and not advice.outcome.startswith(_NO_ADVISORIES_PREFIXES)
    ):
        return NO_FIX, "no-fix"
    return None, ""


def _legend() -> MarkerLegend:
    return MarkerLegend(
        badge=BADGE_LEGEND,
        levels=LEVELS,
        target=TARGET_LEGEND,
        target_partial=TARGET_PARTIAL_LEGEND,
        no_fix=NO_FIX_LEGEND,
        could_not_check=COULD_NOT_CHECK_LEGEND,
    )


def _records(value: Plain) -> tuple[Mapping[str, Plain], ...]:
    items = value if isinstance(value, tuple) else ()
    return tuple(item for item in items if isinstance(item, Mapping))
