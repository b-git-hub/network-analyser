"""The Findings tab's model: by level, then one row per Check (#108, stories 86-95).

The page draws this model; every decision about what the tab shows is made here, from the
read-only `topology.json` content alone:

- Findings are grouped by level, Critical first, and within a level by Check. One Check whose
  Findings differ in level appears once under each level (story 88).
- A row counts devices, or Links when the Check concerns Links (story 87).
- Filter chips name every Check type (story 90).
- Picking a row gives the devices and Links it hit, so the page can light only those and dim
  the rest (story 91); a network-wide Finding names every device it hit (story 92).
- An Advisory's pane carries Cisco's own detail, and a safe link built only from an id that
  passes the `cisco-sa-` pattern (stories 51 and 93); any other Check's pane carries its
  advice and where it was found (story 94).
- The header says whether Cisco lookups ran and when, read through the one
  `topology_file.cisco_lookups` accessor (story 95; the field lands in #104).

A Finding from before #93 has no level or Check, so the tab leaves it out; the Map still
draws it from its v1 `kind` and `summary`.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from network_analyser.diagram.topology_file import (
    DeviceAdvice,
    Plain,
    TopologyFile,
    cisco_lookups,
    device_advice,
)

LEVELS: Final = ("Critical", "High", "Medium", "Low")
"""Worst first. There is no Info level (spec #92, "Levels")."""
OPEN_BY_DEFAULT: Final = frozenset({"Critical", "High", "Medium"})
"""Levels the page opens on load (story 86)."""
CHECK_TYPES: Final = ("Advisory", "Configuration", "Lifecycle", "Consistency", "Topology")
"""Every Check type, in the order the filter chips show them (story 90)."""
AFFECTED_RELEASE: Final = "Affected release"
FIXED_NOTE: Final = (
    "Matched on software release only. Cisco may limit this Advisory to devices that use a "
    "particular feature; see 'Vulnerable Products' on Cisco's page."
)
"""The fixed line every Advisory pane carries (story 49)."""
NOT_RECORDED: Final = "not recorded"
NOT_AVAILABLE: Final = "not available"
"""Shown for advice this topology.json does not hold, rather than guessing (#105, #89)."""

_ADVISORY_ID: Final = re.compile(r"cisco-sa-[A-Za-z0-9._-]{1,160}")
_ADVISORY_HREF: Final = (
    "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/"
)
"""Cisco's Advisory page, followed only by an id that passed `_ADVISORY_ID` (story 51)."""


@dataclass(frozen=True, slots=True)
class LookupHeader:
    """What the tab says about Cisco lookups (story 95).

    Attributes:
        ran: whether Cisco lookups ran during the Run.
        when: when they ran, as the file records it; None when it recorded no time.
        text: the line the page shows.
    """

    ran: bool
    when: str | None
    text: str


@dataclass(frozen=True, slots=True)
class Chip:
    """One filter chip: All, or one Check type (story 90)."""

    type: str
    label: str


@dataclass(frozen=True, slots=True)
class DeviceRow:
    """One affected device in an Advisory's table (story 93).

    Attributes:
        hostname: its hostname, or its management IP when no hostname was read.
        management_ip: the address the tool logged into.
        model: its model.
        release: its software release.
        upgrade_target: its Upgrade Target, `no fix in Train`, or `not available`.
        latest_release: its Latest Release, or `not available`.
        not_cleared: how many Advisories its Upgrade Target leaves open (#124); 0 when none.
    """

    hostname: str
    management_ip: str
    model: str
    release: str
    upgrade_target: str
    latest_release: str
    not_cleared: int


@dataclass(frozen=True, slots=True)
class FindingRow:
    """One row of another Check's where-and-what table (story 94)."""

    where: str
    what_was_found: str


@dataclass(frozen=True, slots=True)
class AdvisoryPane:
    """An Advisory Check's detail pane (stories 51, 93).

    Attributes:
        id: Cisco's Advisory id.
        href: the link to Cisco's page; None when the id did not pass the pattern.
        title: the Advisory's title, in Cisco's words.
        sir: Cisco's Security Impact Rating.
        cves: the CVEs it covers.
        published: when Cisco published it.
        updated: when Cisco last updated it.
        status: always `Affected release`.
        note: the fixed line about a release-only match.
        devices: the affected devices, in hostname order.
    """

    id: str
    href: str | None
    title: str
    sir: str
    cves: tuple[str, ...]
    published: str
    updated: str
    status: str
    note: str
    devices: tuple[DeviceRow, ...]


@dataclass(frozen=True, slots=True)
class CheckRow:
    """One Check under one level (stories 87-89).

    Attributes:
        key: `"<level>:<Check id>"`, the row's key when the same Check appears under two
            levels.
        level: the level this row sits under.
        name: the Check's name.
        type: the Check's type.
        soft: True for a soft Check, listed last in its level.
        title: what the row shows first: an Advisory's id, or the Check's name.
        subtitle: an Advisory's title and SIR, or the Check's type.
        count: devices the Check hit, or Links for a Link Check.
        count_label: `3 devices` or `2 Links`.
        findings: how many Findings this Check has at this level.
        devices: the ids of the devices it hit.
        items: the ids of the Links, Bundles or Shared Segments it hit.
        finding_ids: the ids of its Findings, for `#finding=<id>`.
        advisory: an Advisory's pane; None when Cisco's detail is not recorded.
        what_to_do: how to fix it, for a non-Advisory Check.
        source: where it comes from, for a non-Advisory Check.
        rows: where and what was found, for a non-Advisory Check.
    """

    key: str
    level: str
    name: str
    type: str
    soft: bool
    title: str
    subtitle: str
    count: int
    count_label: str
    findings: int
    devices: tuple[str, ...]
    items: tuple[str, ...]
    finding_ids: tuple[str, ...]
    advisory: AdvisoryPane | None
    what_to_do: str
    source: str
    rows: tuple[FindingRow, ...]


@dataclass(frozen=True, slots=True)
class LevelGroup:
    """One level's group of Checks (story 86).

    Attributes:
        level: Critical, High, Medium or Low.
        open: whether the page opens it on load.
        findings: how many Findings its Checks hold.
        checks: its rows, a soft Check last.
    """

    level: str
    open: bool
    findings: int
    checks: tuple[CheckRow, ...]


@dataclass(frozen=True, slots=True)
class FindingsTab:
    """The whole Findings tab: header, chips and level groups."""

    lookups: LookupHeader
    chips: tuple[Chip, ...]
    total: int
    levels: tuple[LevelGroup, ...]


def findings_tab(topology: TopologyFile) -> FindingsTab:
    """Return the Findings tab's model for `topology`."""
    content = topology.content
    devices = {
        ident: record
        for record in _records(content.get("devices"))
        if isinstance(ident := record.get("id"), str)
    }
    findings = [finding for finding in _records(content.get("findings")) if _scaled(finding)]

    buckets: dict[tuple[str, str], list[Mapping[str, Plain]]] = {}
    for finding in findings:
        level = _text(finding.get("level"))
        check = _record(finding.get("check")) or {}
        buckets.setdefault((level, _text(check.get("id"))), []).append(finding)

    by_level: dict[str, list[tuple[int, CheckRow]]] = {level: [] for level in LEVELS}
    for (level, _check_id), group in buckets.items():
        by_level[level].append((len(group), _check_row(level, group, devices)))

    levels = tuple(
        LevelGroup(
            level=level,
            open=level in OPEN_BY_DEFAULT,
            findings=sum(count for count, _row in rows),
            checks=tuple(row for _count, row in sorted(rows, key=_row_order)),
        )
        for level in LEVELS
        for rows in (by_level[level],)
        if rows
    )
    return FindingsTab(
        lookups=_lookup_header(topology),
        chips=(Chip("All", "All"), *(Chip(name, name) for name in CHECK_TYPES)),
        total=len(findings),
        levels=levels,
    )


def _row_order(item: tuple[int, CheckRow]) -> tuple[bool, str]:
    return (item[1].soft, item[1].key)


def _lookup_header(topology: TopologyFile) -> LookupHeader:
    lookups = cisco_lookups(topology)
    if not lookups.ran:
        text = "Cisco lookups did not run."
    elif lookups.when is None:
        text = "Cisco lookups ran; the time was not recorded."
    else:
        text = f"Cisco lookups ran on {lookups.when}."
    return LookupHeader(ran=lookups.ran, when=lookups.when, text=text)


def _check_row(
    level: str, group: list[Mapping[str, Plain]], devices: Mapping[str, Mapping[str, Plain]]
) -> CheckRow:
    first = group[0]
    check = _record(first.get("check")) or {}
    check_id = _text(check.get("id"))
    check_type = _text(check.get("type"))
    device_ids = tuple(
        sorted({ident for finding in group for ident in _strings(finding.get("devices"))})
    )
    item_ids = tuple(
        sorted({ident for finding in group for ident in _strings(finding.get("items"))})
    )
    link_check = bool(item_ids) and all(_strings(finding.get("items")) for finding in group)
    count = len(item_ids) if link_check else len(device_ids)
    advisory = _advisory_pane(check_type, first, device_ids, devices)
    rows = () if advisory is not None or check_type == "Advisory" else _finding_rows(group, devices)
    title = advisory.id if advisory is not None else _text(check.get("name"))
    subtitle = f"{advisory.title} · SIR {advisory.sir}" if advisory is not None else check_type
    return CheckRow(
        key=f"{level}:{check_id}",
        level=level,
        name=_text(check.get("name")),
        type=check_type,
        soft=check.get("soft") is True,
        title=title,
        subtitle=subtitle,
        count=count,
        count_label=_count_label(count, links=link_check),
        findings=len(group),
        devices=device_ids,
        items=item_ids,
        finding_ids=tuple(sorted(_text(finding.get("id")) for finding in group)),
        advisory=advisory,
        what_to_do=_text(first.get("what_to_do")),
        source=_text(first.get("source")),
        rows=rows,
    )


def _count_label(count: int, *, links: bool) -> str:
    noun = "Link" if links else "device"
    return f"{count} {noun}{'' if count == 1 else 's'}"


def _advisory_pane(
    check_type: str,
    finding: Mapping[str, Plain],
    device_ids: tuple[str, ...],
    devices: Mapping[str, Mapping[str, Plain]],
) -> AdvisoryPane | None:
    if check_type != "Advisory":
        return None
    detail = _record(finding.get("cisco_detail"))
    if detail is None:
        return None
    ident, title, sir = detail.get("id"), detail.get("title"), detail.get("sir")
    if not (isinstance(ident, str) and isinstance(title, str) and isinstance(sir, str)):
        return None
    return AdvisoryPane(
        id=ident,
        href=advisory_href(ident),
        title=title,
        sir=sir,
        cves=_strings(detail.get("cves")),
        published=_text(detail.get("published")),
        updated=_text(detail.get("updated")),
        status=AFFECTED_RELEASE,
        note=FIXED_NOTE,
        devices=_device_rows(device_ids, devices),
    )


def advisory_href(ident: str) -> str | None:
    """Cisco's page for `ident`, or None when it did not pass the `cisco-sa-` pattern.

    The one place a Cisco link is built, for the Findings tab and the Findings report
    (story 51): a reply can never plant a hostile link.
    """
    return f"{_ADVISORY_HREF}{ident}" if _ADVISORY_ID.fullmatch(ident) else None


def _device_rows(
    device_ids: tuple[str, ...], devices: Mapping[str, Mapping[str, Plain]]
) -> tuple[DeviceRow, ...]:
    rows = [_device_row(devices[ident]) for ident in device_ids if ident in devices]
    return tuple(sorted(rows, key=lambda row: (row.hostname, row.management_ip)))


def _device_row(device: Mapping[str, Plain]) -> DeviceRow:
    advice = device_advice(device)
    return DeviceRow(
        hostname=_device_name(device),
        management_ip=_text(device.get("management_ip")),
        model=_text(device.get("model")),
        release=_text(device.get("software_version")),
        upgrade_target=_upgrade_target(advice),
        latest_release=_latest_release(advice),
        not_cleared=advice.not_cleared,
    )


def _device_name(device: Mapping[str, Plain]) -> str:
    for field in ("hostname", "management_ip"):
        value = device.get(field)
        if isinstance(value, str):
            return value
    return _text(device.get("id"))


def _upgrade_target(advice: DeviceAdvice) -> str:
    if not advice.known:
        return NOT_AVAILABLE
    if advice.upgrade_target:
        return advice.upgrade_target
    return "no fix in Train" if advice.target_recorded else NOT_AVAILABLE


def _latest_release(advice: DeviceAdvice) -> str:
    if advice.known and advice.latest_release:
        return advice.latest_release
    return NOT_AVAILABLE


def _finding_rows(
    group: list[Mapping[str, Plain]], devices: Mapping[str, Mapping[str, Plain]]
) -> tuple[FindingRow, ...]:
    rows = [
        FindingRow(
            where=_where(finding, devices),
            what_was_found=_text(finding.get("what_was_found"))
            if isinstance(finding.get("what_was_found"), str)
            else _text(finding.get("summary")),
        )
        for finding in group
    ]
    return tuple(sorted(rows, key=lambda row: (row.where, row.what_was_found)))


def _where(finding: Mapping[str, Plain], devices: Mapping[str, Mapping[str, Plain]]) -> str:
    names = [devices[ident] for ident in _strings(finding.get("devices")) if ident in devices]
    if names:
        return " ⇄ ".join(_device_name(device) for device in names)
    items = _strings(finding.get("items"))
    return ", ".join(items) if items else "the whole network"


def _scaled(finding: Mapping[str, Plain]) -> bool:
    check = _record(finding.get("check"))
    return (
        isinstance(finding.get("level"), str)
        and finding.get("level") in LEVELS
        and check is not None
        and all(isinstance(check.get(field), str) for field in ("id", "name", "type"))
    )


def _records(value: Plain) -> tuple[Mapping[str, Plain], ...]:
    return tuple(item for item in _items(value) if isinstance(item, Mapping))


def _items(value: Plain) -> tuple[Plain, ...]:
    return value if isinstance(value, tuple) else ()


def _strings(value: Plain) -> tuple[str, ...]:
    return tuple(item for item in _items(value) if isinstance(item, str))


def _record(value: Plain) -> Mapping[str, Plain] | None:
    if not isinstance(value, Mapping):
        return None
    return None if isinstance(value.get("unknown"), str) and len(value) == 1 else value


def _text(value: Plain) -> str:
    return value if isinstance(value, str) else NOT_RECORDED
