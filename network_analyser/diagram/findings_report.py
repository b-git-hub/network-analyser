"""`findings.html`: the Findings report, one sheet per device (#107, stories 103-111, 117).

The page is drawn from `topology.json` alone, like the diagrams, so `render` redraws it
without a new Run. Only the Run time comes from the Run folder's name, which is the Run's UTC
start (story 118) and which both the Run and a later `render` see.

- Every Finding is listed with its device. The Topology map, the Backups and the Unvisited
  Devices are left out, so the page can be handed to whoever patches and hardens (story 103).
- The top carries the Run time, the total, the counts per level and an index of devices,
  worst first, each with its counts per level (story 104).
- One sheet per device, worst first, headed by hostname, management IP, model and release
  (story 105), led by the Upgrade Target callout with the Latest Release beside it (story
  106).
- The device's Advisories fold into one `<details>` line with their count and the counts per
  level, opening to a table of level, Advisory id link, title, CVSS, CVEs and first-fixed
  release, with the fixed line given once (story 107).
- The other Findings sit in one table (level, Check, what was found, what to do), "Device
  Role out of date" first (story 108). An EoX Finding lists each item with its dates and
  Cisco's replacement PID (story 109).
- A Finding appears on every device sheet it names, so a Link Finding is on both ends and a
  network-wide Finding on each named device (story 110).

The page is static, offline and script-free behind a CSP. Every device string and every Cisco
string passes the Run's secret scan and is then HTML-escaped; `://` in that text becomes an
entity, so the only URLs are the Advisory links, built by `diagram.findings.advisory_href`
from an id that passed the `cisco-sa-` pattern, with `rel="noopener noreferrer"` (stories 51,
111, 117). A file from before Analysis has no level or Check on its Findings; those are left
out, as the Findings tab leaves them out.
"""

import html
import re
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from typing import Final

from network_analyser.diagram.findings import FIXED_NOTE, advisory_href
from network_analyser.diagram.topology_file import (
    NOT_RECORDED,
    DeviceAdvice,
    Plain,
    TopologyFile,
    cisco_lookups,
    device_advice,
)

LEVELS: Final = ("Critical", "High", "Medium", "Low")
"""Worst first. There is no Info level (spec #92, "Levels")."""
DEVICE_ROLE_CHECK: Final = "Device Role out of date"
"""The Check listed first among a device's other Findings (story 108). It is the name
`platforms.collection.DEVICE_ROLE_CHECK` gives the Finding; a test keeps the two equal."""
NOT_AVAILABLE: Final = "not available"
"""Shown for advice this topology.json does not hold, rather than guessing (#89)."""
_POLICY: Final = (
    "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; "
    "img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'"
)
_SCHEME: Final = re.compile(r"://", re.IGNORECASE)
_MATCHED: Final = re.compile(r"(\d+) Advisor(?:y|ies) match", re.IGNORECASE)
_NOT_SAFE: Final = "this topology.json does not record the Advisory answer"
_NOT_LISTED: Final = "the Advisory Findings are not recorded in this topology.json"
_STYLE: Final = (
    "body{font-family:sans-serif;margin:1.5rem;max-width:72rem;}"
    "table{border-collapse:collapse;}"
    "th,td{border:1px solid;padding:0.2rem 0.4rem;vertical-align:top;}"
    "dd{margin:0 0 0.4rem;}"
    ".device{border:1px solid;margin:1.5rem 0;padding:0.4rem 1rem;}"
    ".upgrade{display:flex;flex-wrap:wrap;gap:0.5rem 1.5rem;align-items:baseline;}"
    ".callout{border-left:4px solid;padding:0.4rem 0.8rem;}"
    ".callout.upgrade{border-color:#2f8f4e;}"
    ".callout.no-fix,.callout.could-not-check{border-color:#b04040;}"
    ".latest{margin:0;}"
    ".fixed{font-style:italic;}"
    ".eox{margin:0.3rem 0 0;padding-left:1.2rem;}"
    ".level{font-weight:bold;}"
)


def draw_findings_report(
    topology: TopologyFile, redact: Callable[[str], str], *, run_time: str
) -> str:
    """Return `findings.html` for `topology`, every string passed through `redact` first.

    `run_time` is the Run's UTC start as fixed text, taken from the Run folder's name.
    """
    content = topology.content
    devices = [
        record for record in _records(content.get("devices")) if isinstance(record.get("id"), str)
    ]
    findings = [finding for finding in _records(content.get("findings")) if _scaled(finding)]
    known = {_string(record.get("id")) for record in devices}
    on_device: dict[str, list[Mapping[str, Plain]]] = {}
    orphans: list[Mapping[str, Plain]] = []
    for finding in findings:
        named = [
            ident for ident in dict.fromkeys(_strings(finding.get("devices"))) if ident in known
        ]
        if not named:
            orphans.append(finding)
        for ident in named:
            on_device.setdefault(ident, []).append(finding)
    sheets = sorted(devices, key=lambda record: _sheet_order(record, on_device))
    header = (
        f'<p class="run">Run time {_text(run_time, redact)} \u00b7 '
        f"{_count(len(findings), 'Finding')}</p>\n"
    )
    body = (
        header
        + _top(topology, findings, sheets, on_device, redact)
        + "".join(_sheet(record, on_device.get(_ident(record), []), redact) for record in sheets)
        + _orphans(orphans, redact)
    )
    return _page(body)


# -- The top --------------------------------------------------------------------------------


def _top(
    topology: TopologyFile,
    findings: Sequence[Mapping[str, Plain]],
    sheets: Sequence[Mapping[str, Plain]],
    on_device: Mapping[str, list[Mapping[str, Plain]]],
    redact: Callable[[str], str],
) -> str:
    counts = Counter(_string(finding.get("level")) for finding in findings)
    rows = tuple(_index_row(record, on_device, redact) for record in sheets)
    header = ("Device", *LEVELS, "Findings")
    table = _table(header, rows, ident="device-index")
    return (
        '<section id="summary">\n<h2>Summary</h2>\n'
        f'<dl class="counts"><dt>Findings</dt><dd>{len(findings)}</dd>'
        + "".join(f"<dt>{level}</dt><dd>{counts.get(level, 0)}</dd>" for level in LEVELS)
        + "</dl>\n"
        f'<p class="lookups">{_text(_lookups_line(topology), redact)}</p>\n'
        "<h2>Devices, worst first</h2>\n"
        f"{table}\n</section>\n"
    )


def _index_row(
    record: Mapping[str, Plain],
    on_device: Mapping[str, list[Mapping[str, Plain]]],
    redact: Callable[[str], str],
) -> tuple[str, ...]:
    counts = _counts(record, on_device)
    return (
        _device_link(record, redact),
        *(str(counts.get(level, 0)) for level in LEVELS),
        str(sum(counts.values())),
    )


def _lookups_line(topology: TopologyFile) -> str:
    lookups = cisco_lookups(topology)
    if not lookups.ran:
        return "Cisco lookups did not run."
    if lookups.when is None:
        return "Cisco lookups ran; the time was not recorded."
    return f"Cisco lookups ran on {lookups.when}."


def _sheet_order(
    record: Mapping[str, Plain], on_device: Mapping[str, list[Mapping[str, Plain]]]
) -> tuple[int, int, str, str]:
    """Worst level first, then the device with more Findings, then its name and id."""
    findings = on_device.get(_ident(record), [])
    worst = min((_rank(finding) for finding in findings), default=len(LEVELS))
    return (worst, -len(findings), _device_name(record).casefold(), _ident(record))


def _counts(
    record: Mapping[str, Plain], on_device: Mapping[str, list[Mapping[str, Plain]]]
) -> Counter[str]:
    return Counter(
        _string(finding.get("level")) or "" for finding in on_device.get(_ident(record), [])
    )


# -- One device's sheet ---------------------------------------------------------------------


def _sheet(
    record: Mapping[str, Plain],
    findings: Sequence[Mapping[str, Plain]],
    redact: Callable[[str], str],
) -> str:
    advisories = [finding for finding in findings if _advisory_detail(finding) is not None]
    others = [finding for finding in findings if _advisory_detail(finding) is None]
    return (
        f'<section class="device" id="{_ident(record)}">\n'
        f"<header><h2>{_device_name_text(record, redact)}</h2>\n"
        f"{_facts(record, redact)}</header>\n"
        f"{_callout(record, advisories, redact)}\n"
        f"{_advisories(advisories, _train(record), redact)}\n"
        f"{_others(others, redact)}\n"
        "</section>\n"
    )


def _facts(record: Mapping[str, Plain], redact: Callable[[str], str]) -> str:
    pairs = (
        ("Management IP", _text(record.get("management_ip"), redact)),
        ("Model", _text(record.get("model"), redact)),
        ("Release", _text(record.get("software_version"), redact)),
    )
    rows = "".join(f"<dt>{term}</dt><dd>{detail}</dd>" for term, detail in pairs)
    return f"<dl>{rows}</dl>"


def _callout(
    record: Mapping[str, Plain],
    advisories: Sequence[Mapping[str, Plain]],
    redact: Callable[[str], str],
) -> str:
    """The Upgrade Target callout, with the Latest Release beside it (stories 55-57, 106)."""
    advice = device_advice(record)
    kind, text = _callout_text(advice, advisories)
    latest = _latest(advice, redact)
    return (
        '<div class="upgrade">'
        f'<p class="callout {kind}"><b>{_text(text, redact)}</b></p>'
        f'<p class="latest">{latest}</p>'
        "</div>"
    )


def _callout_text(
    advice: DeviceAdvice,
    advisories: Sequence[Mapping[str, Plain]],
) -> tuple[str, str]:
    """One of the four callouts (story 106), decided from the recorded advice and Findings."""
    if not advice.known or advice.outcome is None:
        return ("could-not-check", f"could not check: {_NOT_SAFE}")
    outcome = advice.outcome
    lowered = outcome.lower()
    if lowered.startswith("could not check"):
        return ("could-not-check", outcome)
    if lowered.startswith("no known"):
        return ("none", "no Critical/High Advisories")
    return _matched_callout(advice, outcome, advisories)


def _matched_callout(
    advice: DeviceAdvice,
    outcome: str,
    advisories: Sequence[Mapping[str, Plain]],
) -> tuple[str, str]:
    """The callout when the outcome says Advisories match this device's release."""
    if _MATCHED.search(outcome) is None:
        return ("could-not-check", f"could not check: {_NOT_SAFE}")
    if not advisories:
        return ("could-not-check", f"could not check: {_NOT_LISTED}")
    if not advice.target_recorded:
        return ("could-not-check", f"could not check: {_NOT_SAFE}")
    return _target_callout(advice)


def _target_callout(advice: DeviceAdvice) -> tuple[str, str]:
    """The callout for a recorded Upgrade Target: a release, or its fixed "no fix" text.

    A target that does not clear every Advisory says so, and names the Train the rest need
    (#124, story 23). `not available` is shown as it is, never turned into an upgrade
    instruction: it means the fix could not be worked out (#136).
    """
    target = advice.upgrade_target
    if target is None:
        return ("no-fix", _no_fix(advice))
    lowered = target.lower()
    if lowered == NOT_AVAILABLE:
        return ("could-not-check", NOT_AVAILABLE)
    if lowered.startswith("no fix"):
        return ("no-fix", target)
    if lowered.startswith("no critical"):
        return ("none", "no Critical/High Advisories")
    return ("upgrade", f"Upgrade to {target} or later{_leaves_open(advice)}")


def _leaves_open(advice: DeviceAdvice) -> str:
    """What the target leaves open, or nothing when it clears every Advisory (#124)."""
    if advice.not_cleared <= 0:
        return ""
    return f" (does not clear {advice.not_cleared} Advisories: {_no_fix(advice)})"


def _no_fix(advice: DeviceAdvice) -> str:
    return f"no fix in Train {advice.train}" if advice.train else "no fix in this device's Train"


def _latest(advice: DeviceAdvice, redact: Callable[[str], str]) -> str:
    """Both Latest Release values with Cisco's lifecycle code beside each (#127)."""
    in_train = _latest_value(advice.latest_in_train, advice.latest_in_train_lifecycle, redact)
    overall = _latest_value(advice.latest_release, advice.latest_release_lifecycle, redact)
    return f"Latest Release in Train: {in_train}; overall: {overall}"


def _latest_value(release: str | None, lifecycle: str | None, redact: Callable[[str], str]) -> str:
    shown = _text(NOT_AVAILABLE if release is None else release, redact)
    if lifecycle is None:
        return shown
    return f"{shown} ({_text(lifecycle, redact)})"


def _advisories(
    advisories: Sequence[Mapping[str, Plain]], train: str | None, redact: Callable[[str], str]
) -> str:
    """The device's Advisories, folded into one `<details>` (story 107)."""
    if not advisories:
        return ""
    counts = Counter(_string(finding.get("level")) for finding in advisories)
    summary = f"{_count(len(advisories), 'Advisory', 'Advisories')} \u2014 " + ", ".join(
        f"{counts[level]} {level}" for level in LEVELS if counts.get(level)
    )
    ordered = sorted(advisories, key=lambda finding: (_rank(finding), _string(finding.get("id"))))
    rows = tuple(_advisory_row(finding, train, redact) for finding in ordered)
    table = _table(("Level", "Advisory", "Title", "CVSS", "CVEs", "First fixed"), rows)
    return (
        f"<details><summary>{_text(summary, redact)}</summary>\n"
        f'<p class="fixed">{_text(FIXED_NOTE, redact)}</p>\n{table}\n</details>'
    )


def _advisory_row(
    finding: Mapping[str, Plain], train: str | None, redact: Callable[[str], str]
) -> tuple[str, ...]:
    detail = _advisory_detail(finding) or {}
    first_fixed = _string(detail.get("first_fixed"), strict=True)
    if first_fixed is None:
        first_fixed = _first_fixed_text(detail, train)
    return (
        _level(finding, redact),
        _advisory_link(detail, redact),
        _text(detail.get("title"), redact),
        _text(detail.get("cvss"), redact),
        _text(", ".join(_strings(detail.get("cves"))) or NOT_RECORDED, redact),
        _text(first_fixed, redact),
    )


def _first_fixed_text(detail: Mapping[str, Plain], train: str | None) -> str:
    """The First fixed cell when Cisco named no release: unknown, or none in the Train (#136)."""
    if detail.get("fix_unresolved") is True:
        return NOT_AVAILABLE
    return f"no fix in Train {train}" if train else "no fix in its Train"


def _advisory_link(detail: Mapping[str, Plain], redact: Callable[[str], str]) -> str:
    """Cisco's page, linked only from an id that passed the `cisco-sa-` pattern (story 51)."""
    ident = _string(detail.get("id"), strict=True)
    shown = _text(detail.get("id"), redact)
    href = None if ident is None else advisory_href(ident)
    if href is None:
        return shown
    return f'<a href="{href}" rel="noopener noreferrer">{shown}</a>'


def _others(others: Sequence[Mapping[str, Plain]], redact: Callable[[str], str]) -> str:
    """The device's other Findings in one table, "Device Role out of date" first (story 108)."""
    if not others:
        return "<p>No Findings recorded for this device.</p>"
    rows = tuple(
        (
            _level(finding, redact),
            _text(_check(finding).get("name"), redact),
            _found(finding, redact),
            _text(finding.get("what_to_do"), redact),
        )
        for finding in sorted(others, key=_other_order)
    )
    return (
        "<h3>Other Findings</h3>\n"
        f"{_table(('Level', 'Check', 'What was found', 'What to do'), rows)}"
    )


def _other_order(finding: Mapping[str, Plain]) -> tuple[int, int, str, str, str]:
    name = _string(_check(finding).get("name")) or ""
    return (
        0 if name == DEVICE_ROLE_CHECK else 1,
        _rank(finding),
        name,
        _string(finding.get("what_was_found")) or "",
        _string(finding.get("id")) or "",
    )


def _found(finding: Mapping[str, Plain], redact: Callable[[str], str]) -> str:
    """What was found, then an EoX Finding's items with their dates and replacement (story 109)."""
    text = _text(finding.get("what_was_found"), redact)
    detail = _record(finding.get("cisco_detail"))
    if detail is None:
        return text
    return text + _eox(detail, redact)


def _eox(detail: Mapping[str, Plain], redact: Callable[[str], str]) -> str:
    items = _records(detail.get("items"))
    if not items:
        return ""
    lines = "".join(f"<li>{_eox_item(item, redact)}</li>" for item in items)
    return f'<ul class="eox">{lines}</ul>'


def _eox_item(item: Mapping[str, Plain], redact: Callable[[str], str]) -> str:
    parts = [
        f"{label} {_text(item.get(field), redact)}"
        for label, field in (
            ("Last date of support", "last_date_of_support"),
            ("End of security support", "end_of_security_support"),
            ("End of SW maintenance", "end_of_sw_maintenance"),
            ("End of sale", "end_of_sale"),
        )
        if _string(item.get(field), strict=True) is not None
    ]
    replacement = _string(item.get("replacement"), strict=True)
    parts.append(
        f"Replacement PID {_text(replacement, redact)}"
        if replacement is not None
        else "no replacement PID named"
    )
    return f"<b>{_text(item.get('name'), redact)}</b>: {'; '.join(parts)}"


def _orphans(findings: Sequence[Mapping[str, Plain]], redact: Callable[[str], str]) -> str:
    """Findings that name no known device, so no sheet carries them."""
    if not findings:
        return ""
    rows = tuple(
        (
            _level(finding, redact),
            _text(_check(finding).get("name"), redact),
            _found(finding, redact),
            _text(finding.get("what_to_do"), redact),
        )
        for finding in sorted(findings, key=_other_order)
    )
    return (
        '<section id="no-device">\n<h2>Findings with no device</h2>\n'
        f"{_table(('Level', 'Check', 'What was found', 'What to do'), rows)}\n</section>\n"
    )


# -- Small pieces ---------------------------------------------------------------------------


def _level(finding: Mapping[str, Plain], redact: Callable[[str], str]) -> str:
    level = _string(finding.get("level"))
    return f'<span class="level">{_text(level, redact)}</span>'


def _device_link(record: Mapping[str, Plain], redact: Callable[[str], str]) -> str:
    return f'<a href="#{_ident(record)}">{_device_name_text(record, redact)}</a>'


def _ident(record: Mapping[str, Plain]) -> str:
    """A device record's id. The page keeps only records whose id is already text."""
    value = record.get("id")
    return value if isinstance(value, str) else ""


def _device_name(record: Mapping[str, Plain]) -> str:
    """The hostname, or the management IP when no hostname was read, or the id."""
    for field in ("hostname", "management_ip"):
        value = _string(record.get(field), strict=True)
        if value is not None:
            return value
    return _ident(record)


def _device_name_text(record: Mapping[str, Plain], redact: Callable[[str], str]) -> str:
    return _text(_device_name(record), redact)


def _train(record: Mapping[str, Plain]) -> str | None:
    return device_advice(record).train


def _check(finding: Mapping[str, Plain]) -> Mapping[str, Plain]:
    return _record(finding.get("check")) or {}


def _advisory_detail(finding: Mapping[str, Plain]) -> Mapping[str, Plain] | None:
    """An Advisory Finding's Cisco detail, or None for any other Finding."""
    if _string(_check(finding).get("type")) != "Advisory":
        return None
    detail = _record(finding.get("cisco_detail"))
    if detail is None or _string(detail.get("id"), strict=True) is None:
        return None
    return detail


def _rank(finding: Mapping[str, Plain]) -> int:
    level = _string(finding.get("level"))
    return LEVELS.index(level) if level in LEVELS else len(LEVELS)


def _scaled(finding: Mapping[str, Plain]) -> bool:
    check = _record(finding.get("check"))
    return (
        _string(finding.get("level")) in LEVELS
        and check is not None
        and all(
            _string(check.get(field), strict=True) is not None for field in ("id", "name", "type")
        )
    )


def _count(number: int, noun: str, plural: str | None = None) -> str:
    """`1 Finding` or `3 Findings`; `plural` for a word like Advisory."""
    if number == 1:
        return f"1 {noun}"
    return f"{number} {plural if plural is not None else f'{noun}s'}"


def _shown(value: object) -> str:
    """A leaf as the operator reads it: its text, or the fixed reason it is unknown."""
    if value is None:
        return "not recorded"
    if isinstance(value, Mapping):
        reason = value.get("unknown")
        return reason if isinstance(reason, str) else NOT_RECORDED
    return str(value)


def _text(value: object, redact: Callable[[str], str]) -> str:
    """Scan `value`, HTML-escape it, and break any `://` so device text holds no URL.

    Escaping is for text between tags, never an attribute: every id that reaches one was
    checked as a plain id. So `'` and `"` stay as the operator reads them.
    """
    escaped = html.escape(redact(_shown(value)), quote=False)
    return _SCHEME.sub(":&#47;&#47;", escaped).replace("\n", "<br>\n")


def _string(value: Plain, *, strict: bool = False) -> str | None:
    """A leaf's text, or None when it is missing, unknown or not text.

    With `strict`, a value that is not text reads as None, so a caller can tell "the file
    says nothing" from a value that happens to read `not recorded`.
    """
    if isinstance(value, str):
        return value
    if value is None and not strict:
        return NOT_RECORDED
    return None


def _strings(value: Plain) -> tuple[str, ...]:
    return tuple(item for item in _items(value) if isinstance(item, str))


def _items(value: Plain) -> tuple[Plain, ...]:
    return value if isinstance(value, tuple) else ()


def _record(value: Plain) -> Mapping[str, Plain] | None:
    """A record's fields, or None when the field is missing or unknown."""
    if not isinstance(value, Mapping):
        return None
    if set(value) == {"unknown"} and isinstance(value.get("unknown"), str):
        return None
    return value


def _records(value: Plain) -> tuple[Mapping[str, Plain], ...]:
    return tuple(record for item in _items(value) if (record := _record(item)) is not None)


def _table(
    headers: tuple[str, ...], rows: Sequence[tuple[str, ...]], *, ident: str | None = None
) -> str:
    """A table whose cells are already escaped HTML. Headers are the tool's own words."""
    name = "" if ident is None else f' id="{ident}"'
    head = "".join(f"<th>{html.escape(cell)}</th>" for cell in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return (
        f"<table{name}><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
        if rows
        else f"<table{name}><thead><tr>{head}</tr></thead><tbody></tbody></table>"
    )


def _page(body: str) -> str:
    """The document around the sections. Nothing here is device text."""
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{_POLICY}">\n'
        '<meta name="referrer" content="no-referrer">\n'
        "<title>Network Analyser findings report</title>\n"
        f"<style>{_STYLE}</style>\n</head>\n<body>\n"
        "<h1>Findings report</h1>\n"
        f"{body}</body>\n</html>\n"
    )
