"""`run-report.html`: a static, offline record of one Run (#66, stories 156-160).

No JavaScript at all, and a Content-Security-Policy `<meta>` tag that allows none. Every
device string is scanned for a typed secret before it is HTML-escaped, and `://` in that
text is written as an entity so a hostname cannot put `http://` into the file. Times are
UTC. The page links a device or a finding to `diagram.html` by the Topology's stable id.

The file is written once, through `write_scanned_text`. `render` never calls this module.
"""

import html
import re
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import Final

from network_analyser.credentials import SecretScan
from network_analyser.records.backup import BackupRecord
from network_analyser.records.device import DeviceRecord, LandingPrivilege, UnvisitedReason
from network_analyser.records.host_keys import HostKeyVerdict
from network_analyser.records.platform import CredentialSetResult, Platform
from network_analyser.records.run_summary import RunReport, RunReportFacts
from network_analyser.records.sweep import SweepResult
from network_analyser.records.topology import (
    Check,
    DeviceAdvice,
    Finding,
    FindingKind,
    FindingLevel,
    Topology,
    VisitedDevice,
)
from network_analyser.records.unknown import Unknown
from network_analyser.run_output.folder import RunFolder
from network_analyser.run_output.scanned_file import write_scanned_text

RUN_REPORT_FILE: Final = "run-report.html"
DEVICE_ROLE_CHECK_ID: Final = "config-device-role-out-of-date"
"""The stable Check id of the Medium "Device Role out of date" Finding (#102, story 80).

`analysis.catalogue.ROLE_CHECK` gives the Finding this id; `run_output` may not import
`analysis`, so the id is repeated here and a test keeps the two equal.
"""
COULD_NOT_CHECK_CHECK_ID: Final = "advisory-could-not-check"
"""The stable Check id of a Low "could not check" Advisory Finding (story 53)."""
CRITICAL_AND_HIGH_ROWS: Final = 10
"""How many of the worst Critical and High Checks the table shows (story 101)."""
_POLICY: Final = (
    "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; "
    "img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'"
)
_ID: Final = re.compile(r"[A-Za-z0-9._-]{1,200}\Z")
_SCHEME: Final = re.compile(r"://", re.IGNORECASE)
ATTENTION_REASONS: Final = frozenset(
    {
        UnvisitedReason.UNREACHABLE.value,
        UnvisitedReason.ALGORITHMS_TOO_OLD.value,
        UnvisitedReason.HOST_KEY_CHANGED.value,
        UnvisitedReason.HOST_KEY_NOT_TRUSTED.value,
        UnvisitedReason.AUTHENTICATION_FAILED.value,
        UnvisitedReason.SETS_RETIRED.value,
    }
)
"""Unvisited reasons marked `!!`, the same set as the console summary (#56)."""
_STYLE: Final = (
    "body{font-family:sans-serif;margin:1.5rem;}"
    "table{border-collapse:collapse;}"
    "th,td{border:1px solid;padding:0.2rem 0.4rem;vertical-align:top;}"
    "dd{margin:0 0 0.4rem;}"
)
_NOT_REPORTED: Final = "not reported"
_MEDIUM_AND_LOW_NOTE: Final = "Medium and Low Advisories are not listed."
_NXOS_NOTE: Final = "openVuln covers NX-OS only from July 2019."
_TLS_NOTE: Final = "Cisco's data was fetched over TLS and not signature-checked."
"""Story 21: said once, and only when Cisco lookups ran."""


def render_run_report(report: RunReport, scan: SecretScan) -> str:
    """Return `run-report.html`. Each device string is scanned before it is escaped."""
    names = _names(report.topology)
    by_ip = _records_by_ip(report.devices)
    locked = {item.ip: item for item in report.backups.backups}
    advice = _advice_by_device(report.topology)
    body = "".join(
        (
            _host_keys(report.devices, scan),
            _visited(report.topology, by_ip, locked, advice, scan),
            _unvisited(report.topology, names, scan),
            _findings(report.topology, names, scan),
            _sweep(report.sweep, scan),
            _credential_sets(report.credential_sets, scan),
        )
    )
    hits = max(report.facts.secret_scan_hits, scan.hits)
    return _page(_summary(report, scan, hits) + _attention(report, names, scan, hits) + body)


def write_run_report(folder: RunFolder, report: RunReport, scan: SecretScan) -> int:
    """Write `run-report.html` in the Run folder through the secret scan.

    Returns the hits `write_scanned_text` counted on the finished page.

    Raises:
        OSError: the file could not be written.
    """
    return write_scanned_text(folder, RUN_REPORT_FILE, render_run_report(report, scan), scan)


def _page(body: str) -> str:
    """The document around the sections. Nothing here is device text."""
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{_POLICY}">\n'
        '<meta name="referrer" content="no-referrer">\n'
        "<title>Network Analyser run report</title>\n"
        f"<style>{_STYLE}</style>\n</head>\n<body>\n"
        "<h1>Run report</h1>\n"
        f"{body}</body>\n</html>\n"
    )


def _summary(report: RunReport, scan: SecretScan, hits: int) -> str:
    """Folder, times, version, account, how it ended, Scope, Seeds, flags and counts."""
    facts = report.facts
    taken = sum(1 for item in report.backups.backups if item.path is not None)
    levels = Counter(finding.level for finding in report.topology.findings)
    pairs = (
        ("Folder", _text(facts.folder, scan)),
        ("Started", _utc(facts.started_at)),
        ("Ended", _utc(facts.ended_at)),
        ("Duration", _clock((facts.ended_at - facts.started_at).total_seconds())),
        ("Tool version", _text(facts.tool_version, scan)),
        ("Windows account", _text(facts.windows_account, scan)),
        ("PC", _text(facts.pc_name, scan)),
        ("How the Run ended", _text(_ending(facts), scan)),
        ("Visited", str(len(report.topology.devices))),
        ("Unvisited", str(len(report.topology.unvisited))),
        ("Findings", str(len(report.topology.findings))),
        *((level.value, str(levels.get(level, 0))) for level in FindingLevel),
        ("Backups locked", f"{taken} of {len(report.backups.backups)}"),
        ("Locking time", f"{report.backups.lock_seconds:.1f} s"),
        ("Secret-scan hits", str(hits)),
    )
    scope = _items(facts.scope, scan) or "<li>none</li>"
    exclusions = _items(facts.exclusions, scan) or "<li>none</li>"
    seeds = _items(facts.seeds, scan) or "<li>none</li>"
    flags = _items(facts.flags, scan)
    return (
        '<section id="summary">\n<h2>Summary</h2>\n'
        f"{_dl(pairs)}\n<h3>Scope</h3>\n<ul>{scope}</ul>\n"
        f"<h3>Exclusions</h3>\n<ul>{exclusions}</ul>\n"
        f"<h3>Seeds</h3>\n<ul>{seeds}</ul>\n"
        f"<h3>Flags</h3>\n<ul>{flags}</ul>\n</section>\n"
    )


def _attention(report: RunReport, names: dict[str, str], scan: SecretScan, hits: int) -> str:
    """Needs attention: notices, the summary's items, Analysis's priorities and a scan hit."""
    items = [_text(notice, scan) for notice in report.facts.notices]
    items.extend(f"!! {_text(item, scan)}" for item in report.attention)
    items.extend(_analysis_attention(report.topology, names, scan))
    if hits:
        pieces = "1 piece" if hits == 1 else f"{hits} pieces"
        items.append(
            "!! "
            + _text(
                f"The secret scan replaced {pieces} of this Run's output with [blocked].",
                scan,
            )
        )
    items.append("!! " + _text(_critical_line(report.topology), scan))
    body = "<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"
    return f'<section id="attention">\n<h2>Needs attention</h2>\n{body}\n</section>\n'


def _analysis_attention(built: Topology, names: dict[str, str], scan: SecretScan) -> list[str]:
    """One line per "could not check" and per Device Role out of date (story 100).

    A Cisco source that is down already has one line from the Run's end, in
    `RunReport.attention`; these are the per-device gaps Analysis found. A whole-source
    outage skips both Checks, so it never turns into one line per device (story 118).
    """
    selected = sorted(
        (
            finding
            for finding in built.findings
            if finding.check.id in (COULD_NOT_CHECK_CHECK_ID, DEVICE_ROLE_CHECK_ID)
        ),
        key=lambda finding: finding.order,
    )
    return ["!! " + _finding_attention(finding, names, scan) for finding in selected]


def _finding_attention(finding: Finding, names: dict[str, str], scan: SecretScan) -> str:
    """`<device>: <what was found>` for one per-device Finding."""
    who = ", ".join(names.get(device, device) for device in finding.devices)
    return _text(f"{who or 'the whole network'}: {finding.what_was_found}", scan)


def _critical_line(built: Topology) -> str:
    """Story 100's one line: how much Critical work there is, and where to read it."""
    critical = [finding for finding in built.findings if finding.level is FindingLevel.CRITICAL]
    checks = len({finding.check.id for finding in critical})
    return f"{len(critical)} Critical Findings from {checks} Checks \u2014 see the Findings report."


def _host_keys(devices: tuple[DeviceRecord, ...], scan: SecretScan) -> str:
    """Host keys trusted for the first time: IP, hostname, key type, fingerprint."""
    rows = [
        (
            _text(record.ip, scan),
            _text(_hostname(record), scan),
            _text(check.key_type, scan),
            _text(check.fingerprint, scan),
        )
        for record in devices
        if (check := record.host_key) is not None and check.verdict is HostKeyVerdict.NEW
    ]
    body = (
        "<p>No host key was trusted for the first time.</p>"
        if not rows
        else _details(
            "New host keys",
            _table(("IP", "Hostname", "Key type", "SHA-256 fingerprint"), rows),
        )
    )
    return f'<section id="host-keys">\n<h2>New host keys</h2>\n{body}\n</section>\n'


def _visited(
    built: Topology,
    by_ip: dict[IPv4Address, DeviceRecord],
    locked: dict[IPv4Address, BackupRecord],
    advice: dict[str, DeviceAdvice],
    scan: SecretScan,
) -> str:
    """Visited Devices, with the login and the Backup beside each one."""
    rows = [
        _visited_row(device, by_ip.get(device.management_ip), locked, advice, scan)
        for device in built.devices
    ]
    body = _details("Visited Devices", _table(_VISITED_HEAD, rows)) if rows else "<p>None.</p>"
    return f'<section id="visited">\n<h2>Visited Devices</h2>\n{body}\n</section>\n'


_VISITED_HEAD: Final = (
    "Device",
    "Management IP",
    "Platform",
    "Username",
    "Landing privilege",
    "Backup",
    "Path",
    "Ciphertext SHA-256",
    "Scrypt level",
    "Upgrade Target",
)


def _advice_by_device(built: Topology) -> dict[str, DeviceAdvice]:
    """Each Visited Device's advice record, when Analysis ran (#124)."""
    if built.analysis is None:
        return {}
    return {record.device: record for record in built.analysis.advice}


def _visited_row(
    device: VisitedDevice,
    record: DeviceRecord | None,
    locked: dict[IPv4Address, BackupRecord],
    advice: dict[str, DeviceAdvice],
    scan: SecretScan,
) -> tuple[str, ...]:
    """One Visited Device's cells. The name links into the diagram."""
    backup = locked.get(device.management_ip)
    credential_set = None if record is None else record.credential_set
    username = None if credential_set is None else credential_set.username
    privilege = None if record is None else record.landing_privilege
    return (
        _link("device", device.id, _shown_name(device.hostname, device.id), scan),
        _text(device.management_ip, scan),
        _text(device.platform, scan),
        _text(username, scan),
        _text(_privilege(privilege), scan),
        _text(_backup_status(backup), scan),
        _text(None if backup is None else backup.path, scan),
        _text(None if backup is None else backup.ciphertext_sha256, scan),
        _text(_scrypt(None if backup is None else backup.scrypt_level), scan),
        _text(_upgrade_target(advice.get(device.id)), scan),
    )


def _upgrade_target(advice: DeviceAdvice | None) -> str:
    """The device's advice, in the same words the Findings report uses (#124, story 29)."""
    if advice is None or not advice.upgrade_target:
        return "not available"
    target = advice.upgrade_target
    lowered = target.lower()
    if lowered == "not available" or lowered.startswith(("no fix", "no critical")):
        return target
    if advice.not_cleared > 0:
        train = f"Train {advice.train}" if advice.train else "this device's Train"
        return (
            f"Upgrade to {target} or later "
            f"(does not clear {advice.not_cleared} Advisories: no fix in {train})"
        )
    return f"Upgrade to {target} or later"


def _unvisited(built: Topology, names: dict[str, str], scan: SecretScan) -> str:
    """Unvisited Devices grouped by reason, attention reasons marked `!!` and listed first."""
    grouped: dict[str, list[str]] = {}
    for device in built.unvisited:
        reason = _reason(device.reason)
        label = names.get(device.id, device.id)
        grouped.setdefault(reason, []).append(
            _link("device", device.id, label, scan) + " " + _text(device.id, scan)
        )
    ordered = sorted(
        grouped,
        key=lambda reason: (reason not in ATTENTION_REASONS, -len(grouped[reason]), reason),
    )
    if not ordered:
        body = "<p>None.</p>"
    else:
        blocks = []
        for reason in ordered:
            mark = "!! " if reason in ATTENTION_REASONS else ""
            items = "".join(f"<li>{item}</li>" for item in grouped[reason])
            heading = f"{mark}{_text(reason, scan)} ({len(grouped[reason])})"
            blocks.append(f"<h3>{heading}</h3><ul>{items}</ul>")
        body = _details("Unvisited Devices", "".join(blocks))
    return f'<section id="unvisited">\n<h2>Unvisited Devices</h2>\n{body}\n</section>\n'


def _findings(built: Topology, names: dict[str, str], scan: SecretScan) -> str:
    """Finding and Check counts, the worst Checks, the Cisco notes and v1's diagnostics.

    The per-Finding list is the Findings report's job, so it is not repeated here (story
    101). The tables v1 added under this heading stay, because they are not in that report.
    """
    findings = built.findings
    checks = {finding.check.id for finding in findings}
    rows = _critical_and_high(findings)
    body = (
        f"<p>{_count(len(findings), 'Finding')} from {_count(len(checks), 'Check')}. "
        f'The full list, with devices, is in <a href="findings.html">findings.html</a>.</p>\n'
        + _hardest_checks(rows, scan)
        + _cisco_notes(built, scan)
        + _topology_details(built, names, scan)
    )
    return f'<section id="findings">\n<h2>Findings</h2>\n{body}\n</section>\n'


def _critical_and_high(
    findings: Sequence[Finding],
) -> tuple[tuple[FindingLevel, Check, int], ...]:
    """One row per Check at Critical and High, worst first, with its device count.

    A Check whose Findings differ in level appears once under each level, as on the
    Findings tab (story 88). Worst first is level, then the most devices hit.
    """
    groups: dict[tuple[FindingLevel, str], list[Finding]] = {}
    for finding in findings:
        if finding.level in (FindingLevel.CRITICAL, FindingLevel.HIGH):
            groups.setdefault((finding.level, finding.check.id), []).append(finding)
    rows = [
        (
            level,
            group[0].check,
            len({device for finding in group for device in finding.devices}),
        )
        for (level, _check_id), group in groups.items()
    ]
    return tuple(
        sorted(
            rows,
            key=lambda row: (
                row[0].rank,
                -row[2],
                row[1].soft,
                row[1].name.casefold(),
                row[1].id,
            ),
        )
    )


def _hardest_checks(rows: tuple[tuple[FindingLevel, Check, int], ...], scan: SecretScan) -> str:
    """The capped Critical and High table, or a line saying there are none (story 101)."""
    if not rows:
        return "<p>No Critical or High Checks.</p>\n"
    shown = rows[:CRITICAL_AND_HIGH_ROWS]
    table = _table(
        ("Level", "Check", "Devices"),
        tuple(
            (_text(level.value, scan), _text(check.name, scan), str(devices))
            for level, check, devices in shown
        ),
    )
    body = f"<p>The Checks that hit hardest:</p>\n{table}\n"
    if len(rows) > len(shown):
        body += (
            f"<p>Showing the worst {len(shown)} of {_count(len(rows), 'Critical and High Check')}"
            ".</p>\n"
        )
    return body


def _cisco_notes(built: Topology, scan: SecretScan) -> str:
    """Story 47's and 54's notes, plus story 21's when Cisco lookups ran."""
    notes = [_MEDIUM_AND_LOW_NOTE, _NXOS_NOTE]
    if built.cisco_lookups is not None and built.cisco_lookups.ran:
        notes.append(_TLS_NOTE)
    return f"<h3>About Cisco data</h3>\n<p>{_text(' '.join(notes), scan)}</p>\n"


def _topology_details(built: Topology, names: dict[str, str], scan: SecretScan) -> str:
    """v1's skipped checks, unrecognised names and unplaced next hops, kept unchanged."""
    checks = _table(
        ("Device", "Data", "Reason"),
        tuple(
            (
                _link("device", item.device, names.get(item.device, item.device), scan),
                _text(item.data, scan),
                _text(item.reason, scan),
            )
            for item in built.skipped
        ),
    )
    names_table = _table(
        ("Device", "Reported name"),
        tuple(
            (
                _link("device", item.device, names.get(item.device, item.device), scan),
                _text(item.reported, scan),
            )
            for item in built.unknown_interface_names
        ),
    )
    hops = _table(
        ("Reporter", "Far device", "VRF", "Next hop", "Why there is no Link"),
        tuple(
            (
                _link("device", hop.reporter, names.get(hop.reporter, hop.reporter), scan),
                _link("device", hop.far, names.get(hop.far, hop.far), scan),
                _text(hop.vrf, scan),
                _text(hop.ip, scan),
                _text(hop.reason, scan),
            )
            for hop in built.unplaced_next_hops
        ),
    )
    body = (
        f"<h3>Unknown checks</h3>\n{checks}\n"
        f"<h3>Unrecognised interface names</h3>\n{names_table}\n"
        f"<h3>Next hops with no Link</h3>\n{hops}\n"
    )
    return _details("Topology details", body)


def _count(count: int, noun: str) -> str:
    """`1 Check`, `0 Checks`: the counts in the Findings section and the table's cap."""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _sweep(sweep: SweepResult | None, scan: SecretScan) -> str:
    """Every probe, or a line when this Run did not sweep."""
    if sweep is None:
        body = "<p>This Run did not sweep.</p>"
    else:
        rows = tuple(
            (
                _text(probe.ip, scan),
                _text("open" if probe.open else "closed", scan),
                _text(probe.ssh_id, scan),
                _text(None if probe.failure is None else probe.failure.value, scan),
            )
            for probe in sweep.probes
        )
        seeds = ", ".join(_text(ip, scan) for ip in sweep.login_seeds) or "none"
        body = _details("Sweep probes", _table(("IP", "TCP", "Identification", "Failure"), rows))
        body += f"\n<p>Extra Seeds from the Sweep: {seeds}.</p>"
    return f'<section id="sweep">\n<h2>Sweep</h2>\n{body}\n</section>\n'


def _credential_sets(results: tuple[CredentialSetResult, ...], scan: SecretScan) -> str:
    """Each Credential Set: username, Platform limit, successes, failures, retired."""
    if not results:
        body = "<p>No Credential Set was used.</p>"
    else:
        rows = tuple(
            (
                str(item.view.number),
                _text(item.view.username, scan),
                _text(_limit(item.view.platform_limit), scan),
                str(item.successes),
                str(item.failures),
                "retired" if item.retired else "not retired",
            )
            for item in results
        )
        body = _table(
            ("Set", "Username", "Platform limit", "Successes", "Failures", "Retired"),
            rows,
        )
    return f'<section id="credential-sets">\n<h2>Credential Sets</h2>\n{body}\n</section>\n'


# -- Small pieces ---------------------------------------------------------------------------


def _ending(facts: RunReportFacts) -> str:
    """`ended: crashed`, or `ended: stopped` with the fixed reason."""
    line = f"ended: {facts.ending.value}"
    if facts.stop_reason:
        return f"{line}: {facts.stop_reason}"
    return line


def _link(kind: str, ident: str, label: str, scan: SecretScan) -> str:
    """A link into `diagram.html`, or just the label when the id is not a plain id."""
    shown = _text(label, scan)
    if _ID.fullmatch(ident):
        return f'<a href="diagram.html#{kind}={ident}">{shown}</a>'
    return shown


def _text(value: object, scan: SecretScan) -> str:
    """Scan `value`, HTML-escape it, and break any `://` so the page holds no URL."""
    redacted, _found = scan.contains_secret(_plain(value))
    escaped = html.escape(redacted, quote=True)
    return _SCHEME.sub(":&#47;&#47;", escaped).replace("\n", "<br>\n")


def _plain(value: object) -> str:
    """One value as text. Unknown keeps its reason; an enum keeps its value."""
    if value is None:
        return _NOT_REPORTED
    if isinstance(value, Unknown):
        return value.reason
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, UnvisitedReason | FindingKind | Platform | HostKeyVerdict):
        return str(value.value)
    return str(value)


def _items(lines: tuple[str, ...], scan: SecretScan) -> str:
    """A list of already-fixed lines, each scanned and escaped."""
    return "".join(f"<li>{_text(line, scan)}</li>" for line in lines)


def _dl(pairs: tuple[tuple[str, str], ...]) -> str:
    """A definition list. The descriptions are already escaped HTML."""
    rows = "".join(f"<dt>{html.escape(term)}</dt><dd>{detail}</dd>" for term, detail in pairs)
    return f"<dl>{rows}</dl>"


def _table(headers: tuple[str, ...], rows: Sequence[tuple[str, ...]]) -> str:
    """A table whose cells are already escaped HTML. Headers are the tool's own words."""
    head = "".join(f"<th>{html.escape(cell)}</th>" for cell in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    if not rows:
        return f"<table><thead><tr>{head}</tr></thead><tbody></tbody></table>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _details(summary: str, body: str) -> str:
    """A closed disclosure around a long table. The summary is the tool's own words."""
    return f"<details><summary>{html.escape(summary)}</summary>\n{body}\n</details>"


def _names(built: Topology) -> dict[str, str]:
    """Display names for diagram ids. A missing name falls back to the id."""
    names = {device.id: _shown_name(device.hostname, device.id) for device in built.devices}
    for device in built.unvisited:
        names[device.id] = _shown_name(device.label, device.id)
    return names


def _shown_name(value: str | Unknown, fallback: str) -> str:
    """A hostname or label, or the id when it is unknown."""
    if isinstance(value, Unknown):
        return fallback
    return value


def _records_by_ip(devices: tuple[DeviceRecord, ...]) -> dict[IPv4Address, DeviceRecord]:
    """The record to read a login from. One that logged in wins over a skipped address."""
    found: dict[IPv4Address, DeviceRecord] = {}
    for record in devices:
        current = found.get(record.ip)
        if current is None or record.credential_set is not None:
            found[record.ip] = record
    return found


def _hostname(record: DeviceRecord) -> str:
    """The hostname `show version` gave, or the address when it was not learned."""
    version = record.version
    if version is None or isinstance(version.hostname, Unknown):
        return str(record.ip)
    return version.hostname


def _privilege(value: LandingPrivilege | Unknown | None) -> str:
    """What the login landed as, with the too-low mark when it applies."""
    if isinstance(value, LandingPrivilege):
        low = ", too low" if value.too_low else ""
        return f"{value.shown}{low}"
    return _plain(value)


def _backup_status(backup: BackupRecord | None) -> str:
    """Locked, the fixed reason it was not written, or not taken."""
    if backup is None:
        return "not taken"
    if backup.path is None:
        return backup.problem if backup.problem is not None else "not taken"
    return "locked"


def _scrypt(level: int | None) -> str:
    """The scrypt work factor as `2^N`, or not written."""
    if level is None:
        return "not written"
    return f"2^{level}"


def _reason(value: UnvisitedReason | Unknown) -> str:
    """An Unvisited reason as the text the summary uses."""
    if isinstance(value, Unknown):
        return value.reason
    return value.value


def _limit(platform: Platform | None) -> str:
    """A Credential Set's Platform limit, or any Platform."""
    if platform is None:
        return "any Platform"
    return f"{platform.value} only"


def _clock(seconds: float) -> str:
    """A duration as `H:MM:SS`."""
    whole = max(0, int(seconds))
    return f"{whole // 3600}:{whole // 60 % 60:02d}:{whole % 60:02d}"


def _utc(moment: datetime) -> str:
    """A UTC time as `YYYY-MM-DD HH:MM:SSZ`."""
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%SZ")
