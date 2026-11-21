"""Cisco's own insecure-configuration list, mapped to our Checks (#102, story 67).

`show system insecure configuration` (IOS-XE 17.18.2+) names the configured commands Cisco
considers insecure. Each entry is matched against a built-in table:

- a match marks the Finding our own Check raised for the same device with
  `also_flagged_by_cisco`, so one problem is one row;
- no match raises a Finding in Cisco's own words, at Cisco's own level, under the dedicated
  `config-cisco-insecure-list` Check id.

The table names Check ids, not device text. A mapped Check a later ticket ships (for example
`config-telnet` from #96) starts matching as soon as it raises a Finding; until then Cisco's
entry is reported in Cisco's words, which is never worse than dropping it.

The command string is Cisco's own entry, with placeholders such as `<STRING>`: the parser
never keeps the echoed configured value (#97), so no community string reaches a Finding. A
reply that was refused is a Device Role skip; one that cannot be read is a Low "could not
decide" Finding (story 6). Below 17.18.2, or on NX-OS, the Check is not run at all: the
command is absent, not "Cisco found nothing" (story 68).
"""

from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Final

from network_analyser.analysis.catalogue import CISCO_LIST_CHECK
from network_analyser.analysis.ids import finding_id
from network_analyser.analysis.outcome import could_not_decide, missing_reason
from network_analyser.records.analysis import AnalysisInput
from network_analyser.records.collected import InsecureConfigurationItem, Reading
from network_analyser.records.platform import Platform
from network_analyser.records.topology import CheckSkip, Finding, FindingLevel, VisitedDevice
from network_analyser.records.unknown import Unknown

__all__ = [
    "CHECK_IDS_BY_DATA",
    "CISCO_SOURCE",
    "RULES",
    "apply",
    "cisco_list",
    "cisco_skipped",
    "level_for",
]

CISCO_SOURCE: Final = "Cisco insecure configuration"
"""Where a Finding built from Cisco's own list comes from."""

_BELOW_GATE: Final = "IOS-XE 17.18.2 or later is required for show system insecure configuration"
_NO_COMMAND: Final = "this Platform has no Cisco insecure-configuration list"
_PLATFORM_UNKNOWN: Final = "the Platform was not identified"
_NOT_UNDERSTOOD: Final = "Cisco's insecure-configuration list was not understood"
_REMEDIATION: Final = "Remove the command Cisco names, or apply Cisco's remediation for it."

_SEVERITY_LEVELS: Final[Mapping[str, FindingLevel]] = MappingProxyType(
    {
        "CRITICAL": FindingLevel.CRITICAL,
        "HIGH": FindingLevel.HIGH,
        "MEDIUM": FindingLevel.MEDIUM,
        "LOW": FindingLevel.LOW,
    }
)


@dataclass(frozen=True, slots=True)
class Rule:
    """One row of the built-in Cisco-list mapping.

    Attributes:
        modules: the Cisco module names this rule covers, lower-cased.
        words: any of these must appear in Cisco's CLI command; empty means any command.
        check_id: the Check our own Finding carries.
    """

    modules: frozenset[str]
    words: tuple[str, ...]
    check_id: str


RULES: Final[tuple[Rule, ...]] = (
    Rule(frozenset({"snmp"}), ("user",), "config-snmpv3-user-crypto"),
    Rule(frozenset({"snmp"}), ("community", "host"), "config-snmp-communities"),
    Rule(frozenset({"snmp"}), (), "config-snmp-communities"),
    Rule(frozenset({"ntp"}), (), "config-ntp"),
    Rule(frozenset({"copp", "control plane", "control-plane"}), (), "config-copp-applied"),
    Rule(frozenset({"ssh"}), ("key", "modulus", "bits"), "config-ssh-key-size"),
    Rule(frozenset({"ssh"}), (), "config-ssh-version"),
    Rule(frozenset({"telnet"}), (), "config-telnet"),
    Rule(frozenset({"line", "vty"}), ("telnet",), "config-telnet"),
    Rule(frozenset({"line", "vty"}), ("access-class",), "config-vty-access-class"),
    Rule(frozenset({"line", "vty"}), ("exec-timeout",), "config-exec-timeout"),
    Rule(frozenset({"http", "https"}), (), "config-http-server"),
    Rule(frozenset({"ftp", "tftp"}), (), "config-legacy-services"),
    Rule(frozenset({"bootp", "finger", "cdp", "service", "ip"}), (), "config-legacy-services"),
    Rule(frozenset({"aaa", "tacacs", "radius"}), (), "config-aaa"),
    Rule(frozenset({"syslog", "logging"}), (), "config-syslog"),
    Rule(frozenset({"icmp"}), (), "config-icmp"),
    Rule(frozenset({"password", "secret", "enable"}), (), "config-secret-types"),
    Rule(frozenset({"guestshell", "guest shell"}), (), "config-guest-shell"),
)
"""Cisco's module and command, mapped to the Check we ship. Specific rules come first."""

CHECK_IDS_BY_DATA: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {"insecure_configuration": ("config-cisco-insecure-list",)}
)
"""The `Collected` part Cisco's list fills; a Device Role can stop this Check by refusing it."""


def cisco_list(_data: AnalysisInput) -> tuple[Finding, ...]:
    """Return nothing: `apply` raises this Check's Findings, because it sees the others.

    A mapping needs every other Check's Findings to mark a match (story 67), so the registry
    keeps this Check's identity and `analyse` runs `apply` after every other Check.
    """
    return ()


def apply(data: AnalysisInput, findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Mark our Findings Cisco also flags, and return them with the unmatched Cisco items."""
    marked = list(findings)
    extra: list[Finding] = []
    for device in data.topology.devices:
        part = data.collected_for(device.management_ip).insecure_configuration
        if isinstance(part, Unknown):
            if missing_reason(part) is None:
                extra.append(could_not_decide(CISCO_LIST_CHECK, device.id, part.reason))
            continue
        if not isinstance(part, Reading):
            continue
        seen: set[tuple[str, str]] = set()
        for item in part.value:
            key = (
                item.module if isinstance(item.module, str) else "",
                item.command if isinstance(item.command, str) else "",
            )
            if key in seen:
                continue
            seen.add(key)
            if _mark(marked, device, item):
                continue
            extra.append(_finding(device, item))
    return (*marked, *extra)


def cisco_skipped(data: AnalysisInput) -> tuple[CheckSkip, ...]:
    """Return the devices Cisco's list did not run for, and why (story 68).

    Below 17.18.2 and on NX-OS the command is absent, so the Check is not run there: that is
    a skip, never "Cisco found nothing".
    """
    skips: list[CheckSkip] = []
    for device in data.topology.devices:
        if device.platform is Platform.NX_OS:
            skips.append(CheckSkip(device.id, _NO_COMMAND))
            continue
        if device.platform is not Platform.IOS_XE:
            skips.append(CheckSkip(device.id, _PLATFORM_UNKNOWN))
            continue
        part = data.collected_for(device.management_ip).insecure_configuration
        if part is None:
            skips.append(CheckSkip(device.id, _BELOW_GATE))
            continue
        reason = missing_reason(part)
        if reason is not None:
            skips.append(CheckSkip(device.id, reason))
    return tuple(skips)


def level_for(severity: object) -> FindingLevel:
    """Return Cisco's severity as one of our four levels; Low when it cannot be read."""
    if isinstance(severity, str):
        return _SEVERITY_LEVELS.get(severity.strip().upper(), FindingLevel.LOW)
    return FindingLevel.LOW


def _severity_read(severity: object) -> bool:
    """Say whether Cisco's severity was one of the four levels we know."""
    return isinstance(severity, str) and severity.strip().upper() in _SEVERITY_LEVELS


def _mark(findings: list[Finding], device: VisitedDevice, item: InsecureConfigurationItem) -> bool:
    """Mark every Finding the item's mapped Check raised for `device`; True when it matched."""
    check_id = _check_id(item)
    if check_id is None:
        return False
    matched = False
    for index, finding in enumerate(findings):
        if finding.check.id == check_id and device.id in finding.devices:
            findings[index] = replace(finding, also_flagged_by_cisco=True)
            matched = True
    return matched


def _check_id(item: InsecureConfigurationItem) -> str | None:
    """The Check id our built-in table gives this entry, or None when nothing matches."""
    if not isinstance(item.module, str):
        return None
    module = " ".join(item.module.casefold().split())
    command = item.command.casefold() if isinstance(item.command, str) else ""
    for rule in RULES:
        if module not in rule.modules:
            continue
        if rule.words and not any(word in command for word in rule.words):
            continue
        return rule.check_id
    return None


def _finding(device: VisitedDevice, item: InsecureConfigurationItem) -> Finding:
    """One Finding in Cisco's own words, at Cisco's own level (story 67)."""
    module = item.module if isinstance(item.module, str) else "an unnamed module"
    command = item.command if isinstance(item.command, str) else "a command Cisco did not name"
    reason = item.reason if isinstance(item.reason, str) else "Cisco gave no reason"
    what = f"Cisco flags {module}: {command}. Reason: {reason}."
    level = level_for(item.severity)
    if not _severity_read(item.severity):
        what = f"{what} Cisco's severity was not read, so this is Low."
    return Finding(
        id=finding_id(CISCO_LIST_CHECK.id, f"{device.id}\x1f{module}\x1f{command}"),
        devices=(device.id,),
        items=(),
        evidence=(),
        level=level,
        check=CISCO_LIST_CHECK,
        what_was_found=what,
        what_to_do=_REMEDIATION,
        source=CISCO_SOURCE,
        summary=what,
    )
