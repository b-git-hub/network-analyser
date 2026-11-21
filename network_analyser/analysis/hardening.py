"""The first hardening Checks: Telnet, secrets, SNMP, insecure mode, HTTP, legacy services (#96).

Each is decided from the secret-free config facts in `records.config_facts` (stories 59-66,
69). A Check raises one Finding per Visited Device per Check, never a secret, hash, key,
community string or quoted config line.

- Presence-is-the-problem Checks fire only on a hit: Telnet, weak secret types, `enable
  password`, SNMPv1/v2c, insecure mode, the HTTP server, legacy services (story 62).
- The `enable secret` Check is absence-is-the-problem: it always runs on IOS/IOS-XE (story 61).
- SNMPv3 privacy runs only where SNMPv3 is configured (story 63).
- A fact that was not read makes a Low "could not decide" Finding, never a silent pass
  (story 6).
- IOS-XE Checks also run on classic IOS with its own rules; insecure mode stays IOS-XE only
  (story 64).
"""

from typing import Final

from network_analyser.analysis.definition import CheckDefinition
from network_analyser.analysis.ids import finding_id
from network_analyser.records import Platform
from network_analyser.records.analysis import AnalysisInput, ConfigFacts
from network_analyser.records.config_facts import (
    ENABLE_PASSWORD,
    ENABLE_SECRET,
    HTTP_SERVER,
    INSECURE_MODE,
    IP_SOURCE_ROUTE,
    LEGACY_SERVICES,
    SECRET_TYPE_0,
    SECRET_TYPE_4,
    SECRET_TYPE_5,
    SECRET_TYPE_7,
    SNMP_GLOBAL_ENFORCE_PRIV,
    SNMP_V1_V2C_COMMUNITIES,
    SNMP_V1_V2C_READ_WRITE_COMMUNITIES,
    SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME,
    SNMP_V1_V2C_READ_WRITE_NO_ACL,
    SNMP_V3_CONFIGURED,
    SNMP_V3_GROUPS_WITHOUT_PRIV,
    SNMP_V3_USERS,
    SNMP_V3_USERS_WITHOUT_PRIV,
    TELNET_LINES,
)
from network_analyser.records.topology import (
    Check,
    CheckType,
    Finding,
    FindingLevel,
    VisitedDevice,
)
from network_analyser.records.unknown import Unknown

TELNET_CHECK: Final = Check("hardening-telnet", "Telnet enabled", CheckType.CONFIGURATION)
WEAK_SECRET_CHECK: Final = Check(
    "hardening-weak-secret-types", "Weak secret types", CheckType.CONFIGURATION
)
ENABLE_SECRET_CHECK: Final = Check(
    "hardening-enable-secret", "Enable password or no enable secret", CheckType.CONFIGURATION
)
SNMP_V1_V2C_CHECK: Final = Check(
    "hardening-snmp-v1-v2c", "SNMPv1/v2c in use", CheckType.CONFIGURATION
)
SNMP_V3_PRIV_CHECK: Final = Check(
    "hardening-snmp-v3-priv", "SNMPv3 without privacy", CheckType.CONFIGURATION
)
INSECURE_MODE_CHECK: Final = Check(
    "hardening-insecure-mode", "Insecure mode", CheckType.CONFIGURATION
)
HTTP_SERVER_CHECK: Final = Check(
    "hardening-http-server", "Plain HTTP server", CheckType.CONFIGURATION
)
LEGACY_SERVICES_CHECK: Final = Check(
    "hardening-legacy-services", "Legacy services", CheckType.CONFIGURATION
)

_UNDECIDED_TODO: Final = "Re-run the tool so the running config can be read."
_REPLACE_WEAK_TYPES: Final = "Replace each weak secret with a type 8 or 9 secret."


def _finding(
    check: Check, device: VisitedDevice, level: FindingLevel, what: str, todo: str
) -> Finding:
    """One config Finding for `device`, with its stable id and no config text or secret."""
    return Finding(
        id=finding_id(check.id, device.id),
        devices=(device.id,),
        items=(),
        evidence=(),
        level=level,
        check=check,
        what_was_found=what,
        what_to_do=todo,
        source="config",
        summary=what,
    )


def _undecided(check: Check, device: VisitedDevice, name: str, value: Unknown) -> Finding:
    """A Low Finding saying the config could not decide a Check (story 6)."""
    what = f"Could not decide: {name} was not read ({value.reason})."
    return _finding(check, device, FindingLevel.LOW, what, _UNDECIDED_TODO)


def _count(facts: ConfigFacts, name: str) -> int | Unknown:
    """A count fact, or `Unknown` when it is not a count (including not read)."""
    value = facts.fact(name)
    if isinstance(value, Unknown):
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        return Unknown(f"{name} is not a count")
    return value


def _flag(facts: ConfigFacts, name: str) -> bool | Unknown:
    """A boolean fact, or `Unknown` when it is not a boolean (including not read)."""
    value = facts.fact(name)
    if isinstance(value, Unknown):
        return value
    if not isinstance(value, bool):
        return Unknown(f"{name} is not a boolean")
    return value


def _is_classic_ios(device: VisitedDevice) -> bool:
    """True for classic IOS, whose release has parentheses; IOS-XE releases do not (story 64)."""
    return (
        device.platform is Platform.IOS_XE
        and isinstance(device.software_version, str)
        and "(" in device.software_version
    )


def _family_known(device: VisitedDevice) -> bool:
    """Whether the family is known well enough to apply a classic IOS / IOS-XE difference."""
    return device.platform is Platform.NX_OS or isinstance(device.software_version, str)


def _checked_devices(data: AnalysisInput) -> tuple[tuple[VisitedDevice, ConfigFacts], ...]:
    """Every Visited Device with its config facts, in device id order."""
    return tuple((device, data.facts_for(device.id)) for device in data.topology.devices)


# -- Telnet ------------------------------------------------------------------------------------


def telnet(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 62: fire where a vty block permits Telnet."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        value = facts.fact(TELNET_LINES)
        if isinstance(value, Unknown):
            findings.append(_undecided(TELNET_CHECK, device, TELNET_LINES, value))
            continue
        if not isinstance(value, tuple):
            findings.append(
                _undecided(TELNET_CHECK, device, TELNET_LINES, Unknown("not a list of blocks"))
            )
            continue
        if not value:
            continue
        blocks = ", ".join(value)
        noun = "block" if len(value) == 1 else "blocks"
        what = f"Telnet is enabled on {len(value)} vty line {noun}: {blocks}."
        findings.append(
            _finding(
                TELNET_CHECK,
                device,
                FindingLevel.HIGH,
                what,
                "Restrict each vty line's transport input to ssh.",
            )
        )
    return tuple(findings)


# -- Weak secret types -------------------------------------------------------------------------


def weak_secret_types(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 62: fire on secret types 0, 4 and 7, plus type 5 on classic IOS only (story 64)."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        by_type: dict[int, int] = {}
        undecided: Unknown | None = None
        for number, name in (
            (0, SECRET_TYPE_0),
            (4, SECRET_TYPE_4),
            (5, SECRET_TYPE_5),
            (7, SECRET_TYPE_7),
        ):
            value = _count(facts, name)
            if isinstance(value, Unknown):
                undecided = value
            elif value:
                by_type[number] = value
        type_five = by_type.pop(5, 0)
        if type_five and _is_classic_ios(device):
            by_type[5] = type_five
        elif type_five and not _family_known(device):
            undecided = Unknown("the release was not read, so type 5's strength is unknown")
        if by_type:
            listed = ", ".join(
                f"type {number} x{count}" for number, count in sorted(by_type.items())
            )
            findings.append(
                _finding(
                    WEAK_SECRET_CHECK,
                    device,
                    FindingLevel.HIGH,
                    f"Reversible or weak secret types are in use: {listed}.",
                    _REPLACE_WEAK_TYPES,
                )
            )
        elif undecided is not None:
            findings.append(_undecided(WEAK_SECRET_CHECK, device, "a secret type count", undecided))
    return tuple(findings)


# -- Enable password or no enable secret -------------------------------------------------------


def enable_secret(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 61: absence-is-the-problem, on IOS/IOS-XE only; an enable password is a hit too."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        if device.platform is not Platform.IOS_XE:
            continue
        secret = _flag(facts, ENABLE_SECRET)
        password = _flag(facts, ENABLE_PASSWORD)
        if isinstance(secret, Unknown) or isinstance(password, Unknown):
            unknown = secret if isinstance(secret, Unknown) else password
            assert isinstance(unknown, Unknown)  # noqa: S101 (one of the two is Unknown)
            findings.append(_undecided(ENABLE_SECRET_CHECK, device, "enable secret", unknown))
            continue
        if password and not secret:
            what = "Enable password is set and no enable secret is set."
        elif password:
            what = "Enable password is set."
        elif not secret:
            what = "No enable secret is set."
        else:
            continue
        findings.append(
            _finding(
                ENABLE_SECRET_CHECK,
                device,
                FindingLevel.HIGH,
                what,
                "Remove the enable password and configure an enable secret of type 8 or 9.",
            )
        )
    return tuple(findings)


# -- SNMPv1/v2c --------------------------------------------------------------------------------


def snmp_v1_v2c(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 62: fire on any community; Critical for a default-named or acl-less read-write one."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        counts = {
            name: _count(facts, name)
            for name in (
                SNMP_V1_V2C_COMMUNITIES,
                SNMP_V1_V2C_READ_WRITE_COMMUNITIES,
                SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME,
                SNMP_V1_V2C_READ_WRITE_NO_ACL,
            )
        }
        unknown = next((value for value in counts.values() if isinstance(value, Unknown)), None)
        if isinstance(unknown, Unknown):
            findings.append(_undecided(SNMP_V1_V2C_CHECK, device, SNMP_V1_V2C_COMMUNITIES, unknown))
            continue
        total = _total(counts, SNMP_V1_V2C_COMMUNITIES)
        if total == 0:
            continue
        read_write = _total(counts, SNMP_V1_V2C_READ_WRITE_COMMUNITIES)
        default_name = _total(counts, SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME)
        no_acl = _total(counts, SNMP_V1_V2C_READ_WRITE_NO_ACL)
        critical = read_write > 0 and (default_name > 0 or no_acl > 0)
        noun = "community" if total == 1 else "communities"
        what = (
            f"SNMPv1/v2c is in use: {total} {noun} ({read_write} read-write, "
            f"{default_name} with a default name, {no_acl} read-write without an ACL)."
        )
        findings.append(
            _finding(
                SNMP_V1_V2C_CHECK,
                device,
                FindingLevel.CRITICAL if critical else FindingLevel.HIGH,
                what,
                "Remove the SNMPv1/v2c communities and use SNMPv3 with authentication and privacy.",
            )
        )
    return tuple(findings)


def _total(counts: dict[str, int | Unknown], name: str) -> int:
    value = counts[name]
    assert isinstance(value, int)  # noqa: S101 (the caller checked every count for Unknown)
    return value


# -- SNMPv3 without privacy --------------------------------------------------------------------


def snmp_v3_priv(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 63: run only where SNMPv3 is configured; fire on a user or group below priv."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        configured = _flag(facts, SNMP_V3_CONFIGURED)
        if isinstance(configured, Unknown):
            findings.append(_undecided(SNMP_V3_PRIV_CHECK, device, SNMP_V3_CONFIGURED, configured))
            continue
        if not configured:
            continue
        users = _count(facts, SNMP_V3_USERS)
        without = _count(facts, SNMP_V3_USERS_WITHOUT_PRIV)
        groups = _count(facts, SNMP_V3_GROUPS_WITHOUT_PRIV)
        unknown = next(
            (value for value in (users, without, groups) if isinstance(value, Unknown)),
            None,
        )
        if isinstance(unknown, Unknown):
            findings.append(
                _undecided(SNMP_V3_PRIV_CHECK, device, SNMP_V3_USERS_WITHOUT_PRIV, unknown)
            )
            continue
        assert isinstance(users, int)  # noqa: S101 (checked above)
        assert isinstance(without, int)  # noqa: S101
        assert isinstance(groups, int)  # noqa: S101
        if device.platform is Platform.NX_OS:
            enforced = _flag(facts, SNMP_GLOBAL_ENFORCE_PRIV)
            if isinstance(enforced, Unknown):
                findings.append(
                    _undecided(SNMP_V3_PRIV_CHECK, device, SNMP_GLOBAL_ENFORCE_PRIV, enforced)
                )
                continue
            if enforced:
                continue
            what = (
                "SNMPv3 has no global privacy enforcement: "
                f"{without} of {users} users and {groups} groups use no priv."
            )
        else:
            if without == 0 and groups == 0:
                continue
            what = (
                "SNMPv3 is configured without privacy: "
                f"{without} of {users} users and {groups} groups use no priv."
            )
        findings.append(
            _finding(
                SNMP_V3_PRIV_CHECK,
                device,
                FindingLevel.HIGH,
                what,
                "Configure SNMPv3 with authentication and privacy, and enforce privacy.",
            )
        )
    return tuple(findings)


# -- Insecure mode -----------------------------------------------------------------------------


def insecure_mode(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 64: IOS-XE only, and not on classic IOS; `system mode insecure` is a hit."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        if device.platform is not Platform.IOS_XE or _is_classic_ios(device):
            continue
        value = _flag(facts, INSECURE_MODE)
        if isinstance(value, Unknown):
            findings.append(_undecided(INSECURE_MODE_CHECK, device, INSECURE_MODE, value))
            continue
        if value:
            findings.append(
                _finding(
                    INSECURE_MODE_CHECK,
                    device,
                    FindingLevel.HIGH,
                    "Insecure mode is set (system mode insecure).",
                    "Remove system mode insecure and follow Cisco's hardening guide.",
                )
            )
        elif not _family_known(device):
            findings.append(
                _undecided(
                    INSECURE_MODE_CHECK,
                    device,
                    INSECURE_MODE,
                    Unknown("the release was not read, so the IOS-XE rule cannot be applied"),
                )
            )
    return tuple(findings)


# -- Plain HTTP server -------------------------------------------------------------------------


def http_server(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 62: fire when the plain HTTP server is enabled."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        value = _flag(facts, HTTP_SERVER)
        if isinstance(value, Unknown):
            findings.append(_undecided(HTTP_SERVER_CHECK, device, HTTP_SERVER, value))
        elif value:
            findings.append(
                _finding(
                    HTTP_SERVER_CHECK,
                    device,
                    FindingLevel.HIGH,
                    "The plain HTTP server is enabled (ip http server).",
                    "Disable the plain HTTP server and use HTTPS.",
                )
            )
    return tuple(findings)


# -- Legacy services ---------------------------------------------------------------------------


def legacy_services(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 62: fire on source routing and each legacy service the config turns on."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        services = facts.fact(LEGACY_SERVICES)
        source = _flag(facts, IP_SOURCE_ROUTE)
        items: list[str] = []
        if isinstance(source, bool) and source:
            items.append("ip source-route")
        if isinstance(services, tuple):
            items.extend(item for item in services if item not in items)
        if items:
            listed = ", ".join(items)
            findings.append(
                _finding(
                    LEGACY_SERVICES_CHECK,
                    device,
                    FindingLevel.HIGH,
                    f"Legacy services are enabled ({len(items)}): {listed}.",
                    "Disable every legacy service the device does not need.",
                )
            )
        elif isinstance(services, Unknown):
            findings.append(_undecided(LEGACY_SERVICES_CHECK, device, LEGACY_SERVICES, services))
        elif isinstance(source, Unknown):
            findings.append(_undecided(LEGACY_SERVICES_CHECK, device, IP_SOURCE_ROUTE, source))
    return tuple(findings)


HARDENING_CHECKS: Final[tuple[CheckDefinition, ...]] = (
    CheckDefinition(TELNET_CHECK, telnet),
    CheckDefinition(WEAK_SECRET_CHECK, weak_secret_types),
    CheckDefinition(ENABLE_SECRET_CHECK, enable_secret),
    CheckDefinition(SNMP_V1_V2C_CHECK, snmp_v1_v2c),
    CheckDefinition(SNMP_V3_PRIV_CHECK, snmp_v3_priv),
    CheckDefinition(INSECURE_MODE_CHECK, insecure_mode),
    CheckDefinition(HTTP_SERVER_CHECK, http_server),
    CheckDefinition(LEGACY_SERVICES_CHECK, legacy_services),
)
"""These eight Checks, ready to join `checks.CHECKS`."""
