"""The hardening Checks decided from secret-free config facts (#96, #101).

Each is decided from the secret-free config facts in `records.config_facts` (stories 59-66,
69). A Check raises one Finding per Visited Device per Check, never a secret, hash, key,
community string or quoted config line.

- Presence-is-the-problem Checks fire only on a hit: Telnet, weak secret types, `enable
  password`, SNMPv1/v2c, insecure mode, the HTTP server, legacy services (story 62).
- The `enable secret` Check is absence-is-the-problem: it always runs on IOS/IOS-XE (story 61).
- SNMPv3 privacy runs only where SNMPv3 is configured (story 63).
- NTP, remote syslog and brute-force protection are absence-is-the-problem and always run
  where the Platform has them; NTP authentication is judged only where NTP is configured.
- Routing authentication is judged per protocol and only with a live neighbour; FHRP only on
  configured groups; ICMP only on L3 interfaces that are up (story 63).
- NX-OS strength-check and IOS/IOS-XE brute-force protection follow their Platform; insecure
  mode stays IOS-XE only, while the IOS-XE Checks also run on classic IOS (story 64).
- A fact that was not read makes a Low "could not decide" Finding, never a silent pass
  (story 6).
"""

from typing import Final

from network_analyser.analysis.definition import CheckDefinition
from network_analyser.analysis.ids import finding_id
from network_analyser.records import Platform
from network_analyser.records.analysis import AnalysisInput, ConfigFacts
from network_analyser.records.collected import InterfaceIp
from network_analyser.records.config_facts import (
    ENABLE_PASSWORD,
    ENABLE_SECRET,
    FHRP_GROUPS,
    FHRP_GROUPS_WITHOUT_AUTHENTICATION,
    HTTP_SERVER,
    ICMP_REDIRECTS_L3_INTERFACES,
    ICMP_UNREACHABLES_L3_INTERFACES,
    INSECURE_MODE,
    IP_SOURCE_ROUTE,
    LEGACY_SERVICES,
    LOGIN_BLOCK_FOR,
    NTP_AUTHENTICATED,
    NTP_CONFIGURED,
    NTP_MD5_AUTHENTICATION,
    PASSWORD_STRENGTH_CHECK,
    PROXY_ARP_L3_INTERFACES,
    REMOTE_SYSLOG_SERVERS,
    ROUTING_AUTHENTICATION_MISSING,
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
    AdjacencyKind,
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
NTP_CHECK: Final = Check("hardening-ntp", "NTP missing or weak", CheckType.CONFIGURATION)
REMOTE_SYSLOG_CHECK: Final = Check(
    "hardening-remote-syslog", "No remote syslog", CheckType.CONFIGURATION
)
STRENGTH_CHECK: Final = Check(
    "hardening-strength-check", "Password strength-check off", CheckType.CONFIGURATION
)
BRUTE_FORCE_CHECK: Final = Check(
    "hardening-brute-force", "No brute-force protection", CheckType.CONFIGURATION
)
ROUTING_AUTH_CHECK: Final = Check(
    "hardening-routing-authentication",
    "Routing authentication missing",
    CheckType.CONFIGURATION,
)
FHRP_AUTH_CHECK: Final = Check(
    "hardening-fhrp-authentication",
    "FHRP authentication missing",
    CheckType.CONFIGURATION,
)
ICMP_CHECK: Final = Check(
    "hardening-icmp",
    "ICMP redirects, unreachables or proxy ARP",
    CheckType.CONFIGURATION,
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


# -- NTP ---------------------------------------------------------------------------------------


def ntp(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 61/63: NTP must run; its authentication is judged only where NTP does."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        configured = _flag(facts, NTP_CONFIGURED)
        if isinstance(configured, Unknown):
            findings.append(_undecided(NTP_CHECK, device, NTP_CONFIGURED, configured))
            continue
        if not configured:
            findings.append(
                _finding(
                    NTP_CHECK,
                    device,
                    FindingLevel.MEDIUM,
                    "NTP is not configured.",
                    "Configure at least two trusted NTP servers with authenticated time.",
                )
            )
            continue
        authenticated = _flag(facts, NTP_AUTHENTICATED)
        if isinstance(authenticated, Unknown):
            findings.append(_undecided(NTP_CHECK, device, NTP_AUTHENTICATED, authenticated))
            continue
        if not authenticated:
            findings.append(
                _finding(
                    NTP_CHECK,
                    device,
                    FindingLevel.MEDIUM,
                    "NTP is configured without authentication.",
                    "Configure NTP authentication with a strong hash and trusted keys.",
                )
            )
            continue
        md5 = _flag(facts, NTP_MD5_AUTHENTICATION)
        if isinstance(md5, Unknown):
            findings.append(_undecided(NTP_CHECK, device, NTP_MD5_AUTHENTICATION, md5))
        elif md5:
            findings.append(
                _finding(
                    NTP_CHECK,
                    device,
                    FindingLevel.MEDIUM,
                    "NTP authentication uses MD5.",
                    "Replace MD5 NTP keys with SHA-1 or stronger authentication.",
                )
            )
    return tuple(findings)


# -- Remote syslog -----------------------------------------------------------------------------


def remote_syslog(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 61: absence-is-the-problem; no remote syslog server is a Medium Finding."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        servers = _count(facts, REMOTE_SYSLOG_SERVERS)
        if isinstance(servers, Unknown):
            findings.append(_undecided(REMOTE_SYSLOG_CHECK, device, REMOTE_SYSLOG_SERVERS, servers))
        elif servers == 0:
            findings.append(
                _finding(
                    REMOTE_SYSLOG_CHECK,
                    device,
                    FindingLevel.MEDIUM,
                    "No remote syslog server is configured.",
                    "Send logs to a remote syslog server so they survive a device failure.",
                )
            )
    return tuple(findings)


# -- NX-OS password strength-check -------------------------------------------------------------


def strength_check(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 64: NX-OS only; strength-check is on by default and off with the `no` form."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        if device.platform is not Platform.NX_OS:
            continue
        enabled = _flag(facts, PASSWORD_STRENGTH_CHECK)
        if isinstance(enabled, Unknown):
            findings.append(_undecided(STRENGTH_CHECK, device, PASSWORD_STRENGTH_CHECK, enabled))
        elif not enabled:
            findings.append(
                _finding(
                    STRENGTH_CHECK,
                    device,
                    FindingLevel.MEDIUM,
                    "Password strength-check is off.",
                    "Re-enable password strength-check (no password strength-check is set).",
                )
            )
    return tuple(findings)


# -- Brute-force protection --------------------------------------------------------------------


def brute_force(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 61/64: absence-is-the-problem on IOS-XE and classic IOS alike."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        if device.platform is not Platform.IOS_XE:
            continue
        protected = _flag(facts, LOGIN_BLOCK_FOR)
        if isinstance(protected, Unknown):
            findings.append(_undecided(BRUTE_FORCE_CHECK, device, LOGIN_BLOCK_FOR, protected))
        elif not protected:
            findings.append(
                _finding(
                    BRUTE_FORCE_CHECK,
                    device,
                    FindingLevel.MEDIUM,
                    "Brute-force protection is not configured.",
                    "Configure login block-for with attempts and within.",
                )
            )
    return tuple(findings)


# -- Routing authentication --------------------------------------------------------------------


def routing_authentication(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 63: per protocol, and only where this device has a live neighbour of it."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        live = _live_routing_protocols(data, device.id)
        if not live:
            continue
        missing = facts.fact(ROUTING_AUTHENTICATION_MISSING)
        if isinstance(missing, Unknown):
            findings.append(
                _undecided(ROUTING_AUTH_CHECK, device, ROUTING_AUTHENTICATION_MISSING, missing)
            )
            continue
        if not isinstance(missing, tuple):
            findings.append(
                _undecided(
                    ROUTING_AUTH_CHECK,
                    device,
                    ROUTING_AUTHENTICATION_MISSING,
                    Unknown("not a list of protocols"),
                )
            )
            continue
        offending = sorted(live.intersection(item.upper() for item in missing))
        if offending:
            findings.append(
                _finding(
                    ROUTING_AUTH_CHECK,
                    device,
                    FindingLevel.MEDIUM,
                    "Routing authentication is missing for "
                    + ", ".join(offending)
                    + " with a live neighbour.",
                    "Configure authentication for each routing protocol that has a neighbour.",
                )
            )
    return tuple(findings)


def _live_routing_protocols(data: AnalysisInput, device: str) -> set[str]:
    """The routing protocols with a live neighbour touching `device`."""
    kinds = {
        AdjacencyKind.OSPF: "OSPF",
        AdjacencyKind.EIGRP: "EIGRP",
        AdjacencyKind.BGP: "BGP",
    }
    return {
        kinds[adjacency.kind]
        for adjacency in data.topology.adjacencies
        if adjacency.kind in kinds and any(end.device == device for end in adjacency.ends)
    }


# -- FHRP authentication -----------------------------------------------------------------------


def fhrp_authentication(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 63: only configured HSRP, VRRP or GLBP groups are judged."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        groups = _count(facts, FHRP_GROUPS)
        if isinstance(groups, Unknown):
            findings.append(_undecided(FHRP_AUTH_CHECK, device, FHRP_GROUPS, groups))
            continue
        if groups == 0:
            continue
        without = _count(facts, FHRP_GROUPS_WITHOUT_AUTHENTICATION)
        if isinstance(without, Unknown):
            findings.append(
                _undecided(FHRP_AUTH_CHECK, device, FHRP_GROUPS_WITHOUT_AUTHENTICATION, without)
            )
        elif without:
            findings.append(
                _finding(
                    FHRP_AUTH_CHECK,
                    device,
                    FindingLevel.MEDIUM,
                    f"FHRP authentication is missing on {without} of {groups} configured groups.",
                    "Configure authentication on every HSRP, VRRP and GLBP group.",
                )
            )
    return tuple(findings)


# -- ICMP redirects, unreachables and proxy ARP ------------------------------------------------


def icmp(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 63: judged only where an L3 interface is up; Low when any setting is enabled."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        up = _has_up_l3_interface(device)
        if isinstance(up, Unknown):
            findings.append(_undecided(ICMP_CHECK, device, "L3 interface state", up))
            continue
        if not up:
            continue
        counts = {
            name: _count(facts, name)
            for name in (
                ICMP_REDIRECTS_L3_INTERFACES,
                ICMP_UNREACHABLES_L3_INTERFACES,
                PROXY_ARP_L3_INTERFACES,
            )
        }
        unknown = next((value for value in counts.values() if isinstance(value, Unknown)), None)
        if isinstance(unknown, Unknown):
            findings.append(_undecided(ICMP_CHECK, device, ICMP_REDIRECTS_L3_INTERFACES, unknown))
            continue
        items = [
            (label, _total(counts, name))
            for name, label in (
                (ICMP_REDIRECTS_L3_INTERFACES, "ICMP redirects"),
                (ICMP_UNREACHABLES_L3_INTERFACES, "ICMP unreachables"),
                (PROXY_ARP_L3_INTERFACES, "proxy ARP"),
            )
            if _total(counts, name)
        ]
        if not items:
            continue
        listed = ", ".join(
            f"{label} on {count} L3 " + ("interface" if count == 1 else "interfaces")
            for label, count in items
        )
        findings.append(
            _finding(
                ICMP_CHECK,
                device,
                FindingLevel.LOW,
                f"Insecure ICMP settings are enabled: {listed}.",
                "Disable ICMP redirects, unreachables and proxy ARP on L3 interfaces.",
            )
        )
    return tuple(findings)


def _has_up_l3_interface(device: VisitedDevice) -> bool | Unknown:
    """Whether the device has an L3 interface that is up; `Unknown` when its state was not read."""
    interfaces = device.interfaces
    if isinstance(interfaces, Unknown):
        return interfaces
    unread = False
    for interface in interfaces:
        if interface.admin_up is not True or interface.line_up is not True:
            continue
        settings = interface.ip
        if isinstance(settings, InterfaceIp) and settings.addresses:
            return True
        if isinstance(settings, Unknown):
            unread = True
    return Unknown("an interface that is up has unread addressing") if unread else False


HARDENING_CHECKS: Final[tuple[CheckDefinition, ...]] = (
    CheckDefinition(TELNET_CHECK, telnet),
    CheckDefinition(WEAK_SECRET_CHECK, weak_secret_types),
    CheckDefinition(ENABLE_SECRET_CHECK, enable_secret),
    CheckDefinition(SNMP_V1_V2C_CHECK, snmp_v1_v2c),
    CheckDefinition(SNMP_V3_PRIV_CHECK, snmp_v3_priv),
    CheckDefinition(INSECURE_MODE_CHECK, insecure_mode),
    CheckDefinition(HTTP_SERVER_CHECK, http_server),
    CheckDefinition(LEGACY_SERVICES_CHECK, legacy_services),
    CheckDefinition(NTP_CHECK, ntp),
    CheckDefinition(REMOTE_SYSLOG_CHECK, remote_syslog),
    CheckDefinition(STRENGTH_CHECK, strength_check),
    CheckDefinition(BRUTE_FORCE_CHECK, brute_force),
    CheckDefinition(ROUTING_AUTH_CHECK, routing_authentication),
    CheckDefinition(FHRP_AUTH_CHECK, fhrp_authentication),
    CheckDefinition(ICMP_CHECK, icmp),
)
"""These fifteen Checks, ready to join `checks.CHECKS`."""
