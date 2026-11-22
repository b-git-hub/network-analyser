"""The hardening Checks: config facts and the 0.2.0 show output (#96, #100, #101, #102).

The batch-#96 Checks are decided from the secret-free config facts in
`records.config_facts` (stories 59-66, 69):

- Presence-is-the-problem Checks fire only on a hit: Telnet, weak secret types, `enable
  password`, SNMPv1/v2c, insecure mode, the HTTP server, legacy services (story 62).
- The `enable secret`, SSHv2, VTY access-class, AAA, exec-timeout and type 6 Checks are
  absence-is-the-problem: they always run on IOS/IOS-XE (story 61).
- SNMPv3 privacy runs only where SNMPv3 is configured (story 63).
- NTP, remote syslog and brute-force protection are absence-is-the-problem and always run
  where the Platform has them; NTP authentication is judged only where NTP is configured.
- Routing authentication is judged per protocol and only with a live neighbour; FHRP only on
  configured groups; ICMP only on L3 interfaces that are up (story 63).
- NX-OS strength-check and IOS/IOS-XE brute-force protection follow their Platform; insecure
  mode stays IOS-XE only, while the IOS-XE Checks also run on classic IOS with its own rules
  and defaults, such as SSH 1.99 (story 64).
- A fact that was not read makes a Low "could not decide" Finding, never a silent pass
  (story 6). So does a hidden default the config cannot settle, such as SSHv1 on IOS-XE
  17.10+ (story 64).

The #102 Checks each need the 0.2.0 show output (story 60), decided from one part of the
Visited Device's `Collected` record, or, for NX-OS SNMPv3 users, from a secret-free config
fact: NX-OS prints no such command and the users are in the running config. Feature gating
follows story 63: SNMPv3 crypto runs only where SNMPv3 is configured, and NTP sync only where
NTP is. The "absence is the problem" Checks always run (story 61). A part the device refused
(a Device Role that predates the command) or the Run never handed over is a skip for that
device, never a pass. A part that was read but does not decide the question raises story 6's
Low "could not decide" Finding. Findings name protocols, counts and sizes only: never a user
name, key, hash or community string (story 66).

Every Check here raises one Finding per Visited Device per Check, and never a secret, hash,
key, community string or quoted config line.
"""

import re
from collections import Counter
from collections.abc import Callable, Iterable
from typing import Final

from network_analyser.analysis import cisco_list, role
from network_analyser.analysis.catalogue import (
    CISCO_LIST_CHECK,
    COPP_CHECK,
    GUEST_SHELL_CHECK,
    ROLE_CHECK,
    SNMP_CHECK,
    SSH_CHECK,
)
from network_analyser.analysis.catalogue import (
    NTP_CHECK as NTP_SYNC_CHECK,
)
from network_analyser.analysis.definition import CheckDefinition
from network_analyser.analysis.ids import finding_id
from network_analyser.analysis.outcome import could_not_decide, missing_reason
from network_analyser.records import Platform
from network_analyser.records.analysis import (
    SNMP_V3_USER_CRYPTO,
    AnalysisInput,
    ConfigFacts,
)
from network_analyser.records.collected import (
    Collected,
    ControlPlanePolicy,
    InterfaceIp,
    NtpAssociation,
    Reading,
    SnmpUser,
    SshSettings,
)
from network_analyser.records.config_facts import (
    AAA_ACCOUNTING,
    AAA_AUTHORIZATION,
    AAA_CENTRAL_LOGIN,
    AAA_LOGIN_FALLBACK_NONE,
    AAA_NEW_MODEL,
    ENABLE_PASSWORD,
    ENABLE_SECRET,
    EXEC_TIMEOUT_DISABLED_LINES,
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
    SSH_VERSION,
    TELNET_LINES,
    TYPE_6_ENABLED,
    VTY_ACCESS_CLASS_MISSING_LINES,
)
from network_analyser.records.topology import (
    AdjacencyKind,
    Check,
    CheckSkip,
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

SSH_V2_CHECK: Final = Check("hardening-ssh-v2", "SSHv2 not enforced", CheckType.CONFIGURATION)
VTY_ACCESS_CLASS_CHECK: Final = Check(
    "hardening-vty-access-class", "No VTY access-class", CheckType.CONFIGURATION
)
AAA_FALLBACK_CHECK: Final = Check(
    "hardening-aaa-fallback", "AAA fallback to none", CheckType.CONFIGURATION
)
AAA_CENTRAL_CHECK: Final = Check(
    "hardening-aaa-central",
    "No central AAA, authorisation or accounting",
    CheckType.CONFIGURATION,
)
EXEC_TIMEOUT_CHECK: Final = Check("hardening-exec-timeout", "Exec timeout", CheckType.CONFIGURATION)
TYPE_6_CHECK: Final = Check("hardening-type-6", "Type 6 not enabled", CheckType.CONFIGURATION)

SSH_V1_REMOVED: Final = (17, 10)
"""The IOS-XE release from which SSHv1 is refused even without `ip ssh version 2` (#76, X2)."""

_SSH_V2_NUMBER: Final = 2
"""The `ip ssh version` value that refuses SSHv1."""

_UNDECIDED_TODO: Final = "Re-run the tool so the running config can be read."
_REPLACE_WEAK_TYPES: Final = "Replace each weak secret with a type 8 or 9 secret."

CONFIG_SOURCE: Final = "config"
"""Where a hardening Finding comes from: config facts and read-only show output."""
_MINIMUM_SSH_BITS: Final = 2048
_WEAK_PRIVACY: Final = frozenset({"DES", "3DES"})
_PLATFORM_UNKNOWN: Final = "the Platform was not identified"
_NTP_GATE_UNKNOWN: Final = (
    "NTP is not shown as configured and show ntp associations reported no peers"
)

SNMP_SKIPPED: Final = "the SNMPv3 user list could not be read"
COPP_SKIPPED: Final = "the control-plane policy could not be read"
SSH_SKIPPED: Final = "the SSH settings could not be read"
GUEST_SHELL_SKIPPED: Final = "the Guest Shell state could not be read"


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


def _hit(
    check: Check,
    device: VisitedDevice,
    level: FindingLevel,
    what: str,
    what_to_do: str,
) -> Finding:
    """Return one Finding for `device`, with a stable id from the Check and the device."""
    return _finding(check, device, level, what, what_to_do)


def _show(data: AnalysisInput, device: VisitedDevice) -> Collected:
    """This device's collected show output, all-unknown when the Run did not supply it."""
    return data.collected_for(device.management_ip)


def _skips(data: AnalysisInput, part: Callable[[Collected], object]) -> tuple[CheckSkip, ...]:
    """One skip per device whose `part` was refused, not collected or never supplied."""
    skips: list[CheckSkip] = []
    for device in data.topology.devices:
        reason = missing_reason(part(_show(data, device)))
        if reason is not None:
            skips.append(CheckSkip(device.id, reason))
    return tuple(skips)


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


_RELEASE_MAJOR_MINOR: Final = re.compile(r"^(\d+)\.(\d+)")


def _release_at_least(device: VisitedDevice, major: int, minor: int) -> bool | Unknown:
    """Whether the release is at least `major.minor`, or `Unknown` when it was not read."""
    release = device.software_version
    if not isinstance(release, str):
        return Unknown("the release was not read")
    match = _RELEASE_MAJOR_MINOR.match(release)
    if match is None:
        return Unknown("the release could not be read")
    return (int(match.group(1)), int(match.group(2))) >= (major, minor)


def _could_not_decide(check: Check, device: VisitedDevice, what: str, todo: str) -> Finding:
    """A Low Finding saying a hidden default stops the config deciding a Check (story 6)."""
    return _finding(check, device, FindingLevel.LOW, f"Could not decide: {what}", todo)


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
    """Story 62: fire on secret types 0, 4 and 7, plus type 5 (MD5-crypt) on IOS and IOS-XE.

    Type 5 is weak on IOS-XE as well as classic IOS (research #76; operator decision on #142).
    On NX-OS type 5 is SHA-256, so it is not flagged there.
    """
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
        if type_five and device.platform is Platform.IOS_XE:
            by_type[5] = type_five
        elif type_five and device.platform is not Platform.NX_OS:
            undecided = Unknown("the Platform was not identified, so type 5's strength is unknown")
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
    """Story 62: fire on source routing and each legacy service the config turns on.

    Source routing is judged on IOS/IOS-XE only: its default is an IOS default, so on NX-OS it
    is neither a hit nor "could not decide".
    """
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        services = facts.fact(LEGACY_SERVICES)
        source = _flag(facts, IP_SOURCE_ROUTE) if device.platform is Platform.IOS_XE else False
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


# -- SSHv2 not enforced ------------------------------------------------------------------------


def ssh_v2(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 61: absence-is-the-problem; SSH 1.99 on classic IOS and IOS-XE before 17.10."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        if device.platform is not Platform.IOS_XE:
            # NX-OS supports SSHv2 only, so SSHv1 cannot be enabled there.
            continue
        version = _count(facts, SSH_VERSION)
        if isinstance(version, Unknown):
            findings.append(_undecided(SSH_V2_CHECK, device, SSH_VERSION, version))
            continue
        if version == _SSH_V2_NUMBER:
            continue
        if version == 1:
            what = "SSHv2 is not enforced: ip ssh version 1 is configured."
        else:
            late = _release_at_least(device, *SSH_V1_REMOVED)
            if late is not False:
                # The line is absent. From 17.10 Cisco refuses SSHv1 anyway, but the running
                # config cannot show which version is in force (#76, X2).
                findings.append(
                    _could_not_decide(
                        SSH_V2_CHECK,
                        device,
                        "the SSH version in force: the running config has no ip ssh version 2, "
                        "and IOS-XE 17.10 or later refuses SSHv1 by default",
                        "Confirm the SSH version in force with show ip ssh.",
                    )
                )
                continue
            what = (
                "SSHv2 is not enforced: ip ssh version 2 is not configured, so the "
                "release's default (SSH 1.99) accepts SSHv1."
            )
        findings.append(
            _finding(
                SSH_V2_CHECK,
                device,
                FindingLevel.HIGH,
                what,
                "Configure ip ssh version 2 on every device that still accepts SSHv1.",
            )
        )
    return tuple(findings)


# -- No VTY access-class -----------------------------------------------------------------------


def vty_access_class(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 61: absence-is-the-problem; name every vty block without an inbound ACL."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        value = facts.fact(VTY_ACCESS_CLASS_MISSING_LINES)
        if isinstance(value, Unknown):
            findings.append(
                _undecided(VTY_ACCESS_CLASS_CHECK, device, VTY_ACCESS_CLASS_MISSING_LINES, value)
            )
            continue
        if not isinstance(value, tuple):
            findings.append(
                _undecided(
                    VTY_ACCESS_CLASS_CHECK,
                    device,
                    VTY_ACCESS_CLASS_MISSING_LINES,
                    Unknown("not a list of line blocks"),
                )
            )
            continue
        if not value:
            continue
        count = len(value)
        noun = "block" if count == 1 else "blocks"
        what = f"No inbound VTY access-class on {count} vty line {noun}: {', '.join(value)}."
        findings.append(
            _finding(
                VTY_ACCESS_CLASS_CHECK,
                device,
                FindingLevel.HIGH,
                what,
                "Apply an inbound access-class to every line vty block.",
            )
        )
    return tuple(findings)


# -- AAA fallback to none ----------------------------------------------------------------------


def aaa_fallback(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 61: absence-is-the-problem; a login method list that falls back to `none` is a hit."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        count = _count(facts, AAA_LOGIN_FALLBACK_NONE)
        if isinstance(count, Unknown):
            findings.append(_undecided(AAA_FALLBACK_CHECK, device, AAA_LOGIN_FALLBACK_NONE, count))
            continue
        if count == 0:
            continue
        noun = "method list" if count == 1 else "method lists"
        what = f"AAA login falls back to none on {count} {noun}."
        findings.append(
            _finding(
                AAA_FALLBACK_CHECK,
                device,
                FindingLevel.HIGH,
                what,
                "Remove none from each aaa authentication login method list and keep local "
                "as the fallback.",
            )
        )
    return tuple(findings)


# -- No central AAA, authorisation or accounting -----------------------------------------------

_AAA_ITEMS: Final = (
    ("aaa new-model", AAA_NEW_MODEL),
    ("central login server group", AAA_CENTRAL_LOGIN),
    ("command authorisation", AAA_AUTHORIZATION),
    ("accounting", AAA_ACCOUNTING),
)
"""The central-AAA items in the order a Finding names them."""


def aaa_central(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 61: absence-is-the-problem; name the central-AAA items the config lacks."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        on_ios = device.platform is Platform.IOS_XE
        items = tuple(
            (label, name) for label, name in _AAA_ITEMS if on_ios or name != AAA_NEW_MODEL
        )
        missing: list[str] = []
        unknown: Unknown | None = None
        for label, name in items:
            value = _flag(facts, name)
            if isinstance(value, Unknown):
                unknown = value
            elif not value:
                missing.append(label)
        if missing:
            what = (
                f"Central AAA is incomplete: {len(missing)} of {len(items)} items missing "
                f"({', '.join(missing)})."
            )
            todo = (
                "Configure aaa new-model, a central login server group, command "
                "authorisation and accounting."
                if on_ios
                else "Configure a central AAA login server group, command authorisation "
                "and accounting."
            )
            findings.append(_finding(AAA_CENTRAL_CHECK, device, FindingLevel.MEDIUM, what, todo))
        elif isinstance(unknown, Unknown):
            findings.append(_undecided(AAA_CENTRAL_CHECK, device, "a central AAA item", unknown))
    return tuple(findings)


# -- Exec timeout ------------------------------------------------------------------------------


def exec_timeout(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 61: absence-is-the-problem; an explicit `exec-timeout 0` is a hit.

    An absent line is the vendor default (10 minutes on IOS/IOS-XE), not a hit (#76, X10).
    """
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        value = facts.fact(EXEC_TIMEOUT_DISABLED_LINES)
        if isinstance(value, Unknown):
            findings.append(
                _undecided(EXEC_TIMEOUT_CHECK, device, EXEC_TIMEOUT_DISABLED_LINES, value)
            )
            continue
        if not isinstance(value, tuple):
            findings.append(
                _undecided(
                    EXEC_TIMEOUT_CHECK,
                    device,
                    EXEC_TIMEOUT_DISABLED_LINES,
                    Unknown("not a list of line blocks"),
                )
            )
            continue
        if not value:
            continue
        count = len(value)
        noun = "block" if count == 1 else "blocks"
        what = (
            f"The exec timeout is disabled (exec-timeout 0) on {count} line {noun}: "
            f"{', '.join(value)}."
        )
        findings.append(
            _finding(
                EXEC_TIMEOUT_CHECK,
                device,
                FindingLevel.MEDIUM,
                what,
                "Set exec-timeout 10 0 or shorter on every console and vty line.",
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


# -- Type 6 not enabled ------------------------------------------------------------------------


def type_6(data: AnalysisInput) -> tuple[Finding, ...]:
    """Story 61: absence-is-the-problem; without `password encryption aes` only type 7 exists."""
    findings: list[Finding] = []
    for device, facts in _checked_devices(data):
        value = _flag(facts, TYPE_6_ENABLED)
        if isinstance(value, Unknown):
            findings.append(_undecided(TYPE_6_CHECK, device, TYPE_6_ENABLED, value))
            continue
        if value:
            continue
        findings.append(
            _finding(
                TYPE_6_CHECK,
                device,
                FindingLevel.MEDIUM,
                "Reversible secrets are not protected by type 6 (AES) encryption; "
                "they fall back to type 7.",
                "Configure password encryption aes (type 6) and protect its master key.",
            )
        )
    return tuple(findings)


# -- SNMPv3 users on MD5/DES/3DES -------------------------------------------------------------


def snmp_user_crypto(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return a High Finding per device whose SNMPv3 users use MD5, DES or 3DES (story 60).

    On IOS/IOS-XE the users come from `show snmp user`; on NX-OS they come from the running
    config, through the `SNMP_V3_USER_CRYPTO` config fact. The Check applies only where
    SNMPv3 is configured (story 63), and no user is ever listed (story 66).
    """
    findings: list[Finding] = []
    for device in data.topology.devices:
        if device.platform is Platform.NX_OS:
            findings.extend(_nxos_snmp(data, device))
            continue
        if device.platform is not Platform.IOS_XE:
            continue
        findings.extend(_ios_snmp(device, _show(data, device).snmp_users))
    return tuple(findings)


def snmp_skipped(data: AnalysisInput) -> tuple[CheckSkip, ...]:
    """Return the devices whose SNMPv3 users could not be read, so the Check never passes."""
    skips: list[CheckSkip] = []
    for device in data.topology.devices:
        if device.platform is Platform.NX_OS:
            value = data.facts_for(device.id).fact(SNMP_V3_USER_CRYPTO)
            reason = value.reason if isinstance(value, Unknown) else None
        elif device.platform is Platform.IOS_XE:
            reason = missing_reason(_show(data, device).snmp_users)
        else:
            reason = _PLATFORM_UNKNOWN
        if reason is not None:
            skips.append(CheckSkip(device.id, reason))
    return tuple(skips)


def _ios_snmp(device: VisitedDevice, part: object) -> list[Finding]:
    """The SNMPv3 Finding for one IOS/IOS-XE device, from its `show snmp user` reading."""
    if missing_reason(part) is not None:
        return []
    if isinstance(part, Unknown):
        return [could_not_decide(SNMP_CHECK, device.id, part.reason)]
    if not isinstance(part, Reading):
        return [could_not_decide(SNMP_CHECK, device.id, SNMP_SKIPPED)]
    users: tuple[SnmpUser, ...] = part.value
    if not users:
        return []  # SNMPv3 is not configured: the Check does not apply (story 63)
    return _snmp_verdict(device, [(user.auth_protocol, user.privacy_protocol) for user in users])


def _nxos_snmp(data: AnalysisInput, device: VisitedDevice) -> list[Finding]:
    """The SNMPv3 Finding for one NX-OS device, from the config fact."""
    value = data.facts_for(device.id).fact(SNMP_V3_USER_CRYPTO)
    if isinstance(value, Unknown):
        return []  # not read: `snmp_skipped` records it, never a pass
    if not isinstance(value, tuple):
        return [could_not_decide(SNMP_CHECK, device.id, "the SNMPv3 config fact is not a list")]
    if not value:
        return []  # SNMPv3 is not configured: the Check does not apply (story 63)
    pairs: list[tuple[object, object]] = []
    for entry in value:
        if "/" not in entry:
            return [
                could_not_decide(
                    SNMP_CHECK, device.id, "the SNMPv3 config fact does not name auth/privacy"
                )
            ]
        auth, privacy = entry.split("/", 1)
        pairs.append((auth, privacy))
    return _snmp_verdict(device, pairs)


def _snmp_verdict(device: VisitedDevice, pairs: Iterable[tuple[object, object]]) -> list[Finding]:
    """Decide one device's users from each user's authentication and privacy protocol."""
    users = list(pairs)
    weak_auth = Counter(_protocol(auth) for auth, _ in users if _weak_auth(auth))
    weak_privacy = Counter(_protocol(privacy) for _, privacy in users if _weak_privacy(privacy))
    weak_users = sum(1 for auth, privacy in users if _weak_auth(auth) or _weak_privacy(privacy))
    if weak_users:
        details = [
            *(f"{name} authentication on {count}" for name, count in sorted(weak_auth.items())),
            *(f"{name} privacy on {count}" for name, count in sorted(weak_privacy.items())),
        ]
        what = f"SNMPv3 users on MD5, DES or 3DES: {weak_users} ({', '.join(details)})."
        return [
            _hit(
                SNMP_CHECK,
                device,
                FindingLevel.HIGH,
                what,
                "Move every SNMPv3 user to SHA-256 or better authentication and AES privacy.",
            )
        ]
    if any(isinstance(auth, Unknown) or isinstance(privacy, Unknown) for auth, privacy in users):
        return [
            could_not_decide(
                SNMP_CHECK,
                device.id,
                "show snmp user did not report every user's authentication or privacy protocol",
            )
        ]
    return []


def _weak_auth(value: object) -> bool:
    return isinstance(value, str) and _protocol(value) == "MD5"


def _weak_privacy(value: object) -> bool:
    return isinstance(value, str) and _protocol(value) in _WEAK_PRIVACY


def _protocol(value: object) -> str:
    """A protocol as a fixed keyword, so device text is never echoed into a Finding."""
    return value.strip().upper() if isinstance(value, str) else ""


# -- NTP not synchronised ---------------------------------------------------------------------


def ntp_synchronised(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return a Medium Finding per device that runs NTP and has no synchronised peer.

    It runs only where NTP is configured (story 63). NTP that is configured but has no peer at
    all is not synchronised either, so it fires too. A device whose config fact is `Unknown`
    and whose association table is empty is "could not decide", never a pass (story 6).
    """
    findings: list[Finding] = []
    for device in data.topology.devices:
        gate = data.facts_for(device.id).fact(NTP_CONFIGURED)
        if gate is False:
            continue  # NTP is not in use: the Check does not apply (story 63)
        findings.extend(_ntp_verdict(device, gate, _show(data, device).ntp_associations))
    return tuple(findings)


def _ntp_verdict(device: VisitedDevice, gate: object, part: object) -> list[Finding]:
    """Decide one device's NTP state, from the config gate and `show ntp associations`."""
    if missing_reason(part) is not None:
        return []
    if isinstance(part, Unknown):
        return [could_not_decide(NTP_SYNC_CHECK, device.id, part.reason)]
    if not isinstance(part, Reading):
        return [could_not_decide(NTP_SYNC_CHECK, device.id, NTP_SKIPPED)]
    peers: tuple[NtpAssociation, ...] = part.value
    undecidable = _ntp_gate_problem(gate, peers)
    if undecidable is not None:
        return [could_not_decide(NTP_SYNC_CHECK, device.id, undecidable)]
    if any(peer.synchronised for peer in peers):
        return []
    if peers:
        what = (
            f"NTP is not synchronised: {len(peers)} peers, none selected as the "
            "synchronisation source."
        )
    else:
        what = (
            "NTP is not synchronised: NTP is configured and no peer is selected as the "
            "synchronisation source."
        )
    return [
        _hit(
            NTP_SYNC_CHECK,
            device,
            FindingLevel.MEDIUM,
            what,
            "Restore NTP reachability or authentication until a peer is selected.",
        )
    ]


def _ntp_gate_problem(gate: object, peers: tuple[NtpAssociation, ...]) -> str | None:
    """Why the NTP config gate cannot decide this device, or None when it can."""
    if gate is True:
        return None
    if isinstance(gate, Unknown):
        return None if peers else _NTP_GATE_UNKNOWN
    return "the NTP config fact is not true or false"


def ntp_skipped(data: AnalysisInput) -> tuple[CheckSkip, ...]:
    """Return the devices whose NTP state could not be read, so the Check never passes."""
    skips: list[CheckSkip] = []
    for device in data.topology.devices:
        if data.facts_for(device.id).fact(NTP_CONFIGURED) is False:
            continue
        reason = missing_reason(_show(data, device).ntp_associations)
        if reason is not None:
            skips.append(CheckSkip(device.id, reason))
    return tuple(skips)


NTP_SKIPPED: Final = "the NTP associations could not be read"


# -- CoPP not applied -------------------------------------------------------------------------


def copp(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return a Medium Finding per device with no control-plane service policy (story 60)."""
    findings: list[Finding] = []
    for device in data.topology.devices:
        part = _show(data, device).control_plane
        if missing_reason(part) is not None:
            continue
        if isinstance(part, Unknown):
            findings.append(could_not_decide(COPP_CHECK, device.id, part.reason))
            continue
        if not isinstance(part, Reading):
            findings.append(could_not_decide(COPP_CHECK, device.id, COPP_SKIPPED))
            continue
        policy: ControlPlanePolicy = part.value
        if policy.service_policies:
            continue
        findings.append(
            _hit(
                COPP_CHECK,
                device,
                FindingLevel.MEDIUM,
                "No control-plane service policy is applied (CoPP).",
                "Apply the control-plane policing policy this Platform expects.",
            )
        )
    return tuple(findings)


def copp_skipped(data: AnalysisInput) -> tuple[CheckSkip, ...]:
    """Return the devices whose control-plane policy could not be read."""
    return _skips(data, lambda shown: shown.control_plane)


# -- SSH key under 2048 bits ------------------------------------------------------------------


def ssh_key_size(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return a Medium Finding per device whose SSH host key is under 2048 bits (story 60)."""
    findings: list[Finding] = []
    for device in data.topology.devices:
        part = _show(data, device).ssh
        if missing_reason(part) is not None:
            continue
        if isinstance(part, Unknown):
            findings.append(could_not_decide(SSH_CHECK, device.id, part.reason))
            continue
        if not isinstance(part, Reading):
            findings.append(could_not_decide(SSH_CHECK, device.id, SSH_SKIPPED))
            continue
        settings: SshSettings = part.value
        if settings.enabled is False:
            continue  # no SSH server, so no host key to size; the SSHv2 Check covers it
        if isinstance(settings.key_bits, Unknown):
            findings.append(could_not_decide(SSH_CHECK, device.id, settings.key_bits.reason))
            continue
        if settings.key_bits >= _MINIMUM_SSH_BITS:
            continue
        findings.append(
            _hit(
                SSH_CHECK,
                device,
                FindingLevel.MEDIUM,
                f"The SSH host key is smaller than {_MINIMUM_SSH_BITS} bits: "
                f"{settings.key_bits} bits.",
                f"Generate an SSH host key of {_MINIMUM_SSH_BITS} bits or more.",
            )
        )
    return tuple(findings)


def ssh_skipped(data: AnalysisInput) -> tuple[CheckSkip, ...]:
    """Return the devices whose SSH settings could not be read."""
    return _skips(data, lambda shown: shown.ssh)


# -- Guest Shell present (NX-OS) --------------------------------------------------------------


def guest_shell(data: AnalysisInput) -> tuple[Finding, ...]:
    """Return a Medium Finding per NX-OS device whose Guest Shell is present (story 60)."""
    findings: list[Finding] = []
    for device in data.topology.devices:
        if device.platform is not Platform.NX_OS:
            continue
        part = _show(data, device).guest_shell
        if missing_reason(part) is not None:
            continue
        if isinstance(part, Unknown):
            findings.append(could_not_decide(GUEST_SHELL_CHECK, device.id, part.reason))
            continue
        if not isinstance(part, Reading):
            findings.append(could_not_decide(GUEST_SHELL_CHECK, device.id, GUEST_SHELL_SKIPPED))
            continue
        if part.value is not True:
            continue
        findings.append(
            _hit(
                GUEST_SHELL_CHECK,
                device,
                FindingLevel.MEDIUM,
                "The Guest Shell is present and enabled.",
                "Disable the Guest Shell when no automation needs it.",
            )
        )
    return tuple(findings)


def guest_shell_skipped(data: AnalysisInput) -> tuple[CheckSkip, ...]:
    """Return the NX-OS devices whose Guest Shell state could not be read.

    The Check does not apply to IOS/IOS-XE, which has no Guest Shell, so those devices are
    never skipped by it.
    """
    skips: list[CheckSkip] = []
    for device in data.topology.devices:
        if device.platform is not Platform.NX_OS:
            continue
        reason = missing_reason(_show(data, device).guest_shell)
        if reason is not None:
            skips.append(CheckSkip(device.id, reason))
    return tuple(skips)


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
    CheckDefinition(SSH_V2_CHECK, ssh_v2),
    CheckDefinition(VTY_ACCESS_CLASS_CHECK, vty_access_class),
    CheckDefinition(AAA_FALLBACK_CHECK, aaa_fallback),
    CheckDefinition(AAA_CENTRAL_CHECK, aaa_central),
    CheckDefinition(EXEC_TIMEOUT_CHECK, exec_timeout),
    CheckDefinition(TYPE_6_CHECK, type_6),
    CheckDefinition(SNMP_CHECK, snmp_user_crypto, skipped=snmp_skipped),
    CheckDefinition(NTP_SYNC_CHECK, ntp_synchronised, skipped=ntp_skipped),
    CheckDefinition(COPP_CHECK, copp, skipped=copp_skipped),
    CheckDefinition(SSH_CHECK, ssh_key_size, skipped=ssh_skipped),
    CheckDefinition(GUEST_SHELL_CHECK, guest_shell, skipped=guest_shell_skipped),
    CheckDefinition(CISCO_LIST_CHECK, cisco_list.cisco_list, skipped=cisco_list.cisco_skipped),
    CheckDefinition(ROLE_CHECK, role.role_out_of_date, skipped=role.role_skipped),
)
"""These twenty-eight Checks, ready to join `checks.CHECKS`."""
