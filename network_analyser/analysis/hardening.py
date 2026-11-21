"""The hardening Checks: config facts and the 0.2.0 show output (#96, #102).

The batch-#96 Checks are decided from the secret-free config facts in
`records.config_facts` (stories 59-66, 69):

- Presence-is-the-problem Checks fire only on a hit: Telnet, weak secret types, `enable
  password`, SNMPv1/v2c, insecure mode, the HTTP server, legacy services (story 62).
- The `enable secret` Check is absence-is-the-problem: it always runs on IOS/IOS-XE (story 61).
- SNMPv3 privacy runs only where SNMPv3 is configured (story 63).
- A fact that was not read makes a Low "could not decide" Finding, never a silent pass
  (story 6).
- IOS-XE Checks also run on classic IOS with its own rules; insecure mode stays IOS-XE only
  (story 64).

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

from collections import Counter
from collections.abc import Callable, Iterable
from typing import Final

from network_analyser.analysis import cisco_list, role
from network_analyser.analysis.catalogue import (
    CISCO_LIST_CHECK,
    COPP_CHECK,
    GUEST_SHELL_CHECK,
    NTP_CHECK,
    ROLE_CHECK,
    SNMP_CHECK,
    SSH_CHECK,
)
from network_analyser.analysis.definition import CheckDefinition
from network_analyser.analysis.ids import finding_id
from network_analyser.analysis.outcome import could_not_decide, missing_reason
from network_analyser.records import Platform
from network_analyser.records.analysis import (
    NTP_CONFIGURED,
    SNMP_V3_USER_CRYPTO,
    AnalysisInput,
    ConfigFacts,
)
from network_analyser.records.collected import (
    Collected,
    ControlPlanePolicy,
    NtpAssociation,
    Reading,
    SnmpUser,
    SshSettings,
)
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
        return [could_not_decide(NTP_CHECK, device.id, part.reason)]
    if not isinstance(part, Reading):
        return [could_not_decide(NTP_CHECK, device.id, NTP_SKIPPED)]
    peers: tuple[NtpAssociation, ...] = part.value
    undecidable = _ntp_gate_problem(gate, peers)
    if undecidable is not None:
        return [could_not_decide(NTP_CHECK, device.id, undecidable)]
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
            NTP_CHECK,
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
    CheckDefinition(SNMP_CHECK, snmp_user_crypto, skipped=snmp_skipped),
    CheckDefinition(NTP_CHECK, ntp_synchronised, skipped=ntp_skipped),
    CheckDefinition(COPP_CHECK, copp, skipped=copp_skipped),
    CheckDefinition(SSH_CHECK, ssh_key_size, skipped=ssh_skipped),
    CheckDefinition(GUEST_SHELL_CHECK, guest_shell, skipped=guest_shell_skipped),
    CheckDefinition(CISCO_LIST_CHECK, cisco_list.cisco_list, skipped=cisco_list.cisco_skipped),
    CheckDefinition(ROLE_CHECK, role.role_out_of_date, skipped=role.role_skipped),
)
"""These fifteen Checks, ready to join `checks.CHECKS`."""
