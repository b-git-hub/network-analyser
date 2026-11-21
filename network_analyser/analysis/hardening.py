"""The five hardening Checks that need the 0.2.0 show output (#102, story 60).

Each Check is decided from one part of the Visited Device's `Collected` record, or, for NX-OS
SNMPv3 users, from a secret-free config fact: NX-OS prints no such command and the users are
in the running config. Feature gating follows story 63: SNMPv3 crypto runs only where SNMPv3
is configured, and NTP sync only where NTP is. The "absence is the problem" Checks always run
(story 61).

A part the device refused (a Device Role that predates the command) or the Run never handed
over is a skip for that device, never a pass. A part that was read but does not decide the
question raises story 6's Low "could not decide" Finding. Findings name protocols, counts and
sizes only: never a user name, key, hash or community string (story 66).
"""

from collections import Counter
from collections.abc import Callable, Iterable
from typing import Final

from network_analyser.analysis.catalogue import (
    COPP_CHECK,
    GUEST_SHELL_CHECK,
    NTP_CHECK,
    SNMP_CHECK,
    SSH_CHECK,
)
from network_analyser.analysis.ids import finding_id
from network_analyser.analysis.outcome import could_not_decide, missing_reason
from network_analyser.records.analysis import (
    NTP_CONFIGURED,
    SNMP_V3_USER_CRYPTO,
    AnalysisInput,
)
from network_analyser.records.collected import (
    Collected,
    ControlPlanePolicy,
    NtpAssociation,
    Reading,
    SnmpUser,
    SshSettings,
)
from network_analyser.records.platform import Platform
from network_analyser.records.topology import (
    Check,
    CheckSkip,
    Finding,
    FindingLevel,
    VisitedDevice,
)
from network_analyser.records.unknown import Unknown

__all__ = [
    "COPP_CHECK",
    "COPP_SKIPPED",
    "GUEST_SHELL_CHECK",
    "GUEST_SHELL_SKIPPED",
    "NTP_CHECK",
    "SNMP_CHECK",
    "SNMP_SKIPPED",
    "SSH_CHECK",
    "SSH_SKIPPED",
    "copp",
    "copp_skipped",
    "guest_shell",
    "guest_shell_skipped",
    "ntp_skipped",
    "ntp_synchronised",
    "snmp_skipped",
    "snmp_user_crypto",
    "ssh_key_size",
    "ssh_skipped",
]

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


def _hit(
    check: Check,
    device: VisitedDevice,
    level: FindingLevel,
    what: str,
    what_to_do: str,
) -> Finding:
    """Return one Finding for `device`, with a stable id from the Check and the device."""
    return Finding(
        id=finding_id(check.id, device.id),
        devices=(device.id,),
        items=(),
        evidence=(),
        level=level,
        check=check,
        what_was_found=what,
        what_to_do=what_to_do,
        source=CONFIG_SOURCE,
        summary=what,
    )


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
