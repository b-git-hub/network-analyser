"""The records `analysis` takes in and the lookup questions it hands to `advisories` (#94).

Analysis is pure: it takes the Run's plain records and returns the plain records in
`records.topology` (`AnalysisResults`). Nothing here holds a live device, a config line, a
secret or a Cisco client.

**Config facts** are the secret-free values `platforms` reads from a device's running config
at capture time (#96). A fact that was not read is `Unknown`, never absent and never an empty
value, so a Check can never read "not looked at" as "off" (story 126).

**Cisco answers** are what `advisories` learned, or "source unavailable: reason" (#95, #104).
Each of the three sources is either a tuple of answers or a `SourceUnavailable`, so an outage
can never look like "Cisco said none" (stories 118-119).
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, unique
from ipaddress import IPv4Address
from types import MappingProxyType
from typing import Final

from network_analyser.records.collected import Collected
from network_analyser.records.config_facts import ConfigFact, ConfigFacts, FactValue
from network_analyser.records.topology import AdvisoryDetail, EoxItem, Topology

__all__ = [
    "DEVICE_ROLE_CHECKS_BY_DATA",
    "NTP_CONFIGURED",
    "SHOW_OUTPUT_NOT_SUPPLIED",
    "SNMP_V3_USER_CRYPTO",
    "AdvisoryAnswer",
    "AdvisoryPlatform",
    "AnalysisInput",
    "CiscoAnswer",
    "CiscoAnswers",
    "CompatibleRelease",
    "CompatibleReleases",
    "ConfigFact",
    "ConfigFacts",
    "DeviceCollected",
    "DeviceInventory",
    "EoxAnswers",
    "FactValue",
    "FixedRelease",
    "HardwareEox",
    "HardwareItem",
    "HardwareKind",
    "LookupQuestions",
    "OsType",
    "ReleaseAdvisories",
    "ReleaseQuestion",
    "SoftwareEox",
    "SourceUnavailable",
    "SuggestedReleases",
]


@unique
class OsType(Enum):
    """The operating-system family a release question is about (stories 44-45).

    Classic IOS and IOS-XE are separate families because Cisco answers them separately. Both
    share `Platform.IOS_XE`'s command set; the family table decided on #78 tells them apart.
    """

    IOS = "IOS"
    IOS_XE = "IOS-XE"
    NX_OS = "NX-OS"


SNMP_V3_USER_CRYPTO: Final = "snmp_v3_user_crypto"
"""The config fact the SNMPv3 crypto Check reads on NX-OS (#102, story 60).

Its value is one `<auth>/<privacy>` string per SNMPv3 user, such as `MD5/DES`, with no user
name, no key and no community string: the Finding reports keywords and counts only (story 66).
An empty tuple means SNMPv3 is not configured, so the Check does not apply (story 63)."""

NTP_CONFIGURED: Final = "ntp_configured"
"""The config fact that says NTP is in use, gating the sync Check (#102, story 63).

`False` means NTP is not configured, so NTP sync raises nothing. `Unknown` never reads as
"not configured": the Check says it could not decide instead (story 6)."""

SHOW_OUTPUT_NOT_SUPPLIED: Final = "show output was not supplied to Analysis"
"""Why a device's show output is `Unknown` before the Run hands it over (#102)."""

DEVICE_ROLE_CHECKS_BY_DATA: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "inventory": ("lifecycle-hardware-eox",),
        "snmp_users": ("config-snmpv3-user-crypto",),
        "ntp_associations": ("config-ntp-synchronised",),
        "control_plane": ("config-copp-applied",),
        "ssh": ("config-ssh-key-size",),
        "insecure_configuration": ("config-cisco-insecure-list",),
        "guest_shell": ("config-guest-shell",),
    }
)
"""The one Device Role contract both Platforms and Analysis share (#102, story 80).

Keyed by the `Collected` field each 0.2.0 command fills, so a Platform never repeats a Check
id and Analysis never imports a Platform. `lifecycle-hardware-eox` is shipped by #106: a Role
that refuses `show inventory` is already reported against that Check."""


@unique
class HardwareKind(Enum):
    """The hardware a PID question is asked about (story 14). Optics, PSUs and fans are not."""

    CHASSIS = "chassis"
    STACK_MEMBER = "stack member"
    SUPERVISOR = "supervisor"
    LINE_CARD = "line card"


@dataclass(frozen=True, slots=True)
class HardwareItem:
    """One hardware PID that a lookup may ask Cisco about (stories 14, 73).

    Attributes:
        pid: the PID, as the device reported it.
        kind: chassis, stack member, supervisor or line card.
    """

    pid: str
    kind: HardwareKind


@dataclass(frozen=True, slots=True)
class DeviceCollected:
    """One Visited Device's collected show output, keyed by the address logged into (#102).

    Analysis cannot ask a device anything, so the Run hands it what the visit collected. The
    address is the one the tool logged into, which is how the Topology's Visited Device is
    recognised (`VisitedDevice.management_ip`); a record for another address is never used.

    Attributes:
        management_ip: the address the tool logged into.
        collected: the device's collected record, each part a `Reading` or `Unknown`.
    """

    management_ip: IPv4Address
    collected: Collected


@dataclass(frozen=True, slots=True)
class DeviceInventory:
    """The hardware PIDs read from one device's `show inventory` (#97, #98).

    Attributes:
        device: the device's id.
        items: its chassis, stack-member, supervisor and line-card PIDs.
    """

    device: str
    items: tuple[HardwareItem, ...] = ()


@dataclass(frozen=True, slots=True)
class SourceUnavailable:
    """A Cisco source that could not be asked this Run (stories 118-119).

    Attributes:
        reason: why, as fixed text, such as `Cisco could not be reached`.
    """

    reason: str


type CiscoAnswer[T] = tuple[T, ...] | SourceUnavailable
"""One Cisco source: its answers, or why it could not be asked. Never an absent answer."""


@dataclass(frozen=True, slots=True)
class FixedRelease:
    """One first-fixed release Cisco gives an Advisory, within one Train (stories 50, 55).

    Attributes:
        train: the Train, such as `17.9`.
        release: the first fixed release in that Train; None when Cisco names none.
    """

    train: str
    release: str | None = None


@dataclass(frozen=True, slots=True)
class AdvisoryPlatform:
    """One `platforms[]` entry of an NX-OS Advisory, with each fix in its Train (#126).

    Attributes:
        name: Cisco's platform name, such as `Cisco Nexus 9000 Series Switches`; None when
            the entry named none, so it can never match a device's series.
        first_fixed: the platform's first-fixed releases, each with its Train.
    """

    name: str | None
    first_fixed: tuple[FixedRelease, ...] = ()


@dataclass(frozen=True, slots=True)
class AdvisoryAnswer:
    """Cisco's answer for one Advisory (stories 47-50; #105).

    Attributes:
        detail: Cisco's detail, in the same shape a Finding carries (#93).
        first_fixed: every first-fixed release Cisco names, one per Train.
        platforms: the per-platform first fixes an NX-OS reply names; empty otherwise (#126).
    """

    detail: AdvisoryDetail
    first_fixed: tuple[FixedRelease, ...] = ()
    platforms: tuple[AdvisoryPlatform, ...] = ()


@dataclass(frozen=True, slots=True)
class ReleaseAdvisories:
    """Cisco's answer for one OS type and release (stories 43-46).

    Attributes:
        os_type: the family the release belongs to.
        release: the release asked about, normalised before lookup (story 45).
        advisories: every Advisory Cisco named for it; empty means it named none.
        hardware_family: the Nexus hardware family asked about on NX-OS; None otherwise.
        unavailable: why Cisco gave no answer for this release, such as
            `INVALID_IOS_VERSION`; None when it answered (story 53).
    """

    os_type: OsType
    release: str
    advisories: tuple[AdvisoryAnswer, ...] = ()
    hardware_family: str | None = None
    unavailable: str | None = None


@dataclass(frozen=True, slots=True)
class HardwareEox:
    """Cisco's EoX answer for one hardware PID (stories 73-74; #153).

    Attributes:
        pid: the PID asked about.
        items: the EoX items Cisco named for it; empty when Cisco answered and named none.
        unanswered: why Cisco gave no answer for this PID, such as `SSA_ERR_026` or fixed
            text; None when it answered (#153).
    """

    pid: str
    items: tuple[EoxItem, ...] = ()
    unanswered: str | None = None


@dataclass(frozen=True, slots=True)
class SoftwareEox:
    """Cisco's EoX answer for one release (story 75; #153).

    Attributes:
        release: the release asked about.
        items: the EoX items Cisco named for it; empty when Cisco answered and named none.
        unanswered: why Cisco gave no answer for this release, such as `SSA_ERR_026` or fixed
            text; None when it answered (#153).
    """

    release: str
    items: tuple[EoxItem, ...] = ()
    unanswered: str | None = None


@dataclass(frozen=True, slots=True)
class EoxAnswers:
    """Cisco's EoX answers, hardware and software (#106).

    Attributes:
        hardware: one answer per PID asked about.
        software: one answer per release asked about.
    """

    hardware: tuple[HardwareEox, ...] = ()
    software: tuple[SoftwareEox, ...] = ()


@dataclass(frozen=True, slots=True)
class SuggestedReleases:
    """Cisco's Suggested Releases for one PID (stories 57, 77; #89, #106).

    Attributes:
        pid: the PID asked about.
        releases: the releases Cisco suggests for it.
        latest_release_in_train: the newest release in the device's Train; None when Cisco
            gives none, so the report can say `not available` rather than guess.
        latest_release: the newest release overall; None when Cisco gives none.
    """

    pid: str
    releases: tuple[str, ...] = ()
    latest_release_in_train: str | None = None
    latest_release: str | None = None


@dataclass(frozen=True, slots=True)
class CompatibleRelease:
    """One release Cisco lists as compatible with a chassis PID (#127).

    Attributes:
        release: the release's display name, as Cisco gives it.
        lifecycle: Cisco's lifecycle code, such as `ED`; None when the reply names none or
            the code did not pass its pattern.
    """

    release: str
    lifecycle: str | None = None


@dataclass(frozen=True, slots=True)
class CompatibleReleases:
    """Cisco's compatible-release list for one chassis PID (#127).

    Attributes:
        pid: the chassis PID asked about.
        releases: every release Cisco lists as compatible, in the reply's order.
        unanswered: why Cisco gave no list for this PID, such as `S3_INV_BASEPID` or
            `page cap`; None when it answered.
    """

    pid: str
    releases: tuple[CompatibleRelease, ...] = ()
    unanswered: str | None = None


@dataclass(frozen=True, slots=True)
class CiscoAnswers:
    """Everything the Run asked Cisco, each source answered or unavailable (ADR 0007).

    Attributes:
        advisories: per OS type and release.
        eox: per PID and per release.
        suggestions: per PID, from the Suggested Release Check's call.
        compatible: per chassis PID, from the compatible-releases call (#127).
    """

    advisories: CiscoAnswer[ReleaseAdvisories] = ()
    eox: CiscoAnswer[EoxAnswers] = ()
    suggestions: CiscoAnswer[SuggestedReleases] = ()
    compatible: CiscoAnswer[CompatibleReleases] = ()

    @classmethod
    def unavailable(cls, reason: str) -> CiscoAnswers:
        """Return answers where every source is unavailable for `reason`."""
        missing = SourceUnavailable(reason)
        return cls(advisories=missing, eox=missing, suggestions=missing, compatible=missing)


@dataclass(frozen=True, slots=True)
class ReleaseQuestion:
    """One OS type and release to ask Cisco about (stories 12-13, 43-46).

    Attributes:
        os_type: the family the release belongs to.
        release: the release string, pattern-valid and normalised before sending (story 45).
        hardware_family: the Nexus hardware family openVuln is asked about on NX-OS, such as
            `NEXUS9000`; None for IOS and IOS-XE, and for an NX-OS device whose family could
            not be worked out (story 46).
    """

    os_type: OsType
    release: str
    hardware_family: str | None = None


@dataclass(frozen=True, slots=True)
class LookupQuestions:
    """What `analysis` asks `advisories` to look up, with no device record in it (#94).

    Every value is de-duplicated, sorted and pattern-valid before it is put here, so the
    online step never sees a hostname, address, serial, count or config line (stories 12-14).

    Attributes:
        pids: chassis, stack-member, supervisor and line-card PIDs.
        releases: one per distinct OS type and release.
        compatible_pids: Visited Devices' chassis models only, for the compatible-releases
            call; never a line card or any other part (#127).
    """

    pids: tuple[str, ...] = ()
    releases: tuple[ReleaseQuestion, ...] = ()
    compatible_pids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AnalysisInput:
    """Everything the Run hands Analysis at its end (#94).

    Attributes:
        topology: the Run's Topology: its Visited Devices, Links, Bundles and v1 Findings.
            Unvisited Devices are in it, and Analysis never uses them (story 3).
        config_facts: each Visited Device's secret-free facts, read by `platforms` inside the
            visit (#96). A device with no entry has every fact `Unknown`.
        collected: each Visited Device's collected show output, for the show-output Checks
            (#102), keyed by the address logged into.
        inventory: each device's hardware PIDs, once #97 and #98 fill them.
        answers: Cisco's answers, or why each source could not be asked.
        as_of: the moment the Lifecycle Checks judge EoX dates against, as an aware UTC
            datetime; None means now, so a Run uses its own end and a test can pin a date
            without reaching for the clock (#106).
    """

    topology: Topology
    config_facts: tuple[ConfigFacts, ...] = ()
    collected: tuple[DeviceCollected, ...] = ()
    inventory: tuple[DeviceInventory, ...] = ()
    answers: CiscoAnswers = field(default_factory=CiscoAnswers)
    as_of: datetime | None = None

    def facts_for(self, device: str) -> ConfigFacts:
        """Return `device`'s config facts, or an empty set whose every fact is `Unknown`."""
        for facts in self.config_facts:
            if facts.device == device:
                return facts
        return ConfigFacts(device)

    def collected_for(self, management_ip: IPv4Address) -> Collected:
        """Return the show output collected at `management_ip`, or an all-`Unknown` record.

        `Unknown` is never a pass: a Check that needs a part this record lacks is skipped for
        the device, with its reason (story 6; #102).
        """
        for item in self.collected:
            if item.management_ip == management_ip:
                return item.collected
        return Collected.nothing(SHOW_OUTPUT_NOT_SUPPLIED)
