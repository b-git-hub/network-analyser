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

from dataclasses import dataclass, field
from enum import Enum, unique

from network_analyser.records.topology import AdvisoryDetail, EoxItem, Topology
from network_analyser.records.unknown import Unknown

__all__ = [
    "AdvisoryAnswer",
    "AnalysisInput",
    "CiscoAnswer",
    "CiscoAnswers",
    "ConfigFact",
    "ConfigFacts",
    "DeviceInventory",
    "EoxAnswers",
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


type FactValue = bool | int | str | tuple[str, ...] | Unknown
"""One config fact's value. It may be `Unknown` when the fact could not be read."""


@dataclass(frozen=True, slots=True)
class ConfigFact:
    """One secret-free fact read from a device's running config (#96).

    Attributes:
        name: its fixed name, such as `telnet`.
        value: its value; `Unknown` when it could not be read.
    """

    name: str
    value: FactValue


@dataclass(frozen=True, slots=True)
class ConfigFacts:
    """The secret-free config facts of one Visited Device (#96).

    Attributes:
        device: the device's id.
        facts: every fact that was read, in name order.
    """

    device: str
    facts: tuple[ConfigFact, ...] = ()

    def fact(self, name: str) -> FactValue:
        """Return `name`'s value, or `Unknown` when it was not read (never "absent")."""
        for item in self.facts:
            if item.name == name:
                return item.value
        return Unknown(f"config fact not collected: {name}")


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
class AdvisoryAnswer:
    """Cisco's answer for one Advisory (stories 47-50; #105).

    Attributes:
        detail: Cisco's detail, in the same shape a Finding carries (#93).
        first_fixed: every first-fixed release Cisco names, one per Train.
    """

    detail: AdvisoryDetail
    first_fixed: tuple[FixedRelease, ...] = ()


@dataclass(frozen=True, slots=True)
class ReleaseAdvisories:
    """Cisco's answer for one OS type and release (stories 43-46).

    Attributes:
        os_type: the family the release belongs to.
        release: the release asked about, normalised before lookup (story 45).
        advisories: every Advisory Cisco named for it; empty means it named none.
        hardware_family: the Nexus hardware family asked about on NX-OS; None otherwise.
    """

    os_type: OsType
    release: str
    advisories: tuple[AdvisoryAnswer, ...] = ()
    hardware_family: str | None = None


@dataclass(frozen=True, slots=True)
class HardwareEox:
    """Cisco's EoX answer for one hardware PID (stories 73-74).

    Attributes:
        pid: the PID asked about.
        items: the EoX items Cisco named for it.
    """

    pid: str
    items: tuple[EoxItem, ...] = ()


@dataclass(frozen=True, slots=True)
class SoftwareEox:
    """Cisco's EoX answer for one release (story 75).

    Attributes:
        release: the release asked about.
        items: the EoX items Cisco named for it.
    """

    release: str
    items: tuple[EoxItem, ...] = ()


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
class CiscoAnswers:
    """Everything the Run asked Cisco, each source answered or unavailable (ADR 0007).

    Attributes:
        advisories: per OS type and release.
        eox: per PID and per release.
        suggestions: per PID.
    """

    advisories: CiscoAnswer[ReleaseAdvisories] = ()
    eox: CiscoAnswer[EoxAnswers] = ()
    suggestions: CiscoAnswer[SuggestedReleases] = ()

    @classmethod
    def unavailable(cls, reason: str) -> CiscoAnswers:
        """Return answers where every source is unavailable for `reason`."""
        missing = SourceUnavailable(reason)
        return cls(advisories=missing, eox=missing, suggestions=missing)


@dataclass(frozen=True, slots=True)
class ReleaseQuestion:
    """One OS type and release to ask Cisco about (stories 12-13, 43-45).

    Attributes:
        os_type: the family the release belongs to.
        release: the release string, pattern-valid and normalised before sending (story 45).
    """

    os_type: OsType
    release: str


@dataclass(frozen=True, slots=True)
class LookupQuestions:
    """What `analysis` asks `advisories` to look up, with no device record in it (#94).

    Every value is de-duplicated, sorted and pattern-valid before it is put here, so the
    online step never sees a hostname, address, serial, count or config line (stories 12-14).

    Attributes:
        pids: chassis, stack-member, supervisor and line-card PIDs.
        releases: one per distinct OS type and release.
    """

    pids: tuple[str, ...] = ()
    releases: tuple[ReleaseQuestion, ...] = ()


@dataclass(frozen=True, slots=True)
class AnalysisInput:
    """Everything the Run hands Analysis at its end (#94).

    Attributes:
        topology: the Run's Topology: its Visited Devices, Links, Bundles and v1 Findings.
            Unvisited Devices are in it, and Analysis never uses them (story 3).
        config_facts: each Visited Device's secret-free facts, once #96 fills them.
        inventory: each device's hardware PIDs, once #97 and #98 fill them.
        answers: Cisco's answers, or why each source could not be asked.
    """

    topology: Topology
    config_facts: tuple[ConfigFacts, ...] = ()
    inventory: tuple[DeviceInventory, ...] = ()
    answers: CiscoAnswers = field(default_factory=CiscoAnswers)

    def facts_for(self, device: str) -> ConfigFacts:
        """Return `device`'s config facts, or an empty set whose every fact is `Unknown`."""
        for facts in self.config_facts:
            if facts.device == device:
                return facts
        return ConfigFacts(device)
