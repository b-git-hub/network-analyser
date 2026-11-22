"""The lookup questions `analysis` asks and the Cisco answers `advisories` returns (#95).

These records are the only things that cross between the offline side of Analysis and the
one module that goes online. The questions are de-duplicated PIDs and OS type + release
strings; the answers are Cisco's replies as plain data, or `SourceUnavailable(reason)` when a
source could not be reached. No device record, hostname, IP, serial or count is in either.

The answers keep Cisco's text as data, bounded and stripped of control characters. They are
still untrusted: whatever shows them escapes them (story 117).
"""

from dataclasses import dataclass
from enum import Enum, unique


@unique
class CiscoOsType(Enum):
    """The OS type openVuln is asked about. These three strings are the only ones sent."""

    IOS = "ios"
    IOS_XE = "iosxe"
    NX_OS = "nxos"


@dataclass(frozen=True, slots=True)
class ReleaseQuestion:
    """One openVuln question: an OS type and a normalised release.

    Attributes:
        os_type: classic IOS, IOS-XE or NX-OS.
        release: the release to ask about, already normalised for its family.
        platform_alias: the Nexus hardware family NX-OS is matched on, such as `NEXUS9000`;
            None for IOS and IOS-XE.
    """

    os_type: CiscoOsType
    release: str
    platform_alias: str | None = None


@dataclass(frozen=True, slots=True)
class SoftwareEoxQuestion:
    """One software EoX question: an OS type and a normalised release.

    Cisco's query form takes `<release>,<OSType>`, so the OS type travels with the release.

    Attributes:
        os_type: the release's OS family. IOS and IOS-XE are sent; NX-OS is not until its
            Cisco `OSType` name is confirmed (#165).
        release: the release to ask about, already normalised for its family.
    """

    os_type: CiscoOsType
    release: str


@dataclass(frozen=True, slots=True)
class LookupQuestions:
    """Everything one Run needs to ask Cisco, already de-duplicated by `analysis`.

    Attributes:
        releases: one openVuln question per distinct OS type and release.
        hardware_pids: PIDs for the hardware EoX lookup: chassis, stack members,
            supervisors and line cards, never optics, PSUs or fans.
        software_releases: one software EoX question per distinct OS type and release.
        suggestion_pids: base PIDs for the Software Suggestion lookup.
        compatible_pids: chassis PIDs for the compatible-releases lookup (#127), never line
            cards or any other part.
    """

    releases: tuple[ReleaseQuestion, ...] = ()
    hardware_pids: tuple[str, ...] = ()
    software_releases: tuple[SoftwareEoxQuestion, ...] = ()
    suggestion_pids: tuple[str, ...] = ()
    compatible_pids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SourceUnavailable:
    """A Cisco source gave no usable answer for this Run.

    Attributes:
        reason: fixed text the operator can be shown, such as
            `Cisco could not be reached: the connection timed out`.
    """

    reason: str


@dataclass(frozen=True, slots=True)
class CiscoPlatform:
    """One `platforms[]` entry in an NX-OS Advisory reply (#126).

    Cisco names the first-fixed releases per platform rather than per Advisory on NX-OS. An
    entry with no name is dropped before it reaches here, so it can never be mistaken for a
    series.

    Attributes:
        name: Cisco's platform name, such as `Cisco Nexus 9000 Series Switches`.
        first_fixed: the first-fixed releases Cisco gives this platform, in the reply's order.
    """

    name: str
    first_fixed: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CiscoAdvisory:
    """One Advisory from openVuln, as the reply names it.

    Attributes:
        advisory_id: Cisco's Advisory id, such as `cisco-sa-iosxe-webui-privesc-j22S`.
        title: the Advisory's title.
        sir: Cisco's Security Impact Rating, as the reply spells it.
        cvss_base_score: the CVSS base score; None when the reply did not give one.
        cves: the CVE ids the reply names.
        first_published: when Cisco first published it, as the reply gives it.
        last_updated: when Cisco last updated it, as the reply gives it.
        first_fixed: the first releases Cisco names as fixed; empty when it names none,
            as NX-OS replies do.
        platforms: the per-platform first fixes an NX-OS reply names; empty otherwise (#126).
    """

    advisory_id: str
    title: str
    sir: str
    cvss_base_score: float | None
    cves: tuple[str, ...]
    first_published: str
    last_updated: str
    first_fixed: tuple[str, ...]
    platforms: tuple[CiscoPlatform, ...] = ()


@dataclass(frozen=True, slots=True)
class AdvisoriesAnswer:
    """openVuln's answer for one release question.

    Attributes:
        question: the question it answers.
        advisories: every Advisory the reply names, in the reply's order.
        unavailable: why Cisco gave no answer for this release alone, as Cisco's error code
            (such as `INVALID_IOS_VERSION`) or `HTTP 404`; None when it answered (#131).
    """

    question: ReleaseQuestion
    advisories: tuple[CiscoAdvisory, ...]
    unavailable: str | None = None


@dataclass(frozen=True, slots=True)
class EoxRecord:
    """One EoX record Cisco returned for a PID or release.

    Attributes:
        input_value: the PID or release Cisco says this record is about.
        input_type: `PID` or `Software`, as the reply names it.
        product_id: the product or software id the record is for.
        description: Cisco's description of it.
        bulletin: the EoX bulletin's number.
        bulletin_url: the bulletin's URL, as Cisco gave it.
        end_of_sale: the end-of-sale date, as Cisco gives it; None when it is not set.
        end_of_sw_maintenance: the end of software maintenance date; None when not set.
        end_of_security_vul_support: the end of security/vulnerability support date.
        last_date_of_support: the last date of support.
        migration_product_id: Cisco's replacement PID; None when it names none.
        migration_url: the replacement product's information URL; None when it names none.
    """

    input_value: str
    input_type: str
    product_id: str
    description: str
    bulletin: str
    bulletin_url: str
    end_of_sale: str | None
    end_of_sw_maintenance: str | None
    end_of_security_vul_support: str | None
    last_date_of_support: str | None
    migration_product_id: str | None
    migration_url: str | None


@dataclass(frozen=True, slots=True)
class EoxUnanswered:
    """One value the EoX lookup got no record for.

    Attributes:
        input_value: the value asked about; None when Cisco did not echo it.
        reason: Cisco's error code, such as `SSA_ERR_026`, or fixed text.
    """

    input_value: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class EoxAnswer:
    """EoX's answer for every hardware or software question sent.

    Attributes:
        records: the EoX records Cisco returned.
        unanswered: the values Cisco had no record for, with its error code.
    """

    records: tuple[EoxRecord, ...]
    unanswered: tuple[EoxUnanswered, ...]


@dataclass(frozen=True, slots=True)
class SuggestedRelease:
    """One release Software Suggestion lists for a PID.

    Attributes:
        release: the release's display name, as Cisco gives it.
        suggested: whether Cisco marks it as suggested.
        release_date: when the release came out; None when the reply does not say.
        train: the release line it belongs to, such as `17.9`; None when not given.
    """

    release: str
    suggested: bool
    release_date: str | None
    train: str | None


@dataclass(frozen=True, slots=True)
class SuggestionAnswer:
    """Software Suggestion's answer for one base PID.

    Attributes:
        product_id: the base PID asked about.
        product_name: Cisco's name for the product, or the PID when it names none.
        releases: every release the reply lists for the product.
    """

    product_id: str
    product_name: str
    releases: tuple[SuggestedRelease, ...]


@dataclass(frozen=True, slots=True)
class SuggestionUnanswered:
    """One base PID Software Suggestion had no answer for.

    Attributes:
        product_id: the base PID asked about.
        reason: Cisco's error code, such as `S3_INV_BASEPID`, or fixed text.
    """

    product_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class SuggestionsAnswer:
    """Software Suggestion's answer for every base PID sent.

    Attributes:
        answers: one answer per PID Cisco knew.
        unanswered: the PIDs Cisco had no answer for, with its error code.
    """

    answers: tuple[SuggestionAnswer, ...]
    unanswered: tuple[SuggestionUnanswered, ...]


@dataclass(frozen=True, slots=True)
class CompatibleRelease:
    """One release Software Suggestion lists as compatible with a chassis PID (#127).

    Attributes:
        release: the release's display name, as Cisco gives it.
        suggested: whether Cisco marks it as suggested.
        train: the release line Cisco's reply names; None when it names none. Analysis uses
            its own Train rule instead of this text.
        lifecycle: Cisco's lifecycle code, such as `ED`; None when the reply names none.
    """

    release: str
    suggested: bool
    train: str | None
    lifecycle: str | None


@dataclass(frozen=True, slots=True)
class CompatibleAnswer:
    """Software Suggestion's compatible-releases answer for one chassis PID (#127).

    Attributes:
        product_id: the chassis PID asked about.
        releases: every release the reply lists for it.
    """

    product_id: str
    releases: tuple[CompatibleRelease, ...] = ()


@dataclass(frozen=True, slots=True)
class CompatibleUnanswered:
    """One chassis PID Software Suggestion had no compatible list for (#127).

    Attributes:
        product_id: the chassis PID asked about.
        reason: Cisco's error code, such as `S3_INV_BASEPID`, or fixed text such as
            `page cap`.
    """

    product_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class CompatibleAnswers:
    """Software Suggestion's compatible lists for every chassis PID sent (#127).

    Attributes:
        answers: one answer per PID Cisco knew.
        unanswered: the PIDs Cisco had no list for, with its error code or fixed reason.
    """

    answers: tuple[CompatibleAnswer, ...] = ()
    unanswered: tuple[CompatibleUnanswered, ...] = ()


@unique
class CiscoEndpoint(Enum):
    """A Cisco endpoint, as the Audit log counts it (story 22)."""

    TOKEN = "token"  # noqa: S105 (an endpoint name, never a secret)
    OPENVULN = "openVuln"
    EOX = "EoX"
    SUGGESTION = "Software Suggestion"
    COMPATIBLE = "Software Suggestion (compatible)"


@unique
class TokenOutcome(Enum):
    """What came of the one token request."""

    OK = "ok"
    REJECTED = "rejected"
    """Cisco refused the key: HTTP 400 `invalid_client`, 401, or an auth 403."""
    UNAVAILABLE = "unavailable"
    """Cisco could not be reached, or answered with something that is not a token."""
    NOT_REQUESTED = "not requested"
    """Nothing was asked, because a question failed its safe-pattern check first."""


@dataclass(frozen=True, slots=True)
class TokenResult:
    """The token request's result, safe to show and to record (ADR 0008).

    It never holds the token, the client ID or the client secret.

    Attributes:
        outcome: ok, rejected, unavailable, or not requested.
        status: the HTTP status Cisco answered with; None when no reply came.
        error_code: Cisco's error code, such as `invalid_client`, when it gave one.
    """

    outcome: TokenOutcome
    status: int | None = None
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class EndpointUse:
    """How much one endpoint was used, for the Audit log's counts (story 22).

    Attributes:
        endpoint: which Cisco endpoint.
        calls: requests sent to it, retries included.
        values: the PIDs or releases its requests carried, each logical call counted once
            and its single retry not counted twice; a paged compatible list counts its PID
            once, however many pages it took. 0 for the token endpoint.
        retries: how many of the calls were the single retry.
        pages: reply pages read from it; 0 for an endpoint asked without paging.
    """

    endpoint: CiscoEndpoint
    calls: int
    values: int
    retries: int
    pages: int = 0


@dataclass(frozen=True, slots=True)
class CiscoCallTally:
    """The Run's Cisco use as counts only: never a value, a client ID or a token.

    Attributes:
        token: the token request's result.
        endpoints: one count per endpoint, in a fixed order.
    """

    token: TokenResult
    endpoints: tuple[EndpointUse, ...]


@dataclass(frozen=True, slots=True)
class CiscoAnswers:
    """Everything `advisories` brings back from Cisco for one Run.

    Each source is either its answer or `SourceUnavailable(reason)`, so a source that was
    down never reads as "nothing found" (stories 52, 118).

    Attributes:
        advisories: one answer or unavailability per distinct release question.
        hardware_eox: the hardware EoX answer, or why there is none.
        software_eox: the software EoX answer, or why there is none.
        suggestions: the Software Suggestion answer, or why there is none.
        tally: the counts the Audit log records.
        compatible: the compatible-releases answer, or why there is none (#127); empty when
            the caller did not ask for one.
    """

    advisories: tuple[AdvisoriesAnswer | SourceUnavailable, ...]
    hardware_eox: EoxAnswer | SourceUnavailable
    software_eox: EoxAnswer | SourceUnavailable
    suggestions: SuggestionsAnswer | SourceUnavailable
    tally: CiscoCallTally
    compatible: CompatibleAnswers | SourceUnavailable = CompatibleAnswers()
