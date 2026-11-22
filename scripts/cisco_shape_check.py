"""Record the SHAPES of Cisco's replies, for ticket #148 (run by the operator, live API Key).

    uv run --locked python -m scripts.cisco_shape_check
    uv run --locked python -m scripts.cisco_shape_check --pid <PID> --release <release>

It makes the handful of read-only calls ticket #148 lists (the token request, then GETs to
openVuln, Software EoX and Software Suggestion) and prints ONE summary block for the operator
to paste back onto the ticket. The summary holds only:

- field names, only from the fixed `KNOWN_FIELDS` list (any other key shows as its length),
- JSON types, string lengths, array and object sizes, and counts,
- HTTP status codes, and Cisco error codes only from the fixed `ALLOWED_CODES` list (any other
  error string shows as `<unrecognised code, length N>`),
- booleans and counts about release and date fields (a dotted form, a codename prefix, which
  fixed date format), and which of a fixed list of Nexus family spellings a reply used,
- for the licence-slash `%2F` question, the HTTP status and error code, as for every other call
  (the status is not a value, and a bare "2xx: no" cannot tell an unknown PID from an encoding
  refusal).

It never prints a value from a reply, a PID, a release string, a date, a hostname or an
address. By default every PID and release it sends is a synthetic sample from this file. The
operator may add a real PID and release with `--pid` and `--release` to see a successful
reply's shape; they are sent but never printed.

How it stays inside the fence: it reuses the tool's own `advisories` Session (the token
request, pacing, the one retry, the fenced `HttpsTransport` with Cisco's certificate checked
against the Windows store) and adds a second gate, `FencedTransport`, that refuses any call
that is not the token POST to `id.cisco.com` or a GET to `apix.cisco.com` on an openVuln, EoX
or Software Suggestion path. No second HTTP client is written here.

How it reads the key: exactly as a Run does. It takes the data folder's single-instance lock,
checks the Backup Passphrase against the check file at the masked prompt, unlocks
`cisco-key.age` with it and wipes the passphrase. The key is never an option, an environment
variable or a file the script reads, and neither it, the token, the passphrase nor any Cisco
reply is written to disk, a log or the console. Everything printed passes the secret scan.
"""

import argparse
import faulthandler
import json
import re
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from enum import Enum, unique
from typing import Final, NoReturn, override

from network_analyser import backup_store
from network_analyser._version import __version__
from network_analyser.advisories import (
    API_HOST,
    TOKEN_HOST,
    HttpRequest,
    HttpResponse,
    HttpsTransport,
    Pacer,
    ProxyConfig,
    Transport,
    TransportFailed,
    is_safe_pid,
    is_safe_release,
)
from network_analyser.advisories.fence import TOKEN_PATH, is_fenced
from network_analyser.advisories.patterns import wire_pid
from network_analyser.advisories.session import Call, Session
from network_analyser.advisories.transport import header
from network_analyser.backup_store import CiscoKey
from network_analyser.cli import run_secrets
from network_analyser.cli.console import scanned_console
from network_analyser.cli.crash import describe_internal_error, install_crash_hooks
from network_analyser.cli.crash_dump_guard import guard_crash_dumps
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.prompts import Prompter
from network_analyser.cli.run_folder import (
    RefusedError,
    find_data_folder,
    fixed_message,
    hold_instance_lock,
)
from network_analyser.cli.trust_folder import check_trust_folder
from network_analyser.credentials import Secret, SecretScan
from network_analyser.records.cisco import CiscoEndpoint, CiscoOsType, TokenOutcome

SAMPLE_PID: Final = "SYNTH-PID-1"
"""A synthetic PID Cisco cannot know: the unknown-PID error shape."""

SAMPLE_SLASH_PID: Final = "SYNTH-PID-2/K9"
"""A synthetic PID with a licence suffix, for the `%2F` question."""

SAMPLE_RELEASE: Final = "1.2.3"
"""A synthetic release Cisco cannot know: the unknown-release error shape."""

SAMPLE_RELEASE_2: Final = "1.2.4"
"""A second synthetic release, so a comma-joined or `input2` form has two values."""

SAMPLE_NEXUS_ALIAS: Final = "NEXUS9000"
"""The `platformAlias` openVuln needs for an NX-OS question."""

ALLOWED_CODES: Final = frozenset(
    {
        "INVALID_IOS_VERSION",
        "NO_DATA_FOUND",
        "S3_INV_BASEPID",
        "SSA_ERR_026",
        "ERR_403_SERVICE_OVER_QPS",
        "ERR_403_SERVICE_OVER_RATE",
        "ERR_403_DEVELOPER_OVER_QPS",
        "ERR_403_DEVELOPER_OVER_RATE",
        "ERR_403_NOT_AUTHORIZED",
        "ERR_403_DEVELOPER_INACTIVE",
        "invalid_client",
        # Inferred from the lengths (21 and 20) in the first live run, not yet seen by name.
        # A name is printed only when it matches exactly, so a wrong guess shows as its length.
        "INVALID_IOSXE_VERSION",
        "INVALID_NXOS_VERSION",
    }
)
"""The only error strings the summary may print. Any other shows as its length only.

To learn a code's name, add it here deliberately and run again: a reply never decides what is
printed.
"""

KNOWN_REASONS: Final = frozenset(
    {
        "Cisco did not answer in time",
        "Cisco's certificate was not trusted",
        "Cisco's name was not found",
        "Cisco's reply could not be read",
        "Cisco rate limited the calls",
        "Cisco asked for a long wait",
        "Cisco rejected the API key",
        "Cisco did not give the tool a token",
        "Cisco's token reply was not understood",
        "the connection to Cisco failed",
        "the connection to Cisco was refused",
        "the secure connection to Cisco failed",
        "the reply was larger than the tool accepts",
        "refused a host outside the Cisco fence",
        "refused a request path the tool did not build",
    }
)
"""The tool's own fixed reasons for a call with no usable reply: the only text printed."""

_REASON_PATTERNS: Final = (
    re.compile(r"Cisco returned HTTP \d{3}", re.ASCII),
    re.compile(r"refused a redirect \(HTTP \d{3}\)", re.ASCII),
)

_OUTSIDE_FENCE: Final = (
    "refused a call outside the Cisco fence: only the token POST and the read-only GETs"
)
_GET_PREFIXES: Final = (
    "/security/advisories/v2/OSType/",
    "/supporttools/eox/rest/5/",
    "/software/suggestion/v2/suggestions/",
)
_NO_CHECK_FILE: Final = "no Backup Passphrase has been set yet: the first Run sets it"
_NO_KEY: Final = "No Cisco API key is stored. Add one with `network-analyser cisco-key set`."
_CODE_KEYS: Final = frozenset({"errorCode", "ErrorCode", "ErrorID", "error", "code"})
_CODE_KEY_PATTERN: Final = re.compile(r"(?:SSA_ERR|S3)_[A-Za-z0-9_]{1,60}", re.ASCII)
KNOWN_FIELDS: Final = frozenset(
    {
        # What ticket #148 asks about.
        "releaseFormat1",
        "releaseFormat2",
        "relDispName",
        "releaseDate",
        "platforms",
        "name",
        "isSuggested",
        # What `advisories/replies.py` reads from openVuln, Software EoX and Suggestion.
        "advisories",
        "advisoryId",
        "advisoryTitle",
        "sir",
        "cvssBaseScore",
        "cves",
        "firstPublished",
        "lastUpdated",
        "firstFixed",
        "firstFixes",
        "EOXRecord",
        "EOXInputValue",
        "EOXInputType",
        "EOLProductID",
        "EOXMigrationDetails",
        "ProductIDDescription",
        "ProductBulletinNumber",
        "LinkToProductBulletinURL",
        "EndOfSaleDate",
        "EndOfSWMaintenanceReleases",
        "EndOfSecurityVulSupportDate",
        "LastDateOfSupport",
        "MigrationProductId",
        "MigrationProductInfoURL",
        "value",
        "dateFormat",
        "PaginationResponseRecord",
        "LastIndex",
        "PageIndex",
        "paginationResponseRecord",
        "lastIndex",
        "pageIndex",
        "suggestions",
        "suggestedReleases",
        "releases",
        "productList",
        "products",
        "product",
        "basePID",
        "productName",
        "release",
        "releaseTrain",
        "trainDispName",
        "releaseLifeCycle",
        # Error shapes.
        "errorDetailsResponse",
        "errorCode",
        "ErrorCode",
        "ErrorID",
        "ErrorDescription",
        "EOXError",
        "error",
        "errorMessage",
        "code",
    }
)
"""The only JSON keys the summary may print: Cisco's documented field names.

A reply is untrusted text. A key can be a PID, a release or an estate-specific string, and the
summary is pasted onto a public issue, so any key not listed here shows as
`<field name, length N>`, whatever it looks like. To learn a new field's name, add it here
deliberately and run again.
"""
_RELEASE_FIELDS: Final = ("releaseFormat1", "releaseFormat2", "relDispName")
_MASHERY_CODE: Final = "X-Mashery-Error-Code"
_MAX_DEPTH: Final = 8
_MAX_ITEMS: Final = 200
_MAX_SHAPE_LINES: Final = 60
_DOTTED: Final = re.compile(r"\d{1,3}\.\d{1,3}(?:\.\d{1,3}[A-Za-z0-9]*)?", re.ASCII)
_PAREN: Final = re.compile(r"\d{1,3}\.\d{1,3}\(\d{1,3}[A-Za-z0-9]*\)[A-Za-z0-9.()]*", re.ASCII)
_CODENAME: Final = re.compile(r"[A-Za-z]+-\d", re.ASCII)
_DATE_SHAPES: Final = (
    (re.compile(r"\d{4}-\d{2}-\d{2}", re.ASCII), "YYYY-MM-DD"),
    (
        re.compile(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", re.ASCII
        ),
        "YYYY-MM-DDTHH:MM:SS",
    ),
    (re.compile(r"\d{2}/\d{2}/\d{4}", re.ASCII), "NN/NN/YYYY"),
    (re.compile(r"\d{4}/\d{2}/\d{2}", re.ASCII), "YYYY/MM/DD"),
    (re.compile(r"\d{1,2}-[A-Za-z]{3}-\d{4}", re.ASCII), "D-Mon-YYYY"),
    (re.compile(r"[A-Za-z]{3} \d{1,2}, \d{4}", re.ASCII), "Mon D, YYYY"),
)
_FAMILIES: Final = ("3000", "3500", "5500", "5600", "7700", "9000")
_PLATFORM_CANDIDATES: Final = frozenset(
    spelling
    for family in _FAMILIES
    for spelling in (
        f"Nexus {family}",
        f"Nexus {family} Series",
        f"NEXUS{family}",
        f"Nexus{family}",
    )
)
"""Fixed spellings of a Nexus family. A reply is only ever compared with these: the summary
says which of them a `platforms[].name` equalled, never the name itself."""


class OutsideFenceError(Exception):
    """A call outside the Cisco fence was about to be made, so the script stopped."""


@dataclass(frozen=True, slots=True)
class FencedTransport:
    """A second gate in front of the tool's transport: the token POST and read-only GETs only.

    Attributes:
        inner: the transport that makes the call, the tool's own `HttpsTransport` in a real
            run and the fake Cisco in a test.
    """

    inner: Transport

    def __call__(self, request: HttpRequest) -> HttpResponse | TransportFailed:
        """Pass the call on, or raise `OutsideFenceError` before anything is dialled."""
        if not _inside_fence(request):
            raise OutsideFenceError(_OUTSIDE_FENCE)
        return self.inner(request)


def _inside_fence(request: HttpRequest) -> bool:
    if not is_fenced(request.host, request.port):
        return False
    if request.method == "POST":
        return request.host == TOKEN_HOST and request.path == TOKEN_PATH
    return (
        request.method == "GET"
        and request.host == API_HOST
        and request.path.startswith(_GET_PREFIXES)
    )


@dataclass(frozen=True, slots=True)
class Inputs:
    """What the operator may add to the synthetic samples. Sent, never printed.

    Attributes:
        pid: a real PID to ask Software Suggestion, the compatible list and so on about.
        release: a real release to ask openVuln and Software EoX about.
        release_os: the OS type `release` belongs to, for openVuln.
    """

    pid: str | None = None
    release: str | None = None
    release_os: CiscoOsType = CiscoOsType.IOS


@unique
class Kind(Enum):
    """What extra to say about a reply, beyond its generic shape."""

    ADVISORIES = "advisories"
    EOX = "eox"
    SUGGESTIONS = "suggestions"
    COMPATIBLE = "compatible"
    SLASH = "slash"


@dataclass(frozen=True, slots=True)
class Probe:
    """One call to make.

    Attributes:
        label: fixed text naming the call; never holds a value sent.
        endpoint: which Cisco endpoint it counts against.
        path: the path and query. Every value in it passed the tool's own pattern.
        kind: what extra to say about the reply.
        sent: the PIDs or releases the call carries, only to compare with what comes back.
    """

    label: str
    endpoint: CiscoEndpoint
    path: str
    kind: Kind
    sent: tuple[str, ...] = ()


def _advisory_probe(os_type: CiscoOsType, release: str, what: str) -> Probe:
    path = f"/security/advisories/v2/OSType/{os_type.value}?version={release}"
    if os_type is CiscoOsType.NX_OS:
        path = f"{path}&platformAlias={SAMPLE_NEXUS_ALIAS}"
    return Probe(f"openVuln {os_type.value}, {what}", CiscoEndpoint.OPENVULN, path, Kind.ADVISORIES)


def build_probes(inputs: Inputs) -> tuple[Probe, ...]:
    """Return the calls to make, in order: openVuln, Software EoX, then Software Suggestion."""
    probes = [
        _advisory_probe(os_type, SAMPLE_RELEASE, "synthetic unknown release")
        for os_type in CiscoOsType
    ]
    if inputs.release is not None:
        probes.append(_advisory_probe(inputs.release_os, inputs.release, "operator release"))
    probes.extend(_eox_probes(inputs))
    probes.extend(_suggestion_probes(inputs))
    return tuple(probes)


def _eox_probes(inputs: Inputs) -> list[Probe]:
    release = inputs.release or SAMPLE_RELEASE
    whose = "operator release" if inputs.release else "synthetic release"
    base = "/supporttools/eox/rest/5/EOXBySWReleaseString/1"
    both = (release, SAMPLE_RELEASE_2)
    probes = [
        Probe(
            f"software EoX, path form, two releases comma-joined ({whose})",
            CiscoEndpoint.EOX,
            f"{base}/{release},{SAMPLE_RELEASE_2}",
            Kind.EOX,
            both,
        ),
        Probe(
            f"software EoX, query form input1 and input2 as release,IOS ({whose})",
            CiscoEndpoint.EOX,
            f"{base}?input1={release},IOS&input2={SAMPLE_RELEASE_2},IOS",
            Kind.EOX,
            both,
        ),
        Probe(
            f"software EoX, query form input1 as a bare release ({whose})",
            CiscoEndpoint.EOX,
            f"{base}?input1={release}",
            Kind.EOX,
            (release,),
        ),
        Probe(
            "hardware EoX, PID with a licence slash sent as %2F (synthetic PID)",
            CiscoEndpoint.EOX,
            f"/supporttools/eox/rest/5/EOXByProductID/1/{wire_pid(SAMPLE_SLASH_PID)}",
            Kind.SLASH,
        ),
    ]
    # Cisco's documented IOS-XE OS type is `IOS-XE`; the probes above send `IOS`.
    probes.extend(
        [
            Probe(
                f"software EoX, query form input1 as release,IOS-XE ({whose})",
                CiscoEndpoint.EOX,
                f"{base}?input1={release},IOS-XE",
                Kind.EOX,
                (release,),
            ),
            Probe(
                f"software EoX, path form, release,IOS-XE ({whose})",
                CiscoEndpoint.EOX,
                f"{base}/{release},IOS-XE",
                Kind.EOX,
                (release,),
            ),
        ]
    )
    probes.extend(
        [
            Probe(
                "hardware EoX, synthetic slash PID in the query form, raw slash",
                CiscoEndpoint.EOX,
                f"/supporttools/eox/rest/5/EOXByProductID/1?input1={SAMPLE_SLASH_PID}",
                Kind.EOX,
                (SAMPLE_SLASH_PID,),
            ),
            Probe(
                "hardware EoX, synthetic slash PID in the query form, %2F",
                CiscoEndpoint.EOX,
                f"/supporttools/eox/rest/5/EOXByProductID/1?input1={wire_pid(SAMPLE_SLASH_PID)}",
                Kind.EOX,
                (SAMPLE_SLASH_PID,),
            ),
        ]
    )
    if inputs.pid is not None:
        # Cisco's Suggestion API asks for a `basePID`: the PID without the licence suffix.
        base = inputs.pid.split("/", 1)[0]
        if base != inputs.pid:
            probes.append(
                Probe(
                    "hardware EoX, operator base PID without the licence suffix",
                    CiscoEndpoint.EOX,
                    f"/supporttools/eox/rest/5/EOXByProductID/1/{wire_pid(base)}",
                    Kind.EOX,
                    (base,),
                )
            )
        # The production hardware path (`advisories/lookup.py`), with the operator's own PID,
        # then the same PID in the query form, raw and encoded.
        probes.extend(
            [
                Probe(
                    "hardware EoX, operator PID as the tool sends it",
                    CiscoEndpoint.EOX,
                    f"/supporttools/eox/rest/5/EOXByProductID/1/{wire_pid(inputs.pid)}",
                    Kind.EOX,
                    (inputs.pid,),
                ),
                Probe(
                    "hardware EoX, operator PID in the query form, raw slash",
                    CiscoEndpoint.EOX,
                    f"/supporttools/eox/rest/5/EOXByProductID/1?input1={inputs.pid}",
                    Kind.EOX,
                    (inputs.pid,),
                ),
                Probe(
                    "hardware EoX, operator PID in the query form, %2F",
                    CiscoEndpoint.EOX,
                    f"/supporttools/eox/rest/5/EOXByProductID/1?input1={wire_pid(inputs.pid)}",
                    Kind.EOX,
                    (inputs.pid,),
                ),
            ]
        )
    return probes


def _suggestion_probes(inputs: Inputs) -> list[Probe]:
    releases = "/software/suggestion/v2/suggestions/releases/productIds/"
    compatible = "/software/suggestion/v2/suggestions/compatible/productId/"
    probes = [
        Probe(
            "Software Suggestion, unknown PID (synthetic)",
            CiscoEndpoint.SUGGESTION,
            f"{releases}{SAMPLE_PID}",
            Kind.SUGGESTIONS,
        ),
        Probe(
            "Software Suggestion, PID with a licence slash sent as %2F (synthetic PID)",
            CiscoEndpoint.SUGGESTION,
            f"{releases}{wire_pid(SAMPLE_SLASH_PID)}",
            Kind.SLASH,
        ),
        Probe(
            "Software Suggestion compatible list, unknown PID (synthetic)",
            CiscoEndpoint.COMPATIBLE,
            f"{compatible}{SAMPLE_PID}?pageIndex=1",
            Kind.COMPATIBLE,
        ),
    ]
    if inputs.pid is not None:
        pid = wire_pid(inputs.pid)
        base = inputs.pid.split("/", 1)[0]
        if base != inputs.pid:
            probes.append(
                Probe(
                    "Software Suggestion, operator base PID without the licence suffix",
                    CiscoEndpoint.SUGGESTION,
                    f"{releases}{base}",
                    Kind.SUGGESTIONS,
                )
            )
        probes.extend(
            [
                Probe(
                    "Software Suggestion, operator PID",
                    CiscoEndpoint.SUGGESTION,
                    f"{releases}{pid}",
                    Kind.SUGGESTIONS,
                ),
                Probe(
                    "Software Suggestion compatible list, operator PID, page 1",
                    CiscoEndpoint.COMPATIBLE,
                    f"{compatible}{pid}?pageIndex=1",
                    Kind.COMPATIBLE,
                ),
            ]
        )
    return probes


# -- the summary ------------------------------------------------------------------------------


def collect_summary(session: Session, inputs: Inputs) -> str:
    """Make every call through `session` and return the summary block: shapes, never values."""
    lines = [
        f"=== Cisco reply shapes for ticket #148 (network-analyser {__version__}) ===",
        "Shapes only: no value from a reply, PID, release, date or name is printed.",
        "Operator PID given: "
        + _yes(inputs.pid is not None)
        + "; operator release given: "
        + _yes(inputs.release is not None)
        + f" (release OS type: {inputs.release_os.value})",
    ]
    token = session.token()
    lines.append(
        f"token request (id.cisco.com): {token.outcome.value}; HTTP {_status(token.status)}; "
        f"error code: {_code(token.error_code)}"
    )
    if token.outcome is not TokenOutcome.OK:
        lines.append("No API call was made, because the token request did not succeed.")
    else:
        for number, probe in enumerate(build_probes(inputs), start=1):
            call = session.get(
                probe.endpoint,
                probe.path,
                values=len(probe.sent) or 1,
                pages=1 if probe.endpoint is CiscoEndpoint.COMPATIBLE else 0,
            )
            lines.extend(_describe(number, probe, call))
    lines.extend(_tally(session))
    lines.append("=== end of summary ===")
    return "\n".join(lines).encode("ascii", "replace").decode("ascii")


def _yes(value: bool) -> str:  # noqa: FBT001 (a tiny formatter, called with a plain boolean)
    return "yes" if value else "no"


def _status(status: int | None) -> str:
    return "none" if status is None else str(status)


def _code(code: str | None) -> str:
    if code is None:
        return "none"
    return code if code in ALLOWED_CODES else f"<unrecognised code, length {len(code)}>"


def _reason(reason: str) -> str:
    if reason in KNOWN_REASONS or any(pattern.fullmatch(reason) for pattern in _REASON_PATTERNS):
        return reason
    return f"<unrecognised reason, length {len(reason)}>"


def _tally(session: Session) -> list[str]:
    lines = ["call counts (no value, counts only):"]
    lines.extend(
        f"  {use.endpoint.value}: {use.calls} calls, {use.values} values, {use.retries} retries, "
        f"{use.pages} pages"
        for use in session.tally().endpoints
    )
    return lines


def _describe(number: int, probe: Probe, call: Call) -> list[str]:
    lines = [f"[{number}] {probe.label}"]
    response = call.response
    if response is None:
        lines.append(f"    {call.outcome.value}; no reply ({_reason(call.reason)})")
        return lines
    lines.append(
        f"    {call.outcome.value}; HTTP {response.status}; reply {len(response.body)} bytes"
    )
    mashery = header(response, _MASHERY_CODE)
    if mashery is not None:
        lines.append(f"    {_MASHERY_CODE} header: {_code(mashery)}")
    parsed, document = _parse(response.body)
    if not parsed:
        lines.append("    reply is JSON: no")
        return lines
    lines.append(f"    reply is JSON: yes ({_json_type(document)})")
    lines.extend(_code_lines(document))
    if probe.kind is Kind.EOX:
        lines.extend(_eox_lines(document, probe.sent))
    if probe.kind in {Kind.SUGGESTIONS, Kind.COMPATIBLE}:
        lines.extend(_release_lines(document))
    lines.extend(_shape_lines(document))
    return lines


def _parse(body: bytes) -> tuple[bool, object]:
    try:
        return True, json.loads(body)
    except ValueError, RecursionError:
        return False, None


def _json_type(value: object) -> str:  # noqa: PLR0911 (one return per JSON type)
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def _objects(value: object, depth: int = 0) -> Iterator[dict[str, object]]:
    if depth > _MAX_DEPTH:
        return
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _objects(item, depth + 1)
    elif isinstance(value, list):
        for item in value[:_MAX_ITEMS]:
            yield from _objects(item, depth + 1)


# -- error codes ------------------------------------------------------------------------------


def _code_lines(document: object) -> list[str]:
    found: Counter[str] = Counter()
    for obj in _objects(document):
        for key, item in obj.items():
            if key in _CODE_KEYS and isinstance(item, str):
                found[_code(item)] += 1
            elif _CODE_KEY_PATTERN.fullmatch(key):
                found[_code(key)] += 1
    if not found:
        return []
    shown = ", ".join(f"{code} x{count}" for code, count in sorted(found.items()))
    return [f"    error codes in the body: {shown}"]


# -- Software EoX -----------------------------------------------------------------------------


def _eox_lines(document: object, sent: tuple[str, ...]) -> list[str]:
    records = document.get("EOXRecord") if isinstance(document, dict) else None
    if not isinstance(records, list):
        return ["    EOXRecord: not an array"]
    exact = contains = unrelated = absent = 0
    for record in records:
        value = record.get("EOXInputValue") if isinstance(record, dict) else None
        if not isinstance(value, str):
            absent += 1
        elif value in sent:
            exact += 1
        elif any(release in value for release in sent):
            contains += 1
        else:
            unrelated += 1
    echo = (
        f"    EOXInputValue: equals a value sent {exact}, contains one but differs {contains}, "
        f"unrelated {unrelated}, absent or not text {absent}"
    )
    return [f"    EOXRecord: {len(records)} records for {len(sent)} values sent", echo]


# -- release, date and platform fields --------------------------------------------------------


def _release_lines(document: object) -> list[str]:
    objects = list(_objects(document))
    lines = [f"    objects in the reply: {len(objects)}"]
    for name in _RELEASE_FIELDS:
        values = [obj[name] for obj in objects if name in obj]
        texts = [value for value in values if isinstance(value, str)]
        if not values:
            lines.append(f"    {name}: absent from every object")
            continue
        lines.append(
            f"    {name}: in {len(values)} objects, {len(texts)} text; "
            f"dotted form {_count(texts, _DOTTED)}; paren form {_count(texts, _PAREN)}; "
            f"codename prefix {_count_search(texts, _CODENAME)}; "
            f"matches the tool's release pattern {sum(map(is_safe_release, texts))} of "
            f"{len(texts)}"
        )
    lines.extend(_date_lines(objects))
    lines.extend(_platform_lines(objects))
    return lines


def _count(texts: list[str], pattern: re.Pattern[str]) -> str:
    return f"{sum(1 for text in texts if pattern.fullmatch(text))} of {len(texts)}"


def _count_search(texts: list[str], pattern: re.Pattern[str]) -> str:
    return f"{sum(1 for text in texts if pattern.match(text))} of {len(texts)}"


def _date_shape(value: object) -> str:
    if not isinstance(value, str):
        return "not text"
    if value == "":
        return "empty text"
    return next((label for pattern, label in _DATE_SHAPES if pattern.fullmatch(value)), "other")


def _date_lines(objects: list[dict[str, object]]) -> list[str]:
    shapes = Counter(_date_shape(obj["releaseDate"]) for obj in objects if "releaseDate" in obj)
    if not shapes:
        return ["    releaseDate: absent from every object"]
    shown = ", ".join(f"{label} x{count}" for label, count in sorted(shapes.items()))
    return [f"    releaseDate format: {shown}"]


def _platform_lines(objects: list[dict[str, object]]) -> list[str]:
    names: list[str] = []
    for obj in objects:
        platforms = obj.get("platforms")
        if isinstance(platforms, list):
            names.extend(
                item["name"]
                for item in platforms[:_MAX_ITEMS]
                if isinstance(item, dict) and isinstance(item.get("name"), str)
            )
    if not names:
        return ["    platforms[].name: none in the reply"]
    matched = sorted(_PLATFORM_CANDIDATES.intersection(names))
    others = sum(1 for name in names if name not in _PLATFORM_CANDIDATES)
    low, high = min(map(len, names)), max(map(len, names))
    shown = ", ".join(matched) or "none"
    line = (
        f"    platforms[].name: {len(names)} names, length {low}-{high}; equal to a fixed "
        f"Nexus candidate: {shown}; equal to none of them: {others}"
    )
    return [line]


# -- the generic shape ------------------------------------------------------------------------


@dataclass(slots=True)
class _Range:
    low: int | None = None
    high: int | None = None

    def add(self, number: int) -> None:
        self.low = number if self.low is None else min(self.low, number)
        self.high = number if self.high is None else max(self.high, number)

    def text(self) -> str:
        return str(self.low) if self.low == self.high else f"{self.low}-{self.high}"


@dataclass(slots=True)
class _Stat:
    types: Counter[str] = field(default_factory=Counter)
    lengths: _Range = field(default_factory=_Range)
    sizes: _Range = field(default_factory=_Range)


def _field_name(key: str) -> str:
    return key if key in KNOWN_FIELDS else f"<field name, length {len(key)}>"


def _walk(value: object, path: str, stats: dict[str, _Stat], depth: int) -> None:
    stat = stats.setdefault(path, _Stat())
    stat.types[_json_type(value)] += 1
    if isinstance(value, str):
        stat.lengths.add(len(value))
    elif isinstance(value, list):
        stat.sizes.add(len(value))
        if depth < _MAX_DEPTH:
            for item in value[:_MAX_ITEMS]:
                _walk(item, f"{path}[]", stats, depth + 1)
    elif isinstance(value, dict):
        stat.sizes.add(len(value))
        if depth < _MAX_DEPTH:
            for key, item in value.items():
                _walk(item, f"{path}.{_field_name(key)}", stats, depth + 1)


def _shape_lines(document: object) -> list[str]:
    stats: dict[str, _Stat] = {}
    _walk(document, "$", stats, 0)
    lines = ["    shape (path: JSON types seen, with string lengths and container sizes):"]
    for path, stat in list(stats.items())[:_MAX_SHAPE_LINES]:
        types = " + ".join(f"{kind} x{count}" for kind, count in sorted(stat.types.items()))
        extra = ""
        if stat.lengths.low is not None:
            extra += f", length {stat.lengths.text()}"
        if stat.sizes.low is not None:
            extra += f", size {stat.sizes.text()}"
        lines.append(f"      {path}: {types}{extra}")
    if len(stats) > _MAX_SHAPE_LINES:
        lines.append(f"      ... {len(stats) - _MAX_SHAPE_LINES} more paths not shown")
    return lines


# -- the command ------------------------------------------------------------------------------


class _FixedParser(argparse.ArgumentParser):
    """An argument parser whose refusals never echo what the operator typed."""

    @override
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        print(f"{self.prog}: refused: the command line was not accepted.", file=sys.stderr)
        raise SystemExit(ExitCode.REFUSED)


def _pid(text: str) -> str:
    if not is_safe_pid(text):
        msg = "not a PID shape the tool may send"
        raise argparse.ArgumentTypeError(msg)
    return text


def _release(text: str) -> str:
    if not is_safe_release(text):
        msg = "not a release shape the tool may send"
        raise argparse.ArgumentTypeError(msg)
    return text


def _proxy(text: str) -> str:
    try:
        ProxyConfig.explicit(text)
    except ValueError:
        msg = "must be host:port"
        raise argparse.ArgumentTypeError(msg) from None
    return text


def _parser() -> argparse.ArgumentParser:
    parser = _FixedParser(
        prog="python -m scripts.cisco_shape_check",
        description="Record the shapes of Cisco's replies for ticket #148. Prints no value.",
    )
    parser.add_argument(
        "--pid",
        type=_pid,
        metavar="PID",
        help="a real PID to ask Software Suggestion about; sent, never printed",
    )
    parser.add_argument(
        "--release",
        type=_release,
        metavar="RELEASE",
        help="a real release to ask openVuln and Software EoX about; sent, never printed",
    )
    parser.add_argument(
        "--release-os",
        choices=[os_type.value for os_type in CiscoOsType],
        default=CiscoOsType.IOS.value,
        help="the OS type of --release for openVuln (default: ios)",
    )
    parser.add_argument(
        "--proxy",
        type=_proxy,
        metavar="HOST:PORT",
        help="HTTP proxy for Cisco (default: Windows' own proxy setting)",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    transport: Transport | None = None,
    pacer: Pacer | None = None,
) -> int:
    """Run the check and return an exit code.

    Args:
        argv: the arguments after the program name; None reads `sys.argv`.
        transport: the transport that makes the calls. A seam for tests; the real fenced
            HTTPS transport by default.
        pacer: paces the calls. A seam for tests, so none waits.
    """
    try:
        args = _parser().parse_args(argv)
    except SystemExit as stop:
        return int(stop.code or 0)
    scan = SecretScan()
    with scanned_console(scan):
        try:
            return _run(args, scan, transport, pacer)
        except RefusedError as error:
            print(f"cisco_shape_check: refused: {fixed_message(error)}", file=sys.stderr)
            return ExitCode.REFUSED
        except OutsideFenceError:
            print(f"cisco_shape_check: {_OUTSIDE_FENCE}.", file=sys.stderr)
            return ExitCode.REFUSED
        except KeyboardInterrupt, EOFError:
            print("Cancelled.", file=sys.stderr)
            return ExitCode.STOPPED
        except Exception as error:  # noqa: BLE001 (the top-level handler: type only, never text)
            print(describe_internal_error(error), file=sys.stderr)
            return ExitCode.INTERNAL_ERROR


def _run(
    args: argparse.Namespace,
    scan: SecretScan,
    transport: Transport | None,
    pacer: Pacer | None,
) -> int:
    inputs = Inputs(pid=args.pid, release=args.release, release_os=CiscoOsType(args.release_os))
    proxy = ProxyConfig.explicit(args.proxy) if args.proxy else ProxyConfig()
    for value in (args.pid, args.release):
        if value is not None:
            scan.watch(Secret(value))
    data = find_data_folder()
    with hold_instance_lock(data):
        check_trust_folder(data)
        if not data.check_file.exists():
            raise RefusedError(_NO_CHECK_FILE)
        if not data.cisco_key_file.is_file():
            raise RefusedError(_NO_KEY)
        ask = Prompter.for_this_process()
        if not guard_crash_dumps(ask):
            return ExitCode.REFUSED
        passphrase = run_secrets.backup_passphrase(data.check_file, ask)
        if isinstance(passphrase, ExitCode):
            return passphrase
        passphrase.add_to_scan(scan)
        key = backup_store.unlock_key_file(data.cisco_key_file, passphrase)
        passphrase.wipe()
        if key is None:
            print(backup_store.KEY_LOCKED_ELSEWHERE, file=sys.stderr)
            return ExitCode.NEEDS_ATTENTION
        key.add_to_scan(scan)
        try:
            ask.say(
                "Asking Cisco (read-only calls, about a minute; nothing is printed until done)..."
            )
            summary = _collect(
                key, inputs, transport=transport, pacer=pacer, proxy=proxy, scan=scan
            )
        finally:
            key.wipe()
    print(summary)
    return ExitCode.CLEAN


def _collect(  # noqa: PLR0913 (the one place every dependency is named)
    key: CiscoKey,
    inputs: Inputs,
    *,
    transport: Transport | None,
    pacer: Pacer | None,
    proxy: ProxyConfig,
    scan: SecretScan,
) -> str:
    inner = transport if transport is not None else HttpsTransport(proxy=proxy)
    session = Session(
        key.client_id,
        key.client_secret,
        transport=FencedTransport(inner),
        pacer=pacer,
        scan=scan,
    )
    return collect_summary(session, inputs)


if __name__ == "__main__":
    faulthandler.disable()
    install_crash_hooks()
    sys.exit(main())
