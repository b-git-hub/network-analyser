"""Release shapes: the family table, normalisation, the Train and an NX-OS hardware family.

The family table decided on #78 is keyed on what `show version` names, never on a guess from
the Platform alone: classic IOS and IOS-XE share one command set, so the release shape tells
them apart. Only three families are ever looked up (stories 44-45):

- classic IOS, such as `15.2(7)E4` and `12.2(55)SE7`;
- IOS-XE, such as `16.9.1`, `17.9.4a` and `26.1.1`;
- NX-OS, such as `9.3(10)` and `7.0(3)I7(9)`.

NX-OS in ACI mode (`14.2(4i)`, `15.2(3e)`), IOS-XR and any other shape are not in the table,
so they are never matched: the device gets a "could not check" Finding instead. IOS-XR never
reaches Analysis, because it is not a supported Platform. The fields Analysis holds can tell an
NX-OS ACI-mode release from a plain NX-OS one, and an IOS-XE SD-WAN controller release (`20.x`)
from an IOS-XE one, but a cEdge SD-WAN device looks exactly like an IOS-XE device; the family
table keeps its three entries either way.

A device's release is normalised before it is looked up: the NX-OS `[build ...]` suffix is
dropped and IOS-XE zero padding is stripped (`16.09.01` becomes `16.9.1`), so a formatting
difference never hides an Advisory (story 45).
"""

import re
from typing import Final

from network_analyser.records.analysis import OsType
from network_analyser.records.platform import Platform
from network_analyser.records.unknown import Unknown

_BUILD_SUFFIX: Final = re.compile(r"\s*\[build[^\]]*\]", re.IGNORECASE)
_ZERO_PADDED: Final = re.compile(r"^0+([0-9][a-z]*)$")
_COMPONENT: Final = re.compile(r"[0-9]+[a-z]*|[A-Za-z]+")

# NX-OS in ACI mode names its releases `major.minor(patch letter)`, such as `14.2(4i)`.
_ACI_MODE: Final = re.compile(r"1[1-7]\.[0-9]{1,2}\([0-9]{1,3}[a-z][a-z0-9]{0,4}\)")
# Plain NX-OS: `9.3(10)`, `6.2(16)`, `7.0(3)I7(9)`.
_NXOS: Final = re.compile(
    r"(?:[4-9]|10)\.[0-9]{1,2}\([0-9]{1,3}\)(?:[A-Z][0-9]{1,3}\([0-9]{1,3}\))*"
)
# Classic IOS: a parenthesised maintenance rebuild, then a Train letter, such as `15.2(7)E4`.
_CLASSIC_IOS: Final = re.compile(r"[0-9]{1,2}\.[0-9]{1,2}\([0-9]{1,3}\)[A-Za-z]{1,3}[0-9]{0,3}")
# IOS-XE: dotted releases 16.x through 19.x and from 26.x on, such as `17.9.4a`.
_IOS_XE: Final = re.compile(r"(?:1[6-9]|2[6-9]|[3-9][0-9])\.[0-9]{1,2}\.[0-9]{1,3}[a-z]{0,2}")
# The Nexus hardware families openVuln matches NX-OS on, from the model `show version` names.
_NEXUS_FAMILIES: Final = (
    (re.compile(r"\bN9K-|\bNexus ?9000\b", re.IGNORECASE), "NEXUS9000"),
    (re.compile(r"\bN7K-|\bNexus ?7000\b", re.IGNORECASE), "NEXUS7000"),
    (re.compile(r"\bN77-|\bNexus ?7700\b", re.IGNORECASE), "NEXUS7700"),
    (re.compile(r"\bN5K-|\bNexus ?5000\b", re.IGNORECASE), "NEXUS5000"),
    (re.compile(r"\bN3K-|\bNexus ?3000\b", re.IGNORECASE), "NEXUS3000"),
    (re.compile(r"\bN2K-|\bNexus ?2000\b", re.IGNORECASE), "NEXUS2000"),
)
_BASE_TRAIN: Final = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}")
_CLASSIC_TRAIN: Final = re.compile(r"\)([A-Za-z]+)")
_ACI_REASON: Final = "NX-OS in ACI mode is not matched"
_FAMILY_REASON: Final = "the software family could not be worked out from show version"


def normalise_release(release: str) -> str:
    """Return `release` as Cisco's lookup expects it (story 45).

    The NX-OS `[build ...]` suffix is dropped. A dotted release has its zero padding stripped,
    which is what IOS-XE devices print in `show version`. Parenthesised releases, classic IOS
    and NX-OS, are left as they are.
    """
    stripped = _BUILD_SUFFIX.sub("", release).strip()
    if "(" in stripped or "." not in stripped:
        return stripped
    return ".".join(_strip_component(part) for part in stripped.split("."))


def _strip_component(part: str) -> str:
    match = _ZERO_PADDED.fullmatch(part)
    return match.group(1) if match else part


def family_of(platform: Platform | Unknown, release: str | Unknown) -> OsType | None:
    """Return the family `release` belongs to, or None when the table does not hold it.

    None means never matched: an unreadable release, an unsupported Platform, NX-OS in ACI
    mode, or a shape the family table does not name (stories 44, 46).
    """
    if not isinstance(release, str):
        return None
    normalised = normalise_release(release)
    if platform is Platform.NX_OS:
        return OsType.NX_OS if _NXOS.fullmatch(normalised) else None
    if platform is Platform.IOS_XE:
        if _CLASSIC_IOS.fullmatch(normalised):
            return OsType.IOS
        if _IOS_XE.fullmatch(normalised):
            return OsType.IOS_XE
    return None


def family_reason(release: str | Unknown) -> str:
    """Why `family_of` could not name a family, in fixed text the operator can read."""
    if isinstance(release, str) and _ACI_MODE.fullmatch(normalise_release(release)):
        return _ACI_REASON
    return _FAMILY_REASON


def train_of(release: str, os_type: OsType) -> str:
    """Return the Train `release` belongs to (GLOSSARY.md: `17.12`, `15.2E`).

    Classic IOS keeps the Train letter that follows the maintenance rebuild; IOS-XE and NX-OS
    use the first two dotted numbers.
    """
    match = _BASE_TRAIN.match(release)
    base = match.group(0) if match else release
    if os_type is OsType.IOS:
        suffix = _CLASSIC_TRAIN.search(release)
        if suffix is not None:
            return f"{base}{suffix.group(1).upper()}"
    return base


def release_key(release: str) -> tuple[tuple[int, int | str], ...]:
    """A sort key that orders releases within one Train, such as `17.9.10` above `17.9.5`."""
    return tuple(
        (0, int(token)) if token.isdigit() else (1, token) for token in _COMPONENT.findall(release)
    )


def hardware_family(model: str | Unknown) -> str | None:
    """Return the Nexus hardware family `model` names, or None when it cannot be worked out.

    None makes the NX-OS match rest on release alone, and marks the Finding "hardware family
    not confirmed" (story 46). A model that is not a Nexus model gives None as well: Analysis
    never guesses a family from a model it does not recognise.
    """
    if not isinstance(model, str):
        return None
    return next(
        (family for pattern, family in _NEXUS_FAMILIES if pattern.search(model)),
        None,
    )
