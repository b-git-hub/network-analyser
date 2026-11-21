"""Release shapes: the family table, normalisation, the Train and an NX-OS hardware family.

The family table decided on #78 is keyed on what `show version` names, never on a guess from
the Platform alone: classic IOS and IOS-XE share one command set, so the release shape tells
them apart. Only three families are ever looked up (stories 44-45):

- classic IOS, such as `15.2(7)E4`, `12.2(55)SE7` and `15.1(4)M12a`;
- IOS-XE, such as `16.9.1`, `17.9.4a` and `26.1.2s1`;
- NX-OS, such as `9.3(10)`, `10.6(3s)` and `7.0(3)I4(8b)`.

A lettered or special running release is an ordinary release: the letters and the digit after
them (`26.1.2s1`, `10.3(4a)`, `15.1(4)M12a`) are part of the release, never a reason to skip it.

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
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from network_analyser.records.analysis import OsType
from network_analyser.records.platform import Platform
from network_analyser.records.unknown import Unknown

_BUILD_SUFFIX: Final = re.compile(r"\s*\[build[^\]]*\]", re.IGNORECASE)
_ZERO_PADDED: Final = re.compile(r"^0+([0-9][a-z]*)$")
_PART_SEPARATOR: Final = re.compile(r"[^0-9A-Za-z]+")
_DIGITS: Final = re.compile(r"[0-9]+")
_SUFFIX_COMPONENT: Final = re.compile(r"[0-9]+|[A-Za-z]+")

# NX-OS in ACI mode names its releases `major.minor(patch letter)`, such as `14.2(4i)`.
_ACI_MODE: Final = re.compile(r"1[1-7]\.[0-9]{1,2}\([0-9]{1,3}[a-z][a-z0-9]{0,4}\)")
# Plain NX-OS: `9.3(10)`, `6.2(16)`, `7.0(3)I7(9)`.
_NXOS: Final = re.compile(
    r"(?:[4-9]|10)\.[0-9]{1,2}\([0-9]{1,3}[a-z]{0,2}\)"
    r"(?:[A-Z][0-9]{1,3}\([0-9]{1,3}[a-z]{0,2}\))*"
)
# Classic IOS: a parenthesised maintenance rebuild, then a Train letter, such as `15.2(7)E4`.
_CLASSIC_IOS: Final = re.compile(
    r"[0-9]{1,2}\.[0-9]{1,2}\([0-9]{1,3}\)[A-Za-z]{1,3}[0-9]{0,3}[a-z]?"
)
# IOS-XE: dotted releases 16.x through 19.x and from 26.x on, such as `17.9.4a`.
_IOS_XE: Final = re.compile(
    r"(?:1[6-9]|2[6-9]|[3-9][0-9])\.[0-9]{1,2}\.[0-9]{1,3}[a-z]{0,2}[0-9]{0,2}"
)
# The Nexus platform aliases openVuln matches NX-OS on, from a chassis PID's series prefix. The
# aliases are the ones Cisco's `/platforms?OSType=nxos` documents (NEXUS3000, NEXUS5000,
# NEXUS6000, NEXUS7000, NEXUS9000); the Nexus 7700 (`N77-`) is listed under NEXUS7000, and a
# Nexus 2000 Fabric Extender (`N2K-`) runs no NX-OS of its own, so neither has an alias of its
# own.
_NEXUS_FAMILIES: Final = (
    (re.compile(r"N9K-", re.IGNORECASE), "NEXUS9000"),
    (re.compile(r"N7K-|N77-", re.IGNORECASE), "NEXUS7000"),
    (re.compile(r"N6K-", re.IGNORECASE), "NEXUS6000"),
    (re.compile(r"N5K-", re.IGNORECASE), "NEXUS5000"),
    (re.compile(r"N3K-", re.IGNORECASE), "NEXUS3000"),
)
_BASE_TRAIN: Final = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}")
_CLASSIC_TRAIN: Final = re.compile(r"\)([A-Za-z]+)")
_NXOS_LETTER_TRAIN: Final = re.compile(
    r"[0-9]{1,3}\.[0-9]{1,3}\([0-9]{1,3}[a-z]{0,2}\)[A-Z][0-9]{1,3}"
)
# The `platforms[].name` text Cisco's openVuln reply gives each Nexus series (#126). The names
# are Cisco's own, as its samples and the 2026 live replies show; a series whose text cannot be
# confirmed is absent, so its Upgrade Target stays `not available` rather than guessing.
_PLATFORM_NAMES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "NEXUS3000": "Cisco Nexus 3000 Series Switches",
        "NEXUS5000": "Cisco Nexus 5000 Series Switches",
        "NEXUS7000": "Cisco Nexus 7000 Series Switches",
        "NEXUS9000": "Cisco Nexus 9000 Series Switches",
    }
)
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

    IOS-XE and NX-OS use the first two dotted numbers. Classic IOS keeps the Train letter that
    follows the maintenance rebuild. An NX-OS release with a hardware-line segment, a capital
    letter and a number such as `I7`, `U6`, `A8`, `F3` or `N1`, keeps everything up to and
    including it, so `7.0(3)I7(9)` is in Train `7.0(3)I7` and `6.0(2)U6(10)` in `6.0(2)U6`
    (#137): releases built for different hardware lines are never lumped (story 19).
    """
    match = _BASE_TRAIN.match(release)
    base = match.group(0) if match else release
    if os_type is OsType.IOS:
        suffix = _CLASSIC_TRAIN.search(release)
        if suffix is not None:
            return f"{base}{suffix.group(1).upper()}"
    if os_type is OsType.NX_OS:
        letter_train = _NXOS_LETTER_TRAIN.match(release)
        if letter_train is not None:
            return letter_train.group(0)
    return base


def release_key(release: str) -> tuple[tuple[int, int, tuple[tuple[int, str | int], ...]], ...]:
    """A sort key that orders any release by Cisco's numbering, across every Platform.

    A release splits into parts at punctuation. A part is a number with an optional suffix, as
    in `17.12.7a`, `26.1.2s1` or `10.6(3s)`. A plain number sorts before the same number with a
    suffix, and that sorts before the next number; suffixes order letter by letter, then by any
    trailing number. The key orders `17.12.7 < 17.12.7a < 17.12.7b < 17.12.8` and the same way
    for IOS-XE, NX-OS and classic IOS.
    """
    return tuple(_part_key(part) for part in _PART_SEPARATOR.split(release) if part)


def _part_key(part: str) -> tuple[int, int, tuple[tuple[int, str | int], ...]]:
    """One release part: a number and its suffix, or a suffix that stands on its own."""
    digits = _DIGITS.match(part)
    if digits is not None:
        return (0, int(digits.group(0)), _suffix_key(part[digits.end() :]))
    return (1, 0, _suffix_key(part))


def _suffix_key(suffix: str) -> tuple[tuple[int, str | int], ...]:
    """A suffix's letters and trailing numbers, in the order they must compare."""
    return tuple(
        (1, int(token)) if token.isdigit() else (0, token)
        for token in _SUFFIX_COMPONENT.findall(suffix)
    )


def hardware_family(chassis_pid: str | None) -> str | None:
    """Return the Nexus series alias a chassis PID names, or None when it cannot be worked out.

    The PID is the chassis entry of `show inventory | json` (`N9K-C93180YC-EX`), because the
    model `show version` gives (`C93180YC-EX`) carries no series (#134). None marks the Finding
    "hardware family not confirmed" (story 46). A PID that does not start with a Nexus series
    prefix gives None as well: Analysis never guesses a series from a name it does not
    recognise.
    """
    if chassis_pid is None:
        return None
    return next(
        (family for pattern, family in _NEXUS_FAMILIES if pattern.match(chassis_pid)),
        None,
    )


def platform_name(family: str | None) -> str | None:
    """Return the `platforms[].name` text for one Nexus series alias, or None (#126).

    None means Cisco's exact text for that series is not in the built-in table, so its Upgrade
    Target stays `not available` rather than matching another series' entry.
    """
    if family is None:
        return None
    return _PLATFORM_NAMES.get(family)
