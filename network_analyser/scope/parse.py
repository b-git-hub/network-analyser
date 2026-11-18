"""Turn the operator's Scope entries and Seeds into checked records (spec #37 stories 5-10, 41).

Checks are strict (decision #10): IPv4 only; CIDR, inclusive `a-b` ranges and single
addresses; no hostnames; no host bits; no reversed ranges; and every exclusion must match
something. Any bad entry refuses the whole Scope, and every bad entry is named.
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from ipaddress import AddressValueError, IPv4Address, IPv4Network, NetmaskValueError

from network_analyser.records import NEVER_TARGETS, AddressRange, Placement, ScopeRecord

NOT_IPV4 = "not an IPv4 address, a-b range or CIDR"
HOSTNAME = "hostnames are refused; give an IPv4 address"
IPV6 = "IPv6 is not supported in v1"
NEVER_A_TARGET_ENTRY = "holds no address that can be a login target (story 41)"

# A CIDR of /30 or shorter has a network and a broadcast address that are never targets.
_EDGES_UP_TO_PREFIX = 30
_LETTER = re.compile(r"[A-Za-z]")
_NEVER_TARGET_RANGES = tuple(
    AddressRange(n.network_address, n.broadcast_address) for n in NEVER_TARGETS
)


@dataclass(frozen=True, slots=True)
class Refusal:
    """One entry the operator gave, and why it was refused.

    `entry` is the operator's own text, unescaped: escape it before printing.
    """

    entry: str
    reason: str
    exclusion: bool = False
    seed: bool = False


@dataclass(frozen=True, slots=True)
class ScopeRefused:
    """The Scope or the Seeds were refused; every reason is listed."""

    refusals: tuple[Refusal, ...]


@dataclass(frozen=True, slots=True)
class _Entry:
    text: str
    span: AddressRange
    edges: tuple[IPv4Address, ...]
    position: int = 0  # where the operator gave it, so warnings name entries in that order


def parse(entries: Sequence[str], exclusions: Sequence[str]) -> ScopeRecord | ScopeRefused:
    """Check every entry and exclusion, and build the merged Scope, or refuse it in full."""
    refusals: list[Refusal] = []
    includes = _read_all(entries, refusals, exclusion=False)
    excludes = _read_all(exclusions, refusals, exclusion=True)
    if refusals:
        return ScopeRefused(tuple(refusals))
    if not includes:
        return ScopeRefused((Refusal("", "the Scope has no entries"),))

    warnings: list[str] = []
    ranges = _merge(includes, warnings)
    refusals.extend(
        Refusal(e.text, "this exclusion matches nothing in the Scope", exclusion=True)
        for e in excludes
        if not any(e.span.overlaps(r) for r in ranges)
    )
    if refusals:
        return ScopeRefused(tuple(refusals))
    removed = _merge(excludes, warnings)
    address_count = sum(r.size for r in _subtract(ranges, removed))
    if address_count == 0:
        return ScopeRefused((Refusal("", "the exclusions remove every address in the Scope"),))
    return ScopeRecord(
        ranges=ranges,
        exclusions=removed,
        edges=frozenset(edge for e in includes for edge in e.edges),
        address_count=address_count,
        warnings=tuple(warnings),
    )


def check_entry(text: str, *, exclusion: bool = False) -> Refusal | None:
    """Check one Scope line as it is typed at the prompt; None means it is good."""
    entry = _read(text, exclusion=exclusion)
    return entry if isinstance(entry, Refusal) else None


def unmatched_exclusions(entries: Sequence[str], exclusions: Sequence[str]) -> tuple[str, ...]:
    """Name the valid exclusions that match nothing among the valid entries."""
    spans = [e.span for e in _read_all(entries, [], exclusion=False)]
    return tuple(
        e.text
        for e in _read_all(exclusions, [], exclusion=True)
        if not any(e.span.overlaps(s) for s in spans)
    )


def check_seeds(texts: Sequence[str], fence: ScopeRecord) -> tuple[IPv4Address, ...] | ScopeRefused:
    """Check every Seed is one IPv4 address the Scope lets the tool touch (story 10)."""
    if not texts:
        return ScopeRefused((Refusal("", "at least one Seed is needed", seed=True),))
    seeds: list[IPv4Address] = []
    refusals: list[Refusal] = []
    for text in texts:
        seed = _read_seed(text, fence)
        if isinstance(seed, Refusal):
            refusals.append(seed)
        elif seed not in seeds:
            seeds.append(seed)
    return ScopeRefused(tuple(refusals)) if refusals else tuple(seeds)


def _read_seed(text: str, fence: ScopeRecord) -> IPv4Address | Refusal:
    raw = text.strip()
    reason = _shape_problem(raw)
    if reason is None and ("/" in raw or "-" in raw):
        reason = "a Seed is one IPv4 address"
    if reason is None:
        try:
            address = IPv4Address(raw)
        except AddressValueError:
            reason = "not an IPv4 address"
        else:
            placement = fence.placement(address)
            if placement is Placement.INSIDE:
                return address
            reason = f"this Seed is {placement.value}"
    return Refusal(text, reason, seed=True)


def _read_all(texts: Iterable[str], refusals: list[Refusal], *, exclusion: bool) -> list[_Entry]:
    read: list[_Entry] = []
    for position, text in enumerate(texts):
        entry = _read(text, exclusion=exclusion)
        if isinstance(entry, Refusal):
            refusals.append(entry)
        else:
            read.append(replace(entry, position=position))
    return read


def _read(text: str, *, exclusion: bool) -> _Entry | Refusal:
    raw = text.strip()
    entry = _shape_problem(raw) or _parse_form(raw)
    if isinstance(entry, str):
        return Refusal(text, entry, exclusion=exclusion)
    if not exclusion and not _subtract((entry.span,), _NEVER_TARGET_RANGES):
        return Refusal(text, NEVER_A_TARGET_ENTRY)
    return entry


def _shape_problem(raw: str) -> str | None:
    if not raw:
        return "the entry is empty"
    if ":" in raw:
        return IPV6
    if _LETTER.search(raw):
        return HOSTNAME
    return None


def _parse_form(raw: str) -> _Entry | str:
    if "/" in raw:
        return _parse_cidr(raw)
    try:
        if "-" in raw:
            first_text, last_text = raw.split("-", 1)
            first, last = IPv4Address(first_text.strip()), IPv4Address(last_text.strip())
        else:
            first = last = IPv4Address(raw)
    except AddressValueError:
        return NOT_IPV4
    if last < first:
        return "the range is reversed"
    return _Entry(raw, AddressRange(first, last), ())


def _parse_cidr(raw: str) -> _Entry | str:
    try:
        network = IPv4Network(raw)
    except AddressValueError, NetmaskValueError:
        return NOT_IPV4
    except ValueError:
        try:
            meant = IPv4Network(raw, strict=False)
        except ValueError:
            return NOT_IPV4
        return f"host bits are set (did you mean {meant}?)"
    edges = (
        (network.network_address, network.broadcast_address)
        if network.prefixlen <= _EDGES_UP_TO_PREFIX
        else ()
    )
    return _Entry(raw, AddressRange(network.network_address, network.broadcast_address), edges)


def _merge(entries: list[_Entry], warnings: list[str]) -> tuple[AddressRange, ...]:
    """Join overlapping and touching entries; warn about each group that overlapped."""
    merged: list[AddressRange] = []
    group: list[_Entry] = []
    overlapped = False
    for entry in sorted(entries, key=lambda e: e.span):
        if merged and int(entry.span.first) <= int(merged[-1].last) + 1:
            overlapped = overlapped or entry.span.first <= merged[-1].last
            merged[-1] = AddressRange(merged[-1].first, max(merged[-1].last, entry.span.last))
            group.append(entry)
            continue
        _warn_if_overlapped(group, merged, warnings, overlapped=overlapped)
        merged.append(entry.span)
        group, overlapped = [entry], False
    _warn_if_overlapped(group, merged, warnings, overlapped=overlapped)
    return tuple(merged)


def _warn_if_overlapped(
    group: list[_Entry], merged: list[AddressRange], warnings: list[str], *, overlapped: bool
) -> None:
    if overlapped:
        names = ", ".join(e.text for e in sorted(group, key=lambda e: e.position))
        warnings.append(f"overlapping entries {names} were merged into {merged[-1]}")


def _subtract(
    ranges: Iterable[AddressRange], removals: Iterable[AddressRange]
) -> list[AddressRange]:
    """Return what is left of `ranges` once every address in `removals` is taken out."""
    left = list(ranges)
    for removal in removals:
        kept: list[AddressRange] = []
        for span in left:
            if not span.overlaps(removal):
                kept.append(span)
                continue
            if span.first < removal.first:
                kept.append(AddressRange(span.first, IPv4Address(int(removal.first) - 1)))
            if removal.last < span.last:
                kept.append(AddressRange(IPv4Address(int(removal.last) + 1), span.last))
        left = kept
    return left
