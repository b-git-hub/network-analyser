"""The secret scan: the last check on everything the tool writes (spec #37 story 164; #30; #145).

Every line bound for `audit.log`, the console, and later `topology.json`, the diagram and the
Run report passes through `SecretScan.contains_secret` first. It looks for the Run's own
Credential Set passwords and its Backup Passphrase, exactly and case-sensitively, and replaces
each match with `[blocked]`. A secret shorter than eight characters counts only where it stands
alone, with no letter or digit beside it, so a short password inside an ordinary word is not a
match (#70). The Run carries on; the hit count is kept so the Run can warn once,
never saying which set matched.

The scan lives in `credentials`, so the modules that write never hold a secret: they hand text
in and get redacted text back.

The scan keeps no value. `watch` records only each secret's length and an HMAC-SHA256
fingerprint of it under a random key this Run draws once, so it can still redact after the Run
has wiped its `Secret`s and while it is online, and nothing recoverable stays in memory
(ADR 0007, #145). Matching a fingerprint means hashing each window of that length; a keyed
rolling hash of the window's first characters picks the few windows worth hashing, so a scan
costs more than a substring search but stays linear in the text.

The fingerprints are dropped by `forget()` once every output is written.
"""

import hmac
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, NoReturn, final, override

from network_analyser.credentials.secret import Secret

BLOCKED: Final = "[blocked]"
_PREFIX: Final = 4
"""Characters of a secret the rolling hash screens on; the fingerprint decides every match. A
secret shorter than this is hashed window by window instead."""
_WHOLE_WORD_BELOW: Final = 8
"""A secret shorter than this counts only where it stands alone: no letter or digit right
before or after it. Longer secrets match anywhere, as before (#70)."""
_DIGEST: Final = "sha256"
_MASK: Final = (1 << 64) - 1
_KEY_BYTES: Final = 32
_BASE_LIMIT: Final = (1 << 62) - 1

type _Fingerprint = tuple[int, bytes]
"""One watched secret: its character length, and the keyed digest of its value."""


@dataclass(frozen=True, slots=True)
class _Watching:
    """One snapshot of what the scan watches: a key and fingerprints, never a value."""

    key: bytes
    base: int
    top: int
    prefixes: Mapping[int, tuple[_Fingerprint, ...]]
    short: tuple[_Fingerprint, ...]


@final
class SecretScan:
    """The Run's secrets, recognised by fingerprint in every line the tool writes."""

    __slots__ = (
        "__base",
        "__hits",
        "__key",
        "__lock",
        "__prefixes",
        "__short",
        "__top",
        "__watched",
    )

    def __init__(self) -> None:
        """Start with nothing to watch for. Add secrets with `watch` as they are typed."""
        self.__key: bytes = secrets.token_bytes(_KEY_BYTES)
        self.__base: int = 3 + 2 * (int.from_bytes(self.__key[8:16], "big") % _BASE_LIMIT)
        self.__top: int = pow(self.__base, _PREFIX - 1, 1 << 64)
        self.__prefixes: dict[int, tuple[_Fingerprint, ...]] = {}
        self.__short: tuple[_Fingerprint, ...] = ()
        self.__watched = 0
        self.__hits = 0
        self.__lock: Final = threading.Lock()

    def watch(self, secret: Secret) -> None:
        """Look for `secret` in everything scanned from now on. An empty one is ignored.

        Only the value's length and a keyed fingerprint are kept, so the scan can still
        redact once the `Secret` is wiped, without holding anything recoverable (#145).
        """
        if secret.is_empty():
            return
        value = secret.reveal()
        fingerprint = (len(value), hmac.digest(self.__key, value.encode(), _DIGEST))
        prefix = _rolling_hash(value, self.__base, _PREFIX)
        with self.__lock:
            if len(value) < _PREFIX:
                self.__short = (*self.__short, fingerprint)
            else:
                self.__prefixes[prefix] = (*self.__prefixes.get(prefix, ()), fingerprint)
            self.__watched += 1

    def forget(self) -> None:
        """Drop every fingerprint once the Run's outputs are written.

        The hit count stays, so the one warning at the Run's end still holds.
        """
        with self.__lock:
            self.__prefixes.clear()
            self.__short = ()
            self.__watched = 0

    def contains_secret(self, text: str) -> tuple[str, int]:
        """Return `text` with every watched secret replaced by `[blocked]`, and the hit count.

        Overlapping or nested matches are blocked as one stretch, so no part of a secret is
        left showing. Safe to call from several threads at once.
        """
        stretches = _merge(_matches(text, self.__snapshot()))
        if not stretches:
            return text, 0
        parts: list[str] = []
        end = 0
        for start, stop in stretches:
            parts.extend((text[end:start], BLOCKED))
            end = stop
        parts.append(text[end:])
        with self.__lock:
            self.__hits += len(stretches)
        return "".join(parts), len(stretches)

    def holds_secret(self, text: str) -> bool:
        """Say whether `text` holds a watched secret, without counting a hit.

        For text that must never be written with a part blocked, such as a path the tool
        will need again: the caller refuses it instead.
        """
        return bool(_matches(text, self.__snapshot()))

    @property
    def hits(self) -> int:
        """How many stretches of text the scan has blocked this Run, in every output."""
        with self.__lock:
            return self.__hits

    def __snapshot(self) -> _Watching:
        """Return what to match against now, copied so a later `watch` cannot change it."""
        with self.__lock:
            return _Watching(
                key=self.__key,
                base=self.__base,
                top=self.__top,
                prefixes=dict(self.__prefixes),
                short=self.__short,
            )

    @override
    def __init_subclass__(cls) -> NoReturn:
        """Refuse subclasses: one could add a way to the secrets."""
        msg = "SecretScan cannot be subclassed"
        raise TypeError(msg)

    @override
    def __repr__(self) -> str:
        return f"SecretScan({self.__watched} secret fingerprints)"

    @override
    def __reduce_ex__(self, protocol: object) -> NoReturn:
        msg = "the secret scan cannot be saved, pickled or copied"
        raise TypeError(msg)


def _matches(text: str, watching: _Watching) -> list[tuple[int, int]]:
    """Every (start, stop) where a watched secret occurs, overlapping occurrences included.

    A secret shorter than `_WHOLE_WORD_BELOW` counts only where it stands alone (#70).
    """
    found = [*_short_matches(text, watching), *_prefix_matches(text, watching)]
    return [(start, stop) for start, stop in found if _counts(text, start, stop)]


def _counts(text: str, start: int, stop: int) -> bool:
    """Say whether a match at text[start:stop] is blocked: long, or standing alone (#70)."""
    if stop - start >= _WHOLE_WORD_BELOW:
        return True
    before = start == 0 or not text[start - 1].isalnum()
    after = stop == len(text) or not text[stop].isalnum()
    return before and after


def _short_matches(text: str, watching: _Watching) -> list[tuple[int, int]]:
    """Every occurrence of a secret too short to screen on its first characters."""
    found: list[tuple[int, int]] = []
    for length, digest in watching.short:
        for start in range(len(text) - length + 1):
            stop = start + length
            if hmac.digest(watching.key, text[start:stop].encode(), _DIGEST) == digest:
                found.append((start, stop))
    return found


def _prefix_matches(text: str, watching: _Watching) -> list[tuple[int, int]]:
    """Every occurrence of a secret at least `_PREFIX` characters long, screened first."""
    found: list[tuple[int, int]] = []
    if not watching.prefixes or len(text) < _PREFIX:
        return found
    rolling = _rolling_hash(text, watching.base, _PREFIX)
    for start in range(len(text) - _PREFIX + 1):
        for length, digest in watching.prefixes.get(rolling, ()):
            stop = start + length
            if stop > len(text):
                continue
            window = text[start:stop]
            if hmac.digest(watching.key, window.encode(), _DIGEST) == digest:
                found.append((start, stop))
        if start + _PREFIX < len(text):
            rolling = (
                (rolling - ord(text[start]) * watching.top) * watching.base
                + ord(text[start + _PREFIX])
            ) & _MASK
    return found


def _rolling_hash(value: str, base: int, width: int) -> int:
    """Return the keyed polynomial hash of `value`'s first `width` characters."""
    rolling = 0
    for character in value[:width]:
        rolling = (rolling * base + ord(character)) & _MASK
    return rolling


def _merge(found: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Join matches that overlap or touch into single stretches, in order."""
    merged: list[tuple[int, int]] = []
    for start, stop in sorted(found):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], stop))
        else:
            merged.append((start, stop))
    return merged
