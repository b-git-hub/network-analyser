"""The secret scan: the last check on everything the tool writes (spec #37 story 164; #30).

Every line bound for `audit.log`, the console, and later `topology.json`, the diagram and
the Run report passes through `SecretScan.contains_secret` first. It looks for the Run's own
Credential Set passwords and its Backup Passphrase, exactly and case-sensitively, and
replaces each match with `[blocked]`. The Run carries on; the hit count is kept so the Run
can warn once, never saying which set matched.

The scan lives in `credentials`, so the modules that write never hold a secret: they hand
text in and get redacted text back. The values are revealed only for the search itself and
never kept anywhere else.
"""

import threading
from typing import Final, NoReturn, final, override

from network_analyser.credentials.secret import HELD_IN_MEMORY, Secret

BLOCKED: Final = "[blocked]"


@final
class SecretScan:
    """The Run's secrets, watched for in every line the tool writes."""

    __slots__ = ("__hits", "__lock", "__secrets")

    def __init__(self) -> None:
        """Start with nothing to watch for. Add secrets with `watch` as they are typed."""
        self.__secrets: list[Secret] = []
        self.__hits = 0
        self.__lock: Final = threading.Lock()

    def watch(self, secret: Secret) -> None:
        """Look for `secret` in everything scanned from now on. An empty one is ignored."""
        if secret.is_empty():
            return
        with self.__lock:
            self.__secrets.append(secret)

    def contains_secret(self, text: str) -> tuple[str, int]:
        """Return `text` with every watched secret replaced by `[blocked]`, and the hit count.

        Overlapping or nested matches are blocked as one stretch, so no part of a secret is
        left showing. Safe to call from several threads at once.
        """
        with self.__lock:
            secrets = tuple(self.__secrets)
        stretches = _merge(_matches(text, secrets))
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
        with self.__lock:
            secrets = tuple(self.__secrets)
        return bool(_matches(text, secrets))

    @property
    def hits(self) -> int:
        """How many stretches of text the scan has blocked this Run, in every output."""
        with self.__lock:
            return self.__hits

    @override
    def __init_subclass__(cls) -> NoReturn:
        """Refuse subclasses: one could add a way to the secrets."""
        msg = "SecretScan cannot be subclassed"
        raise TypeError(msg)

    @override
    def __repr__(self) -> str:
        return f"SecretScan({len(self.__secrets)} secrets, {HELD_IN_MEMORY})"

    @override
    def __reduce_ex__(self, protocol: object) -> NoReturn:
        msg = "the secret scan cannot be saved, pickled or copied"
        raise TypeError(msg)


def _matches(text: str, secrets: tuple[Secret, ...]) -> list[tuple[int, int]]:
    """Every (start, stop) where a secret occurs, overlapping occurrences included."""
    found: list[tuple[int, int]] = []
    for secret in secrets:
        value = secret.reveal()
        start = text.find(value)
        while start != -1:
            found.append((start, start + len(value)))
            start = text.find(value, start + 1)
    return found


def _merge(found: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Join matches that overlap or touch into single stretches, in order."""
    merged: list[tuple[int, int]] = []
    for start, stop in sorted(found):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], stop))
        else:
            merged.append((start, stop))
    return merged
