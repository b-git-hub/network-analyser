"""Reading and writing OpenSSH `known_hosts` text (sshd(8), "SSH_KNOWN_HOSTS FILE FORMAT").

A line is `[marker] hosts key-type base64-key [comment]`. `hosts` is a comma-separated list
of patterns matched against the host's name in `known_hosts` form: the bare IP for port 22,
otherwise `[ip]:port`. Only IPs are ever matched, because the tool connects by IP only (#7).
As in OpenSSH, a pattern may use `*` and `?`, a `!` pattern excludes, and a hashed name
(`|1|salt|hash`, HashKnownHosts) is the HMAC-SHA1 of the name under the salt. A `@revoked`
line names a key that is never trusted. `@cert-authority` lines are skipped: host
certificates are not trusted in v1.
"""

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass
from ipaddress import IPv4Address

from network_analyser.records import HostKey, MalformedHostKeyError

DEFAULT_PORT = 22
REVOKED = "@revoked"
_HASHED = "|1|"


def host_name(ip: IPv4Address, port: int) -> str:
    """Return how `known_hosts` names `ip` and `port`: `192.0.2.10` or `[192.0.2.10]:2222`."""
    return str(ip) if port == DEFAULT_PORT else f"[{ip}]:{port}"


@dataclass(frozen=True, slots=True)
class Entry:
    """One understood `known_hosts` line."""

    patterns: tuple[str, ...]
    key: HostKey
    rest: str
    """Everything after the hosts field, as written: key type, key and any comment."""
    revoked: bool

    def names(self, host: str) -> bool:
        """Say whether this line applies to `host` (a `host_name()`), as OpenSSH would."""
        named = False
        for pattern in self.patterns:
            negated = pattern.startswith("!")
            if _matches(pattern.removeprefix("!"), host):
                if negated:
                    return False
                named = True
        return named


def _matches(pattern: str, host: str) -> bool:
    if pattern.startswith(_HASHED):
        return _matches_hashed(pattern, host)
    regex = "".join(
        ".*" if char == "*" else "." if char == "?" else re.escape(char) for char in pattern
    )
    return re.fullmatch(regex, host) is not None


def _matches_hashed(pattern: str, host: str) -> bool:
    parts = pattern.removeprefix(_HASHED).split("|")
    if len(parts) != 2:  # noqa: PLR2004 (salt, hash)
        return False
    try:
        salt, digest = (base64.b64decode(part, validate=True) for part in parts)
    except binascii.Error:
        return False
    expected = hmac.new(salt, host.encode("ascii"), hashlib.sha1).digest()
    return hmac.compare_digest(expected, digest)


def parse(text: str) -> tuple[list[Entry], int]:
    """Return the lines of `text` this module understands, and how many others it skipped."""
    entries: list[Entry] = []
    skipped = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entry = _parse_line(stripped)
        if entry is None:
            skipped += 1
        else:
            entries.append(entry)
    return entries, skipped


def _parse_line(line: str) -> Entry | None:
    revoked = line.startswith("@")
    if revoked:
        marker, _, line = line.partition(" ")
        if marker != REVOKED:
            return None
    fields = line.split(maxsplit=1)
    if len(fields) < 2:  # noqa: PLR2004 (hosts, then the rest)
        return None
    hosts, rest = fields
    key_fields = rest.split()
    if len(key_fields) < 2:  # noqa: PLR2004 (key type, key)
        return None
    try:
        key = HostKey(key_type=key_fields[0], base64=key_fields[1])
    except MalformedHostKeyError:
        return None
    return Entry(patterns=tuple(hosts.split(",")), key=key, rest=rest, revoked=revoked)


def format_line(ip: IPv4Address, port: int, key: HostKey) -> str:
    """Return the `known_hosts` line that trusts `key` for `ip` and `port`."""
    return f"{host_name(ip, port)} {key.key_type} {key.base64}\n"


def append(text: str, line: str) -> str:
    """Return `text` with `line` added as its last line."""
    return text + line if not text or text.endswith("\n") else f"{text}\n{line}"


def without_host(text: str, host: str) -> str:
    """Return `text` with every line that trusts a key for `host` changed so it no longer does.

    Other lines, and the other hosts on a changed line, are kept as written. A line that
    still names `host` through a wildcard gets a `!host` pattern; a hashed line is dropped.
    `@revoked` lines are kept: a revoked key stays revoked.
    """
    kept: list[str] = []
    for line in text.splitlines(keepends=True):
        entry = _parse_line(line.strip())
        if entry is None or entry.revoked or not entry.names(host):
            kept.append(line)
            continue
        patterns = [pattern for pattern in entry.patterns if pattern != host]
        if not patterns or any(pattern.startswith(_HASHED) for pattern in patterns):
            continue
        if Entry(tuple(patterns), entry.key, entry.rest, revoked=False).names(host):
            patterns.append(f"!{host}")
        kept.append(f"{','.join(patterns)} {entry.rest}\n")
    return "".join(kept)
