"""The Trust Store itself: check a device's key, and save it only once a password was sent."""

import os
import secrets
import threading
from enum import Enum, unique
from ipaddress import IPv4Address
from pathlib import Path

from network_analyser._winsys import retry_rename
from network_analyser.records import HostKey, HostKeyCheck, HostKeyVerdict
from network_analyser.trust_store import openssh


class PreloadIsTrustStoreError(ValueError):
    """`--known-hosts` names the Trust Store itself, which the tool writes (story 46)."""


@unique
class AcceptOutcome(Enum):
    """What `accept` did with a key the operator checked out of band (story 45)."""

    SAVED = "saved"
    """The key now replaces whatever was trusted for that IP and port."""
    ALREADY_TRUSTED = "already trusted"
    """The key was already trusted; nothing was written."""
    FINGERPRINT_MISMATCH = "fingerprint mismatch"
    """The typed fingerprint is not the presented key's; nothing was written."""
    REVOKED = "revoked"
    """A `@revoked` line names the presented key, so it is never trusted."""


class TrustStore:
    """The operator's trusted SSH host keys, plus any keys pre-loaded read-only.

    Safe to share between the threads that visit devices in parallel.
    """

    def __init__(self, path: Path, text: str, preloaded: str, *, strict: bool) -> None:
        """Hold the Trust Store kept at `path` (content `text`) and the pre-loaded keys."""
        self._path = path
        self._strict = strict
        self._lock = threading.Lock()
        self._text = text
        self._entries, own_skipped = openssh.parse(text)
        self._preloaded, preload_skipped = openssh.parse(preloaded)
        self._skipped = own_skipped + preload_skipped

    @property
    def skipped_lines(self) -> int:
        """How many lines of the Trust Store and `--known-hosts` file were not understood.

        Counted when loaded, for the Run report: a skipped line trusts nothing.
        """
        return self._skipped

    def key_types(self, ip: IPv4Address, port: int) -> tuple[str, ...]:
        """Return the key types to ask `ip` and `port` for; empty when nothing is trusted."""
        return tuple(sorted({key.key_type for key in self._trusted(ip, port)}))

    def check(self, ip: IPv4Address, port: int, offered: HostKey | None) -> HostKeyCheck:
        """Say whether `offered` is the key trusted for `ip` and `port`."""
        trusted = self._trusted(ip, port)
        if offered is None and not trusted:
            msg = "no key type is pinned for an unknown device, so it must offer a key"
            raise ValueError(msg)
        fingerprints = tuple(key.fingerprint for key in trusted)
        if offered is not None and self._revoked(offered, ip, port):
            verdict = HostKeyVerdict.CHANGED
        elif offered is not None and offered in trusted:
            verdict = HostKeyVerdict.KNOWN
        elif trusted:
            verdict = HostKeyVerdict.CHANGED
        elif self._strict:
            verdict = HostKeyVerdict.NOT_TRUSTED
        else:
            verdict = HostKeyVerdict.NEW
        return HostKeyCheck(ip, port, verdict, offered, fingerprints)

    def password_sent(self, check: HostKeyCheck) -> None:
        """Write a NEW key to the Trust Store, now that a password was sent to its device."""
        if check.verdict is not HostKeyVerdict.NEW or check.offered is None:
            return
        with self._lock:
            if self._trusted(check.ip, check.port):
                return
            line = openssh.format_line(check.ip, check.port, check.offered)
            self._write(openssh.append(self._text, line))

    def accept(
        self, ip: IPv4Address, fingerprint: str, presented: HostKey, *, port: int = 22
    ) -> AcceptOutcome:
        """Trust `presented` for `ip` and `port` in place of any other key (`trust-key`).

        `fingerprint` is what the operator typed after checking the device's console. The key
        is saved only when it is exactly the presented key's `SHA256:` fingerprint; padding
        and surrounding spaces are ignored. Works in strict mode too: it is the operator's
        own decision, taken outside a Run (ADR 0002).
        """
        if fingerprint.strip().rstrip("=") != presented.fingerprint:
            return AcceptOutcome.FINGERPRINT_MISMATCH
        if self._revoked(presented, ip, port):
            return AcceptOutcome.REVOKED
        with self._lock:
            if presented in self._trusted(ip, port):
                return AcceptOutcome.ALREADY_TRUSTED
            text = openssh.without_host(self._text, openssh.host_name(ip, port))
            self._write(openssh.append(text, openssh.format_line(ip, port, presented)))
        return AcceptOutcome.SAVED

    def _trusted(self, ip: IPv4Address, port: int) -> list[HostKey]:
        """Return the keys trusted for `ip` and `port`, leaving out any revoked key."""
        named = self._named(ip, port)
        revoked = {entry.key for entry in named if entry.revoked}
        keys = (entry.key for entry in named if entry.key not in revoked)
        return list(dict.fromkeys(keys))

    def _revoked(self, key: HostKey, ip: IPv4Address, port: int) -> bool:
        return any(entry.revoked and entry.key == key for entry in self._named(ip, port))

    def _named(self, ip: IPv4Address, port: int) -> list[openssh.Entry]:
        host = openssh.host_name(ip, port)
        return [entry for entry in (*self._entries, *self._preloaded) if entry.names(host)]

    def _write(self, text: str) -> None:
        """Replace the Trust Store with `text`: temp file, flush to disk, then rename.

        Windows can refuse the rename for a moment while another process holds the new file
        (#158); `retry_rename` waits a bounded time, and a refusal that outlasts it raises.
        """
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self._path.with_name(f"{self._path.name}.tmp-{secrets.token_hex(8)}")
        handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(handle, text.encode("utf-8"))
            os.fsync(handle)
        finally:
            os.close(handle)
        retry_rename(lambda: temporary.replace(self._path))
        self._text = text
        self._entries, _ = openssh.parse(text)


def load(path: Path, *, strict: bool = False, known_hosts: Path | None = None) -> TrustStore:
    """Read the Trust Store at `path`, and the operator's `--known-hosts` file if given.

    A missing Trust Store is empty: the first Run creates it. The `--known-hosts` file is only
    ever read (story 46): a missing one raises `FileNotFoundError`, and naming the Trust
    Store itself raises `PreloadIsTrustStoreError`. With `strict` (`--strict-host-keys`), a
    device with no trusted key is NOT_TRUSTED instead of NEW, so nothing is trusted on first
    use. Keys trusted in either file count; only the Trust Store is ever written.
    """
    if known_hosts is not None and known_hosts.resolve() == path.resolve():
        raise PreloadIsTrustStoreError
    preloaded = "" if known_hosts is None else _read(known_hosts)
    try:
        text = _read(path)
    except FileNotFoundError:
        text = ""
    return TrustStore(path, text, preloaded, strict=strict)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")
