"""SSH host keys and the Trust Store's verdict on them (ADR 0002; spec #37 stories 42-46).

`device_gateway` builds a `HostKey` from the key a device offers and asks `trust_store` for a
`HostKeyCheck`. The check rides on into the device record, the Run report and the Audit log,
so it holds only public data: an IP, a port, a key type and SHA-256 fingerprints.
"""

import base64
import binascii
import hashlib
import struct
from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address

_LENGTH = struct.Struct(">I")


class MalformedHostKeyError(ValueError):
    """The text is not a well-formed SSH public key of the type it claims."""


@dataclass(frozen=True, slots=True)
class HostKey:
    """A device's SSH host key, as `known_hosts` holds it: a key type and base64 key blob.

    The blob must decode and must name `key_type` as its first field (RFC 4253, 6.6), or
    `MalformedHostKeyError` is raised. `base64` is kept in canonical form, so two equal keys
    compare equal however they were spelled.
    """

    key_type: str
    base64: str

    def __post_init__(self) -> None:
        """Check the blob names the key type, and keep its canonical base64 spelling."""
        blob = _decode(self.base64)
        if _first_field(blob) != self.key_type.encode("ascii", errors="replace"):
            raise MalformedHostKeyError
        object.__setattr__(self, "base64", base64.b64encode(blob).decode("ascii"))

    @property
    def fingerprint(self) -> str:
        """The OpenSSH SHA-256 fingerprint: `SHA256:` and the unpadded base64 digest."""
        digest = hashlib.sha256(base64.b64decode(self.base64)).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _decode(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise MalformedHostKeyError from error


def _first_field(blob: bytes) -> bytes | None:
    if len(blob) < _LENGTH.size:
        return None
    (length,) = _LENGTH.unpack_from(blob)
    end = _LENGTH.size + length
    return blob[_LENGTH.size : end] if length > 0 and end <= len(blob) else None


@unique
class HostKeyVerdict(Enum):
    """What the Trust Store says about the key a device offered (ADR 0002)."""

    KNOWN = "known"
    """The key is already trusted for this IP and port: log in."""
    NEW = "new"
    """Nothing is trusted for this IP and port yet: trust on first use, and report it."""
    CHANGED = "changed"
    """Another key is trusted for this IP and port: a hard stop, never accepted mid-Run."""
    NOT_TRUSTED = "not trusted"
    """Strict mode, and nothing is trusted for this IP and port: never logged into."""


@dataclass(frozen=True, slots=True)
class HostKeyCheck:
    """The Trust Store's verdict on the key one device offered at one IP and port."""

    ip: IPv4Address
    port: int
    verdict: HostKeyVerdict
    offered: HostKey | None
    """The key the device offered; None when it would not offer the key type pinned for it."""
    trusted_fingerprints: tuple[str, ...]
    """The fingerprints already trusted for this IP and port: the old ones when CHANGED."""

    @property
    def key_type(self) -> str | None:
        """The offered key's type, or None when no key of the pinned type was offered."""
        return None if self.offered is None else self.offered.key_type

    @property
    def fingerprint(self) -> str | None:
        """The offered key's SHA-256 fingerprint: the new one when CHANGED."""
        return None if self.offered is None else self.offered.fingerprint
