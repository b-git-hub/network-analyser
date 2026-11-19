"""The records around a Backup (ticket #51; decided on #12, ADR 0004).

The running config itself is never in a record (spec-37-implementation-calls, call 4):
`device_gateway` hands it, beside a `BackupCapture`, straight to `backup_store`'s sink, and
`backup_store` hands back a `BackupRecord` that says what became of it.
"""

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address

from network_analyser.records.device import Unknown
from network_analyser.records.platform import Platform


@dataclass(frozen=True, slots=True)
class BackupCapture:
    """Which device a captured running config came from, and how (story 98).

    Attributes:
        ip: the address logged into.
        platform: the Platform identified.
        hostname: the hostname `show version` gave.
        serials: every chassis serial `show version` gave, the first being the chassis's own.
        command: the exact command whose reply is the config.
        captured_at: when the reply came back, UTC.
    """

    ip: IPv4Address
    platform: Platform
    hostname: str | Unknown
    serials: tuple[str, ...] | Unknown
    command: str
    captured_at: datetime


@dataclass(frozen=True, slots=True)
class BackupRecord:
    """What became of one captured config: locked and written, or why not (stories 98-101).

    Attributes:
        ip: the device's address.
        hostname: the hostname the capture gave.
        path: the Backup's path; None when it was not written.
        ciphertext_sha256: the SHA-256 of the locked file, in hex; None when not written.
            Only the ciphertext's hash is ever kept in the clear (story 99).
        scrypt_level: the scrypt work factor (log2) read from the file's header; None when
            not written.
        lock_seconds: how long locking it took.
        problem: why it was not written, as fixed text; None when it was.
    """

    ip: IPv4Address
    hostname: str | Unknown
    path: str | None
    ciphertext_sha256: str | None
    scrypt_level: int | None
    lock_seconds: float
    problem: str | None = None


@dataclass(frozen=True, slots=True)
class BackupResults:
    """Every Backup of a Run and its manifest, for the summary and the Run report (story 101).

    Attributes:
        backups: one record per captured config, in the order they were locked.
        lock_seconds: the total time spent locking, the manifest included.
        manifest_path: where `manifest.age` was written; None when it was not.
        manifest_problem: why it was not written, as fixed text; None when it was.
    """

    backups: tuple[BackupRecord, ...]
    lock_seconds: float
    manifest_path: str | None
    manifest_problem: str | None
