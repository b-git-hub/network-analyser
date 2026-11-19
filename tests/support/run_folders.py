"""Run folders holding locked Backups, made as a Run makes them (for `change-passphrase`).

Each Backup is the synthetic IOS-XE config in `device_text`, whose `enable secret 9` line is
a config canary, locked by the real `BackupLocker` with whatever age the test has set (the
fast fake, or real age), with the manifest written as at a Run's end.
"""

from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

from network_analyser import backup_store
from network_analyser.backup_store import BackupPassphrase
from network_analyser.credentials import SecretScan
from network_analyser.records import Platform
from network_analyser.records.backup import BackupCapture
from tests.support import device_text

CONFIG = device_text.IOS_XE_RUNNING_CONFIG
CONFIG_CANARY = device_text.CONFIG_CANARIES[0]
WHEN = datetime(2026, 11, 18, 10, 15, 30, tzinfo=UTC)


def make_run_folder(
    folder: Path,
    passphrase: BackupPassphrase,
    *hostnames: str,
    register: Path | None = None,
) -> Path:
    """Create `folder` with one locked Backup per hostname and its manifest.

    Args:
        folder: the Run folder to create.
        passphrase: the Backup Passphrase the Backups are locked with.
        hostnames: one Backup each, named `<hostname>__TEST000<n>.cfg.age`.
        register: the Run register to add the folder to, as a Run does; None adds it nowhere.
    """
    folder.mkdir(parents=True)
    if register is not None:
        backup_store.register_run_folder(register, folder, scan=SecretScan())
    locker = backup_store.BackupLocker(
        folder,
        shown=folder,
        passphrase=passphrase,
        capacity=1,
        emit=lambda _event: None,
        scan=SecretScan(),
        tool_version="0.1.0",
    )
    for number, hostname in enumerate(hostnames, start=1):
        capture = BackupCapture(
            IPv4Address(f"192.0.2.{number}"),
            Platform.IOS_XE,
            hostname,
            (f"TEST000{number}",),
            "show running-config view full",
            WHEN,
        )
        locker.take(capture, CONFIG.replace("hostname sw-a", f"hostname {hostname}"))
    locker.finish()
    return folder
