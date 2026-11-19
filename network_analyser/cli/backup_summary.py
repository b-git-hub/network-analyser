"""The Backups' lines in the end-of-Run summary (ticket #51; stories 98, 101).

How many configs were locked and written, how long locking took in all, and what needs the
operator: a Backup or the manifest that could not be written, and a Backup locked below
scrypt level 2^18 (#27). Only addresses and fixed text: never a hash of a plaintext or any
device output. The Run report (#66) takes the same records.
"""

from network_analyser.records.backup import BackupResults
from network_analyser.records.events import SCRYPT_LEVEL_WARNED_BELOW


def written(results: BackupResults) -> int:
    """Return how many Backups were locked and written."""
    return sum(1 for b in results.backups if b.path is not None)


def summary(results: BackupResults) -> str:
    """Return the Backups' summary lines."""
    total = len(results.backups)
    manifest = "with" if results.manifest_path is not None else "but no"
    lines = [
        (
            f"Backups: {written(results)} of {total} locked and written (locking took "
            f"{results.lock_seconds:.1f} s in all), {manifest} manifest.age."
        )
    ]
    attention = _attention(results)
    if attention:
        lines.append("Backups needing your attention:")
        lines.extend(f"  {item}" for item in attention)
    return "\n".join(lines)


def needs_attention(results: BackupResults) -> bool:
    """Say whether anything about the Backups needs the operator (exit code 1)."""
    return bool(_attention(results))


def _attention(results: BackupResults) -> list[str]:
    items: list[str] = []
    for backup in results.backups:
        if backup.problem is not None:
            items.append(f"{backup.ip}: {backup.problem}. Check the disk the Run folder is on.")
        elif backup.scrypt_level is not None and backup.scrypt_level < SCRYPT_LEVEL_WARNED_BELOW:
            items.append(
                f"{backup.ip}: locked at scrypt level 2^{backup.scrypt_level}, below "
                f"2^{SCRYPT_LEVEL_WARNED_BELOW}: this PC is slow, so the Backup is quicker "
                "to guess against. Keep the Backup Passphrase long."
            )
    if results.manifest_problem is not None:
        items.append(f"{results.manifest_problem}. Check the disk the Run folder is on.")
    return items
