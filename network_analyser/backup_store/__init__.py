"""The `backup_store` module: Backups locked with the Backup Passphrase (ADR 0004).

Owns the single locking worker, age passphrase encryption, ciphertext-only
temp-then-rename writes, the encrypted manifest, the check file, `show-backup`,
`change-passphrase` and the Run register. No plaintext config ever reaches disk.
"""

from network_analyser.backup_store.register import register_run_folder, registered_run_folders

__all__ = ["register_run_folder", "registered_run_folders"]
