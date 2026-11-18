"""The `backup_store` module: Backups locked with the Backup Passphrase (ADR 0004).

Owns the single locking worker, age passphrase encryption, ciphertext-only
temp-then-rename writes, the encrypted manifest, the check file, `show-backup`,
`change-passphrase` and the Run register. No plaintext config ever reaches disk.
"""

from network_analyser.backup_store.check_file import (
    PASSPHRASE_MIN,
    BackupPassphrase,
    CheckFileError,
    change_is_pending,
    create_check_file,
    passphrase_problem,
    unlock_check_file,
)
from network_analyser.backup_store.register import (
    RegisterRefusedError,
    register_run_folder,
    registered_run_folders,
)

__all__ = [
    "PASSPHRASE_MIN",
    "BackupPassphrase",
    "CheckFileError",
    "RegisterRefusedError",
    "change_is_pending",
    "create_check_file",
    "passphrase_problem",
    "register_run_folder",
    "registered_run_folders",
    "unlock_check_file",
]
