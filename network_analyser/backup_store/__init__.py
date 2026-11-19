"""The `backup_store` module: Backups locked with the Backup Passphrase (ADR 0004).

Owns the single locking worker, age passphrase encryption, ciphertext-only
temp-then-rename writes, the encrypted manifest, the check file, `show-backup`,
`change-passphrase` and the Run register. No plaintext config ever reaches disk.
"""

from network_analyser.backup_store.change_pending import (
    ChangeStage,
    ChangeStatus,
    Fingerprints,
    PassphraseFiles,
    PendingChange,
    change_status,
    finish_change,
    resume_change,
    start_change,
)
from network_analyser.backup_store.check_file import (
    PASSPHRASE_MIN,
    BackupPassphrase,
    CheckFileError,
    change_is_pending,
    create_check_file,
    passphrase_problem,
    unlock_check_file,
)
from network_analyser.backup_store.locker import (
    BACKUPS_FOLDER,
    MANIFEST_NAME,
    BackupLocker,
    scrypt_level,
)
from network_analyser.backup_store.register import (
    RegisterRefusedError,
    register_run_folder,
    registered_run_folders,
)
from network_analyser.backup_store.relock import (
    FileOutcome,
    FileResult,
    Relocker,
    RelockPlan,
    RunFiles,
    RunResult,
    plan_relock,
)

__all__ = [
    "BACKUPS_FOLDER",
    "MANIFEST_NAME",
    "PASSPHRASE_MIN",
    "BackupLocker",
    "BackupPassphrase",
    "ChangeStage",
    "ChangeStatus",
    "CheckFileError",
    "FileOutcome",
    "FileResult",
    "Fingerprints",
    "PassphraseFiles",
    "PendingChange",
    "RegisterRefusedError",
    "RelockPlan",
    "Relocker",
    "RunFiles",
    "RunResult",
    "change_is_pending",
    "change_status",
    "create_check_file",
    "finish_change",
    "passphrase_problem",
    "plan_relock",
    "register_run_folder",
    "registered_run_folders",
    "resume_change",
    "scrypt_level",
    "start_change",
    "unlock_check_file",
]
