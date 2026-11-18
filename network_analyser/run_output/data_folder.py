r"""The per-user data folder, `%LOCALAPPDATA%\NetworkAnalyser\` (spec #37 "Per-user data").

It holds what the tool keeps between Runs: the Trust Store, the Backup check file, the Run
register, the change-pending marker and the single-instance lock file, and the default Runs
folder. Every installed version shares it (story 177). The file names here are part of the
tool's compatibility promise: changing one is a breaking change (decision #32).
"""

from dataclasses import dataclass
from pathlib import Path

DATA_FOLDER_NAME = "NetworkAnalyser"


@dataclass(frozen=True, slots=True)
class DataFolder:
    """Where each lasting file lives. Nothing here is created until a holder writes it."""

    root: Path

    @property
    def trust_store(self) -> Path:
        """The Trust Store, an OpenSSH `known_hosts` file (ADR 0002, #46)."""
        return self.root / "trust" / "known_hosts"

    @property
    def check_file(self) -> Path:
        """The Backup check file (ADR 0004, #45)."""
        return self.root / "passphrase-check.age"

    @property
    def run_register(self) -> Path:
        """The Run register: every Run folder the tool has created (#22, #26)."""
        return self.root / "run-register.txt"

    @property
    def change_pending(self) -> Path:
        """The marker `change-passphrase` leaves while it is unfinished (#22, #58)."""
        return self.root / "change-pending.json"

    @property
    def lock_file(self) -> Path:
        """The single-instance lock file (story 16)."""
        return self.root / "instance.lock"

    @property
    def runs(self) -> Path:
        """The default parent of Run folders, used unless `--runs-dir` names another."""
        return self.root / "runs"


def locate_data_folder(local_app_data: Path) -> DataFolder:
    """Return the data folder under `local_app_data` (the operator's `%LOCALAPPDATA%`)."""
    return DataFolder(root=local_app_data / DATA_FOLDER_NAME)
