"""The `run_output` module: the Run folder, `run-report.html` and `audit.log`.

Owns the per-user data folder's layout and its single-instance lock, creating and naming the
Run folder, the Run report and the append-only Audit log, whose writer passes every line
through the secret scan. Never takes raw device output.
"""

from network_analyser.run_output.data_folder import DataFolder, locate_data_folder
from network_analyser.run_output.folder import (
    LABEL_MAX,
    FolderFacts,
    RunFolder,
    RunFolderError,
    RunsParentCheck,
    check_runs_parent,
    create_run_folder,
    label_problem,
    run_folder_name,
)
from network_analyser.run_output.lock import InstanceLock, take_instance_lock

__all__ = [
    "LABEL_MAX",
    "DataFolder",
    "FolderFacts",
    "InstanceLock",
    "RunFolder",
    "RunFolderError",
    "RunsParentCheck",
    "check_runs_parent",
    "create_run_folder",
    "label_problem",
    "locate_data_folder",
    "run_folder_name",
    "take_instance_lock",
]
