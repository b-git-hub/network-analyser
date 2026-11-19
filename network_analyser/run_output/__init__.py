"""The `run_output` module: the Run folder, `run-report.html` and `audit.log`.

Owns the per-user data folder's layout, its single-instance lock and the check of who can
reach its Trust Store folder; creating and naming the Run folder, the Run report and the
append-only Audit log, whose writer passes every line through the secret scan; and the one
scanned writer for the Run folder's other plaintext files (`topology.json`, later the
diagrams and the Run report). Never takes
raw device output.
"""

from network_analyser.run_output.audit import (
    AUDIT_LOG_NAME,
    AUDIT_SCHEMA,
    AuditEventRefusedError,
    AuditLog,
    AuditLogError,
    open_audit_log,
)
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
from network_analyser.run_output.scanned_file import write_scanned_json, write_scanned_text
from network_analyser.run_output.trust_folder import TrustFolderCheck, check_trust_folder

__all__ = [
    "AUDIT_LOG_NAME",
    "AUDIT_SCHEMA",
    "LABEL_MAX",
    "AuditEventRefusedError",
    "AuditLog",
    "AuditLogError",
    "DataFolder",
    "FolderFacts",
    "InstanceLock",
    "RunFolder",
    "RunFolderError",
    "RunsParentCheck",
    "TrustFolderCheck",
    "check_runs_parent",
    "check_trust_folder",
    "create_run_folder",
    "label_problem",
    "locate_data_folder",
    "open_audit_log",
    "run_folder_name",
    "take_instance_lock",
    "write_scanned_json",
    "write_scanned_text",
]
