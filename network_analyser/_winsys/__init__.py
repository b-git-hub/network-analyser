"""The `_winsys` leaf module: every Windows-only call, behind one seam.

The elevation check, the per-user folder and long paths, the single-instance lock file,
folder permissions and the kind of drive a folder is on; later the masked reader's console
calls and the crash-dump guard's registry reads. Each function works on any OS (or says it
cannot) so callers can run, and inject fakes, in tests on Linux. Imports nothing from the
package. `ctypes`, `msvcrt` and `winreg` are imported only here.
"""

from network_analyser._winsys.elevation import is_elevated
from network_analyser._winsys.folders import (
    DriveKind,
    Grant,
    current_user_sid,
    drive_kind,
    modify_grants,
    sync_roots,
)
from network_analyser._winsys.lock import lock_exclusively, unlock
from network_analyser._winsys.paths import extended_length, local_app_data, os_path

__all__ = [
    "DriveKind",
    "Grant",
    "current_user_sid",
    "drive_kind",
    "extended_length",
    "is_elevated",
    "local_app_data",
    "lock_exclusively",
    "modify_grants",
    "os_path",
    "sync_roots",
    "unlock",
]
