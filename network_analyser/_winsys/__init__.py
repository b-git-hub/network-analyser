"""The `_winsys` leaf module: every Windows-only call, behind one seam.

The elevation check, the masked reader's console calls, the crash-dump guard's
`SetErrorMode` and registry reads, the per-user folder and long paths, the single-instance
lock file, folder permissions, the kind of drive a folder is on, Windows' proxy setting, and
the bounded retry of a rename Windows refused.
Each function works on any OS (or says it cannot) so callers can run, and inject fakes, in
tests on Linux. Imports nothing from the package. `ctypes`, `msvcrt` and `winreg` are
imported only here.
"""

from network_analyser._winsys.console import (
    Console,
    enable_live_output,
    open_console,
    stdout_is_console,
)
from network_analyser._winsys.elevation import is_elevated
from network_analyser._winsys.folders import (
    DriveKind,
    Grant,
    current_user_sid,
    drive_kind,
    modify_grants,
    read_grants,
    sync_roots,
)
from network_analyser._winsys.lock import lock_exclusively, unlock
from network_analyser._winsys.paths import (
    extended_length,
    local_app_data,
    os_path,
    pc_name,
    windows_account,
)
from network_analyser._winsys.proxy import WindowsProxy, system_proxy
from network_analyser._winsys.rename import retry_rename
from network_analyser._winsys.wer import (
    RegistryUnreadableError,
    RegistryView,
    read_machine_key,
    suppress_error_reporting,
)

__all__ = [
    "Console",
    "DriveKind",
    "Grant",
    "RegistryUnreadableError",
    "RegistryView",
    "WindowsProxy",
    "current_user_sid",
    "drive_kind",
    "enable_live_output",
    "extended_length",
    "is_elevated",
    "local_app_data",
    "lock_exclusively",
    "modify_grants",
    "open_console",
    "os_path",
    "pc_name",
    "read_grants",
    "read_machine_key",
    "retry_rename",
    "stdout_is_console",
    "suppress_error_reporting",
    "sync_roots",
    "system_proxy",
    "unlock",
    "windows_account",
]
