"""The `_winsys` leaf module: every Windows-only call, behind one seam.

The elevation check, the masked reader's console calls, the crash-dump guard's
`SetErrorMode` and registry reads, and later the lock file, folder permissions and the
per-user folder. Each function works on any OS (or says it cannot) so callers can run, and
inject fakes, in tests on Linux. Imports nothing from the package. `ctypes`, `msvcrt` and
`winreg` are imported only here.
"""

from network_analyser._winsys.console import Console, open_console
from network_analyser._winsys.elevation import is_elevated
from network_analyser._winsys.wer import (
    RegistryUnreadableError,
    RegistryView,
    read_machine_key,
    suppress_error_reporting,
)

__all__ = [
    "Console",
    "RegistryUnreadableError",
    "RegistryView",
    "is_elevated",
    "open_console",
    "read_machine_key",
    "suppress_error_reporting",
]
