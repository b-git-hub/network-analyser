"""The `_winsys` leaf module: every Windows-only call, behind one seam.

The elevation check, and later the masked reader's console calls, the crash-dump guard's
registry reads, the lock file, folder permissions and the per-user folder. Each function
works on any OS (or says it cannot) so callers can run, and inject fakes, in tests on Linux.
Imports nothing from the package. `ctypes`, `msvcrt` and `winreg` are imported only here.
"""

from network_analyser._winsys.elevation import is_elevated

__all__ = ["is_elevated"]
