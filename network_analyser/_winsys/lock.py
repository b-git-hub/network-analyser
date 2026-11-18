"""The single-instance lock file, held exclusively (spec #37 story 16; decided on #26).

The lock is taken on an open file handle, so the OS releases it when the process ends, even
by a crash: a stale lock can never block a later Run. Windows uses `msvcrt.locking`; other
systems use `fcntl.flock`, which behaves the same way, so tests on Linux exercise it.
Nothing is ever written into the lock file.
"""

import os
import sys
from pathlib import Path

if sys.platform == "win32":
    import msvcrt

    def lock_exclusively(path: Path) -> int | None:
        """Open `path` (creating it) and lock it; return the handle, or None if held."""
        handle = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOINHERIT, 0o600)
        try:
            msvcrt.locking(handle, msvcrt.LK_NBLCK, 1)
        except OSError:
            os.close(handle)
            return None
        return handle

    def unlock(handle: int) -> None:
        """Release a lock taken by `lock_exclusively` and close its handle."""
        try:
            os.lseek(handle, 0, os.SEEK_SET)
            msvcrt.locking(handle, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass  # closing the handle releases it anyway
        os.close(handle)

else:
    import fcntl

    def lock_exclusively(path: Path) -> int | None:
        """Open `path` (creating it) and lock it; return the handle, or None if held."""
        handle = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(handle)
            return None
        return handle

    def unlock(handle: int) -> None:
        """Release a lock taken by `lock_exclusively` and close its handle."""
        os.close(handle)
