"""One Run or `change-passphrase` at a time per operator (spec #37 story 16; #26)."""

from types import TracebackType
from typing import Self

from network_analyser import _winsys
from network_analyser.run_output.data_folder import DataFolder


class InstanceLock:
    """The held single-instance lock. Release it, or leave a `with` block, to let go."""

    __slots__ = ("_handle",)

    def __init__(self, handle: int) -> None:
        """Wrap a handle `_winsys.lock_exclusively` returned."""
        self._handle: int | None = handle

    def release(self) -> None:
        """Let another Run or `change-passphrase` start. Safe to call twice."""
        if self._handle is not None:
            _winsys.unlock(self._handle)
            self._handle = None

    def __enter__(self) -> Self:
        """Hold the lock for the `with` block."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Release the lock, however the block ended."""
        self.release()


def take_instance_lock(data: DataFolder) -> InstanceLock | None:
    """Take the lock in the data folder (creating the folder), or return None if it is held.

    The lock file is never deleted: removing it while another process waits would let two
    holders in at once.
    """
    data.root.mkdir(parents=True, exist_ok=True)
    handle = _winsys.lock_exclusively(data.lock_file)
    return None if handle is None else InstanceLock(handle)
