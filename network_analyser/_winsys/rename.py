"""Rename a file over another, waiting out the moment Windows refuses (#158).

On Windows another process (Defender, the search indexer, a backup agent) can hold the new
temporary file open for a moment, and the rename then raises `PermissionError`. Every
temp-then-rename writer in the tool goes through `retry_rename`, so such a moment does not
end a Run. The wait is bounded and only `PermissionError` is retried; any other `OSError`
is raised at once. `SLEEP` is the seam tests replace, so a retry never really sleeps.
"""

import time
from collections.abc import Callable

DELAYS: tuple[float, ...] = (0.1, 0.2, 0.4, 0.8)
"""Seconds to wait before each retry: 1.5 s in total, then the last error is raised."""

SLEEP: Callable[[float], None] = time.sleep
"""The wait itself: a module global, so tests replace it and never sleep for real."""


def retry_rename(rename: Callable[[], object]) -> None:
    """Run `rename`, retrying while Windows refuses it with `PermissionError`.

    `rename` is the writer's own call on its temporary file, already bound to both paths
    (`Path.replace` to overwrite, `Path.rename` to refuse an existing name), so this helper
    never decides whether a file may be replaced.

    Raises:
        PermissionError: the refusal outlasted `DELAYS`; the caller's fixed message for a
            failed write still applies.
        OSError: `rename` failed for any other reason; raised at once, never retried.
    """
    for delay in DELAYS:
        try:
            rename()
        except PermissionError:
            SLEEP(delay)
        else:
            return
    rename()
