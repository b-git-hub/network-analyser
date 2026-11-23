"""A pytest temp root private to one run, so two direct runs never share one (#193).

`scripts/check.py` has given its own pytest subprocess a private root since #167. A direct
`pytest` (or `pytest -m security`) run had none, so two of them in two worktrees shared
`%TEMP%\\pytest-of-<user>` and raced on its `pytest-current` link: one crashed at session
finish with `PermissionError [WinError 5]` and printed no summary.

`tests/conftest.py` calls `seed_pytest_temp_root` before pytest builds its base temp
directory. pytest reads `PYTEST_DEBUG_TEMPROOT` lazily, at the first `tmp_path` use, so a
call at conftest import time comes first. A non-empty root that is already set is left
alone, which keeps #167's gate root and the operator's documented workaround exactly as
they were; an empty one would make pytest fall back to the shared root, so it is replaced.
The root is removed again at interpreter exit, so `%TEMP%` does not fill with `pytest-na-*`
dirs.
"""

import atexit
import shutil
import tempfile
from collections.abc import MutableMapping
from pathlib import Path

VARIABLE = "PYTEST_DEBUG_TEMPROOT"
"""The variable pytest reads for its temp root."""

PREFIX = "pytest-na-"
"""The name prefix of each root, so a leftover one is recognisable in `%TEMP%`."""


def seed_pytest_temp_root(environment: MutableMapping[str, str]) -> Path | None:
    """Give pytest a private temp root in `environment`, unless it already names one.

    A name that is set but empty counts as unset: pytest treats it that way (`from_env or
    tempfile.gettempdir()`) and would otherwise fall back to the shared root.

    Args:
        environment: the environment mapping to seed, which is `os.environ` in `conftest.py`.

    Returns:
        The new root, which exists, or None when the environment already set a non-empty one.
    """
    if environment.get(VARIABLE):
        return None
    root = Path(tempfile.mkdtemp(prefix=PREFIX))
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    environment[VARIABLE] = str(root)
    return root
