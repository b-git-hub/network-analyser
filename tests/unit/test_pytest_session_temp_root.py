"""A direct pytest run keeps its temp files under a private root of its own (#193).

Two direct `pytest` runs in two worktrees can run at the same time on one PC. With no
`PYTEST_DEBUG_TEMPROOT`, both use the shared `%TEMP%\\pytest-of-<user>` root, so one crashes
in session cleanup on the `pytest-current` link and prints no summary. `tests/conftest.py`
seeds the variable before pytest builds its base temp directory.
"""

import os
import tempfile
from pathlib import Path

import pytest


def test_the_session_keeps_its_temp_files_under_a_private_root(
    tmp_path_factory: pytest.TempPathFactory, request: pytest.FixtureRequest
) -> None:
    if request.config.getoption("basetemp") is not None:
        pytest.skip("--basetemp was given, so pytest ignores PYTEST_DEBUG_TEMPROOT")

    seeded = os.environ.get("PYTEST_DEBUG_TEMPROOT")
    assert seeded is not None, "tests/conftest.py must seed PYTEST_DEBUG_TEMPROOT"
    root = Path(seeded).resolve()

    assert root.is_dir(), "pytest needs the root to exist before it starts"
    shared = Path(tempfile.gettempdir()).resolve()
    assert root != shared, "a direct run must not fall back to the shared system temp folder"
    assert shared in root.parents, "the private root sits in the system temp folder"
    assert root in tmp_path_factory.getbasetemp().resolve().parents, (
        "pytest must build its base temp directory under the private root"
    )
