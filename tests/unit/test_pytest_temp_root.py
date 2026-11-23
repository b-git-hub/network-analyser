"""The support module gives pytest a private temp root when no root is set (#193).

The function takes the environment mapping it seeds, so a test never changes the real
environment. `tests/conftest.py` calls it with `os.environ` for every run.
"""

import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.support.pytest_temp_root import seed_pytest_temp_root


@pytest.fixture
def made_roots() -> Iterator[list[Path]]:
    """Collect the roots a test makes, and remove them afterwards."""
    roots: list[Path] = []
    yield roots
    for root in roots:
        shutil.rmtree(root, ignore_errors=True)


def test_an_unset_environment_gets_an_existing_private_root(made_roots: list[Path]) -> None:
    environment: dict[str, str] = {}

    root = seed_pytest_temp_root(environment)

    assert root is not None
    made_roots.append(root)
    assert root.is_dir(), "pytest needs the root to exist before it starts"
    assert root != Path(tempfile.gettempdir())
    assert environment["PYTEST_DEBUG_TEMPROOT"] == str(root)


def test_each_call_with_no_root_set_makes_a_different_root(made_roots: list[Path]) -> None:
    roots = [seed_pytest_temp_root({}) for _ in range(2)]
    made_roots.extend(root for root in roots if root is not None)

    assert None not in roots
    assert len(set(roots)) == 2, "two runs never share a temp root"


def test_a_root_already_set_is_left_alone(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    environment = {"PYTEST_DEBUG_TEMPROOT": str(shared)}

    assert seed_pytest_temp_root(environment) is None
    assert environment == {"PYTEST_DEBUG_TEMPROOT": str(shared)}
