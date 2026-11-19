"""Project settings that keep the build reproducible (ticket #38; decisions #9, #32)."""

import re
import tomllib
from typing import Any

from network_analyser import __version__
from tests.support.source_scan import REPO_ROOT


def _toml(name: str) -> dict[str, Any]:
    return tomllib.loads((REPO_ROOT / name).read_text(encoding="utf-8"))


def test_the_version_is_semver_0_y_z_and_matches_pyproject() -> None:
    pyproject_version = _toml("pyproject.toml")["project"]["version"]

    assert re.fullmatch(r"0\.\d+\.\d+", __version__)
    assert __version__ == pyproject_version


def test_python_is_pinned_to_an_exact_3_14_patch() -> None:
    pinned = (REPO_ROOT / ".python-version").read_text(encoding="utf-8").strip()

    assert re.fullmatch(r"3\.14\.\d+", pinned)
    assert _toml("pyproject.toml")["project"]["requires-python"] == ">=3.14,<3.15"


def test_uv_never_uses_its_own_python_and_never_builds() -> None:
    uv = _toml("pyproject.toml")["tool"]["uv"]

    assert uv["python-preference"] == "only-system"
    assert uv["python-downloads"] == "never"
    assert uv["package"] is False
    assert uv["no-build"] is True


def test_every_locked_download_carries_a_hash() -> None:
    lock = _toml("uv.lock")
    downloads = [
        artefact
        for package in lock["package"]
        for artefact in [package.get("sdist"), *package.get("wheels", [])]
        if artefact is not None
    ]

    assert len(downloads) > 20
    assert [d["url"] for d in downloads if not d.get("hash", "").startswith("sha256:")] == []
