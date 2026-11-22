"""The gate gives each of its runs a pytest temp root of its own (#167).

Two `scripts/check.py` runs in two worktrees can run at the same time on one PC. A shared
pytest temp root makes one of them crash in session cleanup on the `pytest-current` link,
printing no summary.
"""

import subprocess
from pathlib import Path

import pytest

from scripts import check as gate


def test_each_gate_run_gives_pytest_its_own_existing_temp_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setenv("PYTEST_DEBUG_TEMPROOT", str(shared))
    roots: list[Path] = []

    def fake_run(
        command: list[str], *, cwd: Path, check: bool, env: dict[str, str]
    ) -> subprocess.CompletedProcess[bytes]:
        assert cwd == gate.REPO_ROOT
        assert check is False
        assert "PATH" in env, "the gate keeps the caller's environment"
        root = Path(env["PYTEST_DEBUG_TEMPROOT"])
        assert root.is_dir(), "pytest needs the temp root to exist before it starts"
        roots.append(root)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("scripts.check.subprocess.run", fake_run)
    assert gate.main() == 0
    assert gate.main() == 0

    first = roots[: len(gate.CHECKS)]
    second = roots[len(gate.CHECKS) :]
    assert len(roots) == 2 * len(gate.CHECKS)
    assert len(set(first)) == 1, "one temp root for every check of one gate run"
    assert len(set(second)) == 1
    assert first[0] != second[0], "two gate runs never share a temp root"
    assert shared not in {*first, *second}, "an inherited shared root is overridden"
    assert not any(root.exists() for root in roots), "the temp root is removed afterwards"
