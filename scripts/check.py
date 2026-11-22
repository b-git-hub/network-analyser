"""Run every check a change must pass before it merges (CODING_STANDARDS.md, "Tooling").

    uv run --locked python scripts/check.py

Runs, in order, stopping at the first failure: ruff format check, ruff lint, mypy --strict
for the current platform and for Windows, and the whole pytest suite. Exits 0 only if all
pass. Works the same in Windows PowerShell 5.1 and on Linux.

Each invocation gives pytest a temporary root of its own (#167), so two gates running at
once in two worktrees never share pytest's `pytest-current` link.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CHECKS: list[tuple[str, list[str]]] = [
    ("ruff format", ["ruff", "format", "--check", "."]),
    ("ruff lint", ["ruff", "check", "."]),
    ("mypy (this platform)", ["mypy"]),
    ("mypy (Windows)", ["mypy", "--platform", "win32"]),
    ("pytest", ["pytest"]),
]


def gate_environment(pytest_temp_root: Path) -> dict[str, str]:
    """Return the environment for one run's checks, with pytest's own temp root (#167).

    pytest keeps its numbered directories and the `pytest-current` link under
    `PYTEST_DEBUG_TEMPROOT`, which must already exist. A shared root makes a second
    concurrent gate crash in session cleanup on Windows, with a `PermissionError` on
    `pytest-current` and no summary, so each run passes a fresh one.
    """
    return {**os.environ, "PYTEST_DEBUG_TEMPROOT": str(pytest_temp_root)}


def main() -> int:
    """Run each check; return 0 if all pass, else the failing check's exit code."""
    pytest_temp_root = Path(tempfile.mkdtemp(prefix="network-analyser-gate-"))
    environment = gate_environment(pytest_temp_root)
    try:
        for name, command in CHECKS:
            print(f"== {name}", flush=True)
            result = subprocess.run(
                [sys.executable, "-m", *command],
                cwd=REPO_ROOT,
                check=False,
                env=environment,
            )
            if result.returncode != 0:
                print(f"FAILED: {name}", flush=True)
                return result.returncode
    finally:
        shutil.rmtree(pytest_temp_root, ignore_errors=True)
    print("All checks passed.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
