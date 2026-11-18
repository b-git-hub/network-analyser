"""Run every check a change must pass before it merges (CODING_STANDARDS.md, "Tooling").

    uv run --locked python scripts/check.py

Runs, in order, stopping at the first failure: ruff format check, ruff lint, mypy --strict
for the current platform and for Windows, and the whole pytest suite. Exits 0 only if all
pass. Works the same in Windows PowerShell 5.1 and on Linux.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CHECKS: list[tuple[str, list[str]]] = [
    ("ruff format", ["ruff", "format", "--check", "."]),
    ("ruff lint", ["ruff", "check", "."]),
    ("mypy (this platform)", ["mypy"]),
    ("mypy (Windows)", ["mypy", "--platform", "win32"]),
    ("pytest", ["pytest"]),
]


def main() -> int:
    """Run each check; return 0 if all pass, else the failing check's exit code."""
    for name, command in CHECKS:
        print(f"== {name}", flush=True)
        result = subprocess.run([sys.executable, "-m", *command], cwd=REPO_ROOT, check=False)
        if result.returncode != 0:
            print(f"FAILED: {name}", flush=True)
            return result.returncode
    print("All checks passed.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
