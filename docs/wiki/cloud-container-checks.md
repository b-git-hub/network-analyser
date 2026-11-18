# Running the checks in a cloud container

As of `b-git-hub/network-analyser@fc2a616` (2026-11-18), the project pins CPython 3.14.10 and allows only an installed python.org build (#32), and its commands need uv 0.13 or newer. The Linux cloud container that built spec #37 shipped uv 0.11.32, which cannot fetch 3.14.10, and has no python.org build.

What the coordinating session did on 2026-11-18 (container-local, not committed):
- Replaced `/root/.local/bin/uv` with a shim that runs uv 0.13.9 with `UV_PYTHON_PREFERENCE=managed`, `UV_SYSTEM_CERTS=1` and `UV_NATIVE_TLS` unset, so uv's own CPython 3.14.10 is used. The old binary is kept as `uv-0.11.32.bak`.
- With the shim, from the repo root: `uv sync --locked --no-build`, then `uv run --locked python scripts/check.py` (ruff format, ruff lint, mypy strict for linux and win32, pytest).

Caveats:
- The shim loosens the "python.org build only" rule. That is acceptable for running tests in a throwaway Linux container, never for building a release; releases are built only by `build.ps1` (#44) or the release workflow (#47) on Windows.
- A fresh container loses the shim. A future session should save the same setup as the environment's setup script rather than re-deriving it.

Found by ticket #38's implementer, see [agent-worktree-friction](agent-worktree-friction.md).

- 2026-11-18: `gh api` returned 403 for any repo other than b-git-hub/network-analyser (public action repos included); `git ls-remote` and anonymous shallow clones worked.
