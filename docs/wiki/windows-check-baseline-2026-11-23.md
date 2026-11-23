# Windows check baseline (2026-11-23)

Recorded while reviewing #73 on this operator PC. The gate `scripts/check.py` is **not green on this machine**, so a branch is judged against the baseline below, not against an all-pass run.

## Pytest

On 2026-11-23, a worktree of branch `ticket/73-drag-positions` (from `b-git-hub/network-analyser@6a9d4f7`) gave **3224 passed, 21 failed, 1 skipped**. A pristine extract of `origin/main` at the same commit gave **3220 passed with the identical 21 failures**; the four extra passes were that branch's new tests. None of the failures touches the diagram.

The 21 are in three groups:

- `tests/unit/test_trust_folder_check.py`, `test_run_start_folder.py`, `test_runs_parent_check.py`: Windows ACL handling on this PC/user;
- `tests/unit/test_ssh.py`: Paramiko/OpenSSH behaviour on this PC;
- `tests/unit/test_package_build.py::test_the_sums_cover_every_file_in_the_folder_and_the_zip_itself`: zip sums, sensitive to line endings.

They were not investigated further. A branch that shows any *other* failure has a real problem; a branch that shows these 21 has the baseline.

`uv` writes its notices to stderr, which Windows PowerShell 5.1 reports as `NativeCommandError` even on success: read the output, not only the exit code.

## pytest temp root

Direct pytest runs race on the shared `%TEMP%\pytest-of-<user>\pytest-current` link and can end with `PermissionError: [WinError 5]` during cleanup (issue #193). Pass a private `--basetemp`, for example `--basetemp="$env:TEMP\na-pytest-<ticket>"`, for focused and full runs.

## Browser harness

The repo has no JavaScript test runner. On 2026-11-23, Node v26.13.1 plus `playwright-core` in a temp folder (not the repo) drove installed Edge with `chromium.launch({ channel: 'msedge', headless: true })`. `file://` pages allow `localStorage` there, so save/reload/reset and disabled-storage behaviour can be checked. A committed harness remains a candidate follow-up; for now, keep these scripts in the temp folder and record the results in the PR.

## Worktrees

The local `main` checkout is often far behind `origin/main`. Branch worktrees were made with `git worktree add -b ticket/<n>-<slug> <path> origin/main`; the staged file in the main checkout (`lab/check-cisco-release-sources.ps1` on 2026-11-23) is operator work and was left untouched.
