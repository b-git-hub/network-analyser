# pytest temp roots

A recurring Windows problem: two pytest processes on one PC share
`%TEMP%\pytest-of-<user>` and its `pytest-current` link, so one dies in session cleanup with
`PermissionError [WinError 5]` and prints no summary. Two fixes, one per route into pytest.

## 2026-11-22: the gate route (#167)

On 2026-11-22 [#167](https://github.com/b-git-hub/network-analyser/issues/167) gave
`scripts/check.py` a `tempfile.mkdtemp` root per invocation, passed to its pytest subprocess as
`PYTEST_DEBUG_TEMPROOT` and removed in a `finally`. Merged at `bf22e2b`
(`b-git-hub/network-analyser`); see the gate baseline page's "Parallel runs" section.

That fixed only gated runs. A direct `pytest` or `pytest -m security` still used the shared root,
and on 2026-11-22 several #129 sessions hit the crash, including a merger that had to re-run the
security suite. [#193](https://github.com/b-git-hub/network-analyser/issues/193) tracked it.

## 2026-11-23: the direct route (#193)

On 2026-11-23 [#193](https://github.com/b-git-hub/network-analyser/issues/193) was fixed on
`ticket-193-pytest-temp-root` at `39f47d7` (`b-git-hub/network-analyser`), delivered as PR
[#200](https://github.com/b-git-hub/network-analyser/pull/200):

- `tests/support/pytest_temp_root.py`'s `seed_pytest_temp_root` sets `PYTEST_DEBUG_TEMPROOT` to a
  fresh `tempfile.mkdtemp(prefix="pytest-na-")` root and registers an `atexit`
  `shutil.rmtree(..., ignore_errors=True)`.
- `tests/conftest.py` calls it at import time. pytest reads `PYTEST_DEBUG_TEMPROOT` lazily, at the
  first `tmp_path` use, so this runs first.
- A **non-empty**, already-set value is left alone. That is what keeps #167's gate root, and the
  operator's documented workaround, behaving as before; `scripts/check.py` was not edited. An
  empty value is treated as unset, because pytest would otherwise fall back to the shared root.
- No `-p` plugin, no `--basetemp`, no `pyproject.toml` change.

Evidence at `39f47d7` (2026-11-23, operator's Windows PC): with the fix removed, 20 of 20 pairs
of concurrent direct runs crashed with the `pytest-current` `PermissionError` and no summary;
with the fix, two full concurrent direct runs in two worktrees both printed
`21 failed, 3228 passed, 1 skipped`, and two concurrent `pytest -m security` runs both summarised
(`250 passed` each). The gate matched the 21 known Windows failures node for node.

The independent review of PR #200 found one real flaw before merge, on 2026-11-23: the new
session test asserted the inherited root must sit under `%TEMP%`, which rejects the documented
worktree-local workaround (`$env:PYTEST_DEBUG_TEMPROOT = Join-Path $PWD '.pytest-tmp'`) even
though pytest works with it. Fixed in `39f47d7`. Lesson for the next harness test: exercise the
documented workaround path, not only the default one.

## Consequences and false friends

- From `39f47d7`, a `pytest-na-*` directory left in `%TEMP%` means a test leaked a file handle, not
  that the seeding failed: Windows will not remove a directory a live handle still holds. The
  same PR closed the ten `tests/unit/test_audit_log.py` `AuditLog`s (raw `os.open` handles) that
  had blocked removal on a full run.
- The private root is removed at interpreter exit, so pytest's usual "keep the temp dirs of the
  last three failed runs" no longer survives a direct run. Pass `--basetemp <dir>` to keep the
  artefacts of a failing run: pytest then uses that directory and ignores the seeded root.
- A non-empty `PYTEST_DEBUG_TEMPROOT` already in the environment wins, whatever its path. Setting
  it to a shared path re-creates the race on purpose; that is the documented workaround's trade.
- The seeding is in `tests/`, so it covers every pytest invocation that collects this repo's
  `tests/` tree, including `build.ps1`'s `-E -m pytest -m security` run (its `-E` does not hide
  `PYTEST_DEBUG_TEMPROOT`, which is not a `PYTHON*` variable).
- A hard kill (Ctrl+C twice, a task kill) skips `atexit`, so a `pytest-na-*` root can survive.
  Delete it by hand; the name makes it recognisable.

See also [review-fixes-gate-baseline-2026-11-22](review-fixes-gate-baseline-2026-11-22.md) and
[agent-worktree-friction](agent-worktree-friction.md).
