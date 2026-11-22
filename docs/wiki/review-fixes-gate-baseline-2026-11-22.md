# Gate baseline: review fixes, 2026-11-22

Measured on `b-git-hub/network-analyser@6ce2cf9` (integration branch
`build/review-fixes-0.3.1`) on the operator's Windows PC with
`uv run --locked python scripts/check.py`.

As of 2026-11-22, before the Wave A fixes:

- ruff format, ruff lint and both mypy runs pass.
- pytest: 2969 passed, 1 skipped, 22 failed.
- The 21 known Windows failures are the pre-existing Windows ACL, `socketpair` and
  package-build failures recorded in the 0.2.0 and 0.3.0 release pages
  ([0.2.0](release-0.2.0-2026-11-21.md), [0.3.0](release-0.3.0-2026-11-21.md)).
- The 22nd is the intermittent `os.replace` `PermissionError` in
  `tests/unit/test_trust_store.py::test_new_keys_from_parallel_visits_are_all_kept`
  ([#158](https://github.com/b-git-hub/network-analyser/issues/158)).
- `tests/security/test_6_change_passphrase.py::test_a_power_cut_at_any_write_leaves_no_plaintext_and_each_file_old_or_new`
  is the second intermittent failure ([#160](https://github.com/b-git-hub/network-analyser/issues/160));
  it passed on this run.

The exact failing node ids are appended below when the baseline run finishes.

## Exact failing node ids

Pending the 2026-11-22 baseline run.

## Parallel runs

Until [#167](https://github.com/b-git-hub/network-analyser/issues/167) lands, two gates run
at once race on pytest's shared `pytest-current` temp link and one crashes at session finish
with `PermissionError [WinError 5]` and no summary. Set a worktree-local root before the gate:

```powershell
$root = Join-Path $env:TEMP ('na-pytest-' + (Split-Path $PWD -Leaf))
New-Item -ItemType Directory -Force -Path $root | Out-Null
$env:PYTEST_DEBUG_TEMPROOT = $root
```

The directory must exist before pytest starts; a non-existent value fails every test at
setup with `FileNotFoundError [WinError 3]`. #167 must create its unique directory with
`tempfile.mkdtemp` (or equivalent), not merely name one.

## How to read a gate result

A gate passes when ruff, format and mypy pass and every pytest failure is on this page's
list (or is one of the two intermittents while its ticket is still open). Any other failure
belongs to the ticket that introduced it.
