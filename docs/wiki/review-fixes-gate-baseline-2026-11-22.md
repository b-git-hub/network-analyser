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

The run on 2026-11-22 at `6ce2cf9` finished `21 failed, 2970 passed, 1 skipped in
113.87s`. The two intermittents happened to pass, so the 21 below are the pure Windows
baseline.

## Exact failing node ids

- `tests/unit/test_package_build.py::test_the_sums_cover_every_file_in_the_folder_and_the_zip_itself`
- `tests/unit/test_run_start_folder.py::test_permissions_the_tool_cannot_read_are_warned_about`
- `tests/unit/test_run_start_folder.py::test_a_run_checks_the_trust_folder`
- `tests/unit/test_runs_parent_check.py::test_permissions_are_read_from_a_folder_made_where_the_run_folder_will_go`
- `tests/unit/test_ssh.py::test_the_client_identifies_itself_as_network_analyser`
- `tests/unit/test_ssh.py::test_only_modern_algorithms_are_offered`
- `tests/unit/test_ssh.py::test_a_known_device_is_asked_only_for_its_trusted_key_type[trusted0-asked0]`
- `tests/unit/test_ssh.py::test_a_known_device_is_asked_only_for_its_trusted_key_type[trusted1-asked1]`
- `tests/unit/test_ssh.py::test_a_known_device_is_asked_only_for_its_trusted_key_type[trusted2-asked2]`
- `tests/unit/test_ssh.py::test_the_handshake_hands_back_the_identification_string_and_host_key`
- `tests/unit/test_ssh.py::test_no_algorithm_in_common_is_recorded_as_too_old`
- `tests/unit/test_ssh.py::test_one_password_attempt_and_no_key_or_agent_lookup`
- `tests/unit/test_ssh.py::test_a_refused_password_is_a_failed_login`
- `tests/unit/test_trust_folder_check.py::test_another_account_that_can_change_the_folder_refuses[other0]`
- `tests/unit/test_trust_folder_check.py::test_another_account_that_can_change_the_folder_refuses[other1]`
- `tests/unit/test_trust_folder_check.py::test_another_account_that_can_change_the_folder_refuses[other2]`
- `tests/unit/test_trust_folder_check.py::test_another_account_that_can_only_read_the_folder_refuses_too`
- `tests/unit/test_trust_folder_check.py::test_an_account_on_the_known_hosts_file_itself_is_caught`
- `tests/unit/test_trust_folder_check.py::test_before_the_first_run_the_folder_it_will_inherit_from_is_read`
- `tests/unit/test_trust_folder_check.py::test_permissions_windows_will_not_give_refuse[modify]`
- `tests/unit/test_trust_folder_check.py::test_permissions_windows_will_not_give_refuse[read]`

## Parallel runs

**No longer needed from merge commit `bf22e2b` (2026-11-22, [#167](https://github.com/b-git-hub/network-analyser/issues/167)):**
`scripts/check.py` now gives every invocation its own `PYTEST_DEBUG_TEMPROOT` directory, so the
workaround below is retired. A plain `uv run --locked python scripts/check.py` in several
worktrees at once was observed to print full summaries with no `PermissionError`. The text
below is kept as the dated record of the earlier race.

**Extended to direct runs on 2026-11-23 (`ticket-193-pytest-temp-root@39f47d7`, PR
[#200](https://github.com/b-git-hub/network-analyser/pull/200), [#193](https://github.com/b-git-hub/network-analyser/issues/193)):**
`tests/conftest.py` now seeds a private `pytest-na-*` root for a direct `pytest` or
`pytest -m security` run too, unless one is already set. The workaround below is retired for
every run that collects this repo's `tests/` tree. See [pytest-temp-roots](pytest-temp-roots.md).

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
