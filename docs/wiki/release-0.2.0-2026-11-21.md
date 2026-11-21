# Release 0.2.0, 2026-11-21

Built on 2026-11-21 on branch `ticket-111-release`, at the commit ending `(#111)`. This is the
first published release ([#111](https://github.com/b-git-hub/network-analyser/issues/111),
[spec #92](https://github.com/b-git-hub/network-analyser/issues/92)). The tag, the GitHub
Release and the lab results are the operator's, not this session's.

## What the release carries

- **Version 0.2.0** in `pyproject.toml`, `network_analyser/_version.py` and `uv.lock`'s virtual
  project entry. The release workflow compares the tag with `pyproject.toml`'s version
  (`docs/releasing.md`, decision #32), and `scripts/release_gate.py`'s docstring examples now
  use `v0.2.0`.
- **`CHANGELOG.md` 0.2.0 entry**, dated 2026-11-21, opening with Breaking changes then
  Allow-list and Device Role: the new read-only commands listed in both, the instruction to
  re-apply the Device Role, `topology.json` format version 2, and Cisco lookups on by default
  with exit code 1 until a key is stored. Added, Changed and Security then summarise Analysis
  (Advisory, hardening, consistency, lifecycle, v1 re-ranked), `findings.html`, the Findings
  tab and Map markers, the Run report, the Cisco API Key and the lookups switch. It states that
  openVuln covers NX-OS only from July 2019 and that nothing Cisco returns is stored between
  Runs.
- **The lab Device Role was already in step.** `python -m scripts.lab_roles` rewrote nothing and
  `python -m scripts.lab_roles --check` exits 0: the checked-in role in
  `lab/network-analyser-lab.yaml` already carries the 0.2.0 commands, because the allow-list
  tickets (#97, #98) regenerated it as they landed. Security test 1 (allow-list gate) and test
  2 (`role-snippet`) pass, as do `tests/unit/test_lab_role.py`'s three tests.
- **Lab checklist:** sections K ([#97](https://github.com/b-git-hub/network-analyser/issues/97))
  and L ([#98](https://github.com/b-git-hub/network-analyser/issues/98)) already covered every
  new command string, its JSON form and whether its output holds a secret. #111 adds section M
  for Analysis, the Cisco lookups and the Findings outputs, and records the spec's known limit
  that Software Suggestion rejects CML's virtual PIDs, so the Suggested Release Check cannot be
  shown there. Every Result and Date cell is left for the operator: no lab run is claimed.

## Gates

- `uv run --locked python scripts/check.py`: ruff format, ruff lint and both mypy runs pass;
  pytest ends `2471 passed, 1 skipped, 21 failed`. The 21 failures are exactly the pre-existing
  Windows ACL, `socketpair` and package-build failures listed in the baseline; no new failure
  and no previously passing test removed.
- `uv run --locked python -m scripts.release_gate check --tag v0.2.0` passes, so the entry is
  dated, opens with the two required sections, and the tag would match the version.
- `build.ps1` succeeded at commit `9a75eed` on 2026-11-21: the clean-checkout gate, signed
  python.org CPython 3.14.10, `uv sync --locked --no-build`, all 246 security tests, the
  licence check, PyInstaller `--onedir --noupx`, a version resource that matches `--version`
  (0.2.0), and `dist\network-analyser-0.2.0-win-x64.zip` (17.8 MB, 37.6 MB unpacked) with
  `SHA256SUMS.txt`. It made no change to the checkout. The build that becomes the GitHub
  Release is still the operator's, rebuilt on `main` after merging.

## Left to the operator

- Merge the release branch to `main`, then run `build.ps1` on the merged commit and follow
  `docs/releasing.md` sections 1-4. #111 created no tag, pushed no branch and published
  nothing.
- Fill sections K, L and M on the next CML booking; the Software Suggestion limit above is the
  one expected non-pass.
