# Release 0.3.0, 2026-11-21

Built on 2026-11-21 on branch `ticket-125-release`, at the commit ending `(#125)`. It closes
[spec #122](https://github.com/b-git-hub/network-analyser/issues/122) as release 0.3.0, on top
of [Correct release order and Trains](https://github.com/b-git-hub/network-analyser/issues/123),
[Upgrade Target clears Advisories at their first fix and says what it leaves open](https://github.com/b-git-hub/network-analyser/issues/124),
[NX-OS Upgrade Target from Cisco's per-series fixes](https://github.com/b-git-hub/network-analyser/issues/126)
and [Latest Release from Cisco's compatible-release list](https://github.com/b-git-hub/network-analyser/issues/127).
The tag, the GitHub Release and the CML results are the operator's, not this session's.

## What the release carries

- **Version 0.3.0** in `pyproject.toml`, `network_analyser/_version.py` and `uv.lock`'s virtual
  project entry. The release workflow compares the tag with `pyproject.toml`'s version
  (`docs/releasing.md`, decision #32), and the docstring examples in `scripts/release_gate.py`
  and `scripts/package_build.py` now use 0.3.0.
- **`CHANGELOG.md` 0.3.0 entry**, dated 2026-11-21, opening with Breaking changes then Allow-list
  and Device Role. Breaking changes carries the `topology.json` format version bump to 3: each
  Visited Device now has an advice record with the not-cleared count, and an older `render` would
  draw a partial Upgrade Target as complete. Allow-list and Device Role is `None.`: 0.3.0 adds
  no show command, so the 0.2.0 Device Role keeps working and needs no re-apply. Changed
  summarises the release-order and Train fix (#123), the per-Advisory Upgrade Target with
  `not_cleared` (#124), the NX-OS target from `platforms[].firstFixes` (#126), the Latest
  Release from Cisco's compatible list with its lifecycle code (#127), and the four surfaces
  that show those values. Security records the compatible call's one-PID-per-call paging, the
  pattern-checked series alias, that `currentRelease` is never sent, and the Audit log's counts.
  The NX-OS entry states the limit: the Nexus 3000 name is an inference from Cisco's naming, and
  the Nexus 7700 and 2000 names were not confirmed, so those series stay `not available`.
- **GLOSSARY.md and ADR 0007 amendments.** Commits `1df7e5b` and `fc6b859` from
  `claude/great-allen-atcxfe` were cherry-picked onto the release branch because neither had
  landed on `main` by 2026-11-21. They give Train, Upgrade Target and Latest Release their new
  definitions, and amend ADR 0007 in place: the Nexus series alias is among the values that may
  be sent, the compatible-releases call takes one PID per call and is paged, and
  `currentRelease` is never sent.
- **The lab Device Role is already in step.** `python -m scripts.lab_roles --check` exits 0:
  no allow-list change means `lab/network-analyser-lab.yaml` needs no rewrite. Security test 1
  (allow-list gate) and test 2 (`role-snippet`) pass, 207 tests in the two files.
  `docs/lab-checklist.md` gains no section: the two CML checks for this release are on the PR
  and below, and every Result and Date cell stays for the operator.

## Gates

- `uv run --locked python scripts/check.py`: ruff format, ruff lint and both mypy runs pass;
  pytest ends `2557 passed, 1 skipped, 21 failed`. The 21 failures are exactly the pre-existing
  Windows ACL, `socketpair` and package-build failures listed in the baseline; no new failure
  and no previously passing test removed.
- `uv run --locked python -m scripts.release_gate check --tag v0.3.0` passes, so the entry is
  dated, opens with the two required sections, and the tag would match the version.
- `build.ps1` succeeded at commit `b039498` on 2026-11-21: the clean-checkout gate, signed
  python.org CPython 3.14.10, `uv sync --locked --no-build`, all 246 security tests, the licence
  check, PyInstaller `--onedir --noupx`, a version resource that matches `--version` (0.3.0), and
  `dist\network-analyser-0.3.0-win-x64.zip` (17.8 MB, 37.6 MB unpacked) with `SHA256SUMS.txt`.
  It made no change to the checkout. The build that becomes the GitHub Release is still the
  operator's, rebuilt on `main` after merging.

## Left to the operator

- Merge the release branch into `main`, then run `build.ps1` on the merged commit and follow
  `docs/releasing.md` sections 1-4. This session created no tag, pushed no branch and published
  nothing.
- On CML, with the release build: an NX-OS 10.4(3) node shows an Upgrade Target in Train 10.4
  that is no higher than `10.4(8)`, and its Latest Release reads `not available`, because Cisco
  rejects the lab's virtual PIDs. No result is claimed here.
- The single PR `build/0.3.0` → `main` lists the four feature tickets, the gate result and
  these operator-only items. No tag or release exists before the operator merges.
