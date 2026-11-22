# Release 0.3.1, 2026-11-22

Cut on branch `ticket-187-release-0.3.1`, from the integration branch
`build/review-fixes-0.3.1` at `47f73c2`, for
[#187](https://github.com/b-git-hub/network-analyser/issues/187), the last child of
[#129](https://github.com/b-git-hub/network-analyser/issues/129). It is a patch release for the
review fixes on 0.2.0 and 0.3.0: the version bump, the changelog entry and the release gates.
The tag, the GitHub Release, `build.ps1` on merged `main` and the CML/live checks are the
operator's, not this session's.

## What the release carries

- **Version 0.3.1** in `pyproject.toml`, `network_analyser/_version.py` and `uv.lock`'s virtual
  project entry. The docstring examples in `scripts/release_gate.py` and
  `scripts/package_build.py` now use 0.3.1. The release workflow compares the tag with
  `pyproject.toml`'s version ([docs/releasing.md](../releasing.md), decision #32).
- **`CHANGELOG.md` 0.3.1 entry**, dated 2026-11-22, opening with Breaking changes then
  Allow-list and Device Role, then Changed, Fixed and Security. It covers every ticket that
  landed after 0.3.0: #130-#135, #137-#147, #149-#167, including the ones that merged before
  the per-file merge log existed and left only comment text on their tickets. Test-only work is
  summarised rather than itemised.
- **No allow-list or Device Role change**, so no re-apply: `uv run --locked python -m
  scripts.lab_roles --check` exits 0 and `lab/network-analyser-lab.yaml` is unchanged.
- **No new lab-checklist row**: 0.3.1 adds no command, flag for a Run, or Run folder file the
  operator must exercise, and every open CML item stays with its own ticket (see below).

## Breaking changes: none

The entry writes `None.`, so the release gate keeps this a patch bump. Each candidate was
checked against [docs/releasing.md](../releasing.md):

- **`topology.json` stays format version 3.** 0.3.1 adds only optional fields:
  `router_operating_mode` (#147) and the Nexus series token (#134/#159). `render` ignores keys
  it does not know, and `docs/topology-json.md` says an optional field needs no bump, so a
  0.3.0 `render` still reads a 0.3.1 Run folder and a 0.3.1 `render` reads 0.3.0 folders.
  `fix_unresolved` and `latest_in_train` were already optional fields of version 3.
- **The allow-list and Device Role are unchanged.** No command was added, renamed or removed,
  so the role from 0.3.0 keeps working.
- **`cisco-key show --last-4`** is a new option on an existing command; `show` without it asks
  for no passphrase. `cisco-key set --proxy` is also new. Nothing was renamed or removed, and
  the key file's format is unchanged.
- **The NX-OS Train spelling** (`7.0I7`, `7.3D1`, `3.6E`) changes the text Findings and
  reports show. `train` is still text in `topology.json`, and the operator reads a different
  label without having to act before the tool works.
- **Type 5 on IOS-XE, and PAD/BOOTP at their default**, add High Findings to existing configs.
  They change what the tool reports, not how it is operated: no command, file or credential
  changes, and the devices' configs are untouched. The entry calls them behaviour changes.
- **`cisco-key show` prompting less** removes a prompt; it asks the operator for nothing new.

## Gates

- `uv run --locked python scripts/check.py`: ruff format, ruff lint and both mypy runs pass;
  pytest ends `21 failed, 3219 passed, 1 skipped in 107.67s`, the 21 failures exactly the
  Windows ACL, `socketpair` and package-build node ids in
  [review-fixes-gate-baseline-2026-11-22](review-fixes-gate-baseline-2026-11-22.md). Both
  intermittents (#158, #160) passed.
- `uv run --locked python -m scripts.release_gate check --tag v0.3.1`:
  `Release gate passed for v0.3.1 (CHANGELOG.md entry dated 2026-11-22).`
- `uv run --locked python -m scripts.lab_roles --check`: exit 0, no rewrite.

## Left to the operator

- Approve and merge the single integration PR `build/review-fixes-0.3.1` -> `main`, which
  carries every #129 ticket and this release.
- On the merged `main`, run `build.ps1`, then follow [docs/releasing.md](../releasing.md)
  sections 1-4: tag `v0.3.1`, let the workflow publish it, download it and check the SHA-256
  against the run summary.
- CML and live checks that 0.3.1 depends on and does not claim:
  [#142](https://github.com/b-git-hub/network-analyser/issues/142) K5, K7, L1 and L7 (CoPP on a
  blank reply, `% Invalid input`, and the reworded Device Role Finding);
  [#132](https://github.com/b-git-hub/network-analyser/issues/132)'s proxy hand-check;
  [#134](https://github.com/b-git-hub/network-analyser/issues/134)'s CML NX-OS 10.4(3) check;
  [#164](https://github.com/b-git-hub/network-analyser/issues/164)'s remaining reply-shape
  probes; and [#165](https://github.com/b-git-hub/network-analyser/issues/165)'s software-EoX
  match-rule probe, which is why a software EoX answer still reads "could not check".

No tag, release or push to `main` exists from this session.
