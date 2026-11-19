# Releasing Network Analyser

How a version is built, tagged, published, checked and installed. Decided on [#32](https://github.com/b-git-hub/network-analyser/issues/32); built by [#44](https://github.com/b-git-hub/network-analyser/issues/44) (`build.ps1`) and [#47](https://github.com/b-git-hub/network-analyser/issues/47) (the release workflow).

The short version: the operator builds and tests a commit on `main` with `build.ps1`, then tells a Claude session "release `<commit>` as v0.y.z". The session checks the commit and pushes only that tag. The tag starts [`.github/workflows/release.yml`](../.github/workflows/release.yml), which builds the same commit again on a `windows-2025` runner through the same gates and publishes the zip as the Latest GitHub Release.

## Versioning

SemVer held at **0.y.z** for the whole prototype; 1.0.0 is kept for the proper-deployment phase. A **minor** bump (0.y.0) for a breaking change, a **patch** bump for anything else.

A change is **breaking** when, after upgrading, the operator must act before the tool works as before, or files from one version can't be used by the other:

- The allow-list **gains** a command, so the Device Role must be re-applied with `role-snippet`. Removing a command is not breaking, but every allow-list change is listed.
- A command or flag is renamed or removed.
- The Run folder layout or its file names change.
- The Trust Store, Run register, Backup check file or Backup/manifest format changes. The entry must state the migration step.
- `topology.json`'s format version goes up (only when an older `render` would misread the file).

Everything else is a patch: parser fixes, new findings, the diagram's look, dependency bumps, a Python patch bump.

The version lives in `pyproject.toml` and `network_analyser/_version.py`, which must agree (`tests/arch/test_project.py`). It appears in the exe's version resource, `--version`, the run report and `audit.log`.

## Release notes template

A release's notes are its `CHANGELOG.md` entry, so the entry is the template. `tests/unit/test_release_gate.py` checks every entry, and the release gate refuses a tag whose entry breaks the template:

```markdown
## [0.y.z] - YYYY-MM-DD

### Breaking changes

None.  <- or a list: what changed and what the operator must do, with any migration step

### Allow-list and Device Role

None.  <- or each command added or removed

### Added / ### Changed / ### Fixed / ### Security  (any, optional)
```

- Breaking changes always come first, then the allow-list; write `None.` rather than leaving either out.
- An entry that lists breaking changes must be a minor bump (0.y.0).
- Entries go newest first, and each release is higher than every entry below it.

The workflow (`scripts/release_gate.py notes`) adds, after the entry:

- a **Re-apply the Device Role** reminder whenever the allow-list section is not `None.`;
- the system requirements: Windows 11 64-bit, 8 GiB of RAM, 4 logical cores; no Windows 10 or Windows Server;
- that the build is unsigned, so SmartScreen will warn and Smart App Control or an IT policy may block it;
- how to check the download, with the zip's SHA-256 and a link to the run summary;
- the zip and unpacked sizes;
- the install steps below.

## 1. Prepare and test the release (operator)

1. On a branch, set the new version in `pyproject.toml` and `network_analyser/_version.py`, and rename `## [Unreleased]` in `CHANGELOG.md` to `## [0.y.z] - YYYY-MM-DD`. Merge it to `main`.
2. Check out that commit **on `main`** (a merge makes a new commit, so build after merging) and run `build.ps1`. It ends with `To release exactly this build, ask a Claude session: release <commit> as v0.y.z`.
3. Test the build however you judge fit, for example on a booked CML lab with [lab-checklist.md](lab-checklist.md).
4. Tell a Claude session: **release `<commit>` as v0.y.z**. That is permission for that one tag and nothing else.

## 2. Tagging procedure (Claude session)

Only when the operator has named both the commit and the version in their own message. Never tag a commit the operator didn't name, never pick a version yourself, and never move, delete or force-push a tag.

Run each command on its own (the operator's shell is Windows PowerShell 5.1, which rejects `&&`). Stop and tell the operator at the first check that fails.

1. Fetch: `git fetch origin main --tags`
2. The commit is on `main`: `git merge-base --is-ancestor <commit> origin/main` must exit 0.
3. The commit's version matches the tag:
   - `git show <commit>:pyproject.toml` shows `version = "0.y.z"`;
   - `git show <commit>:network_analyser/_version.py` shows `__version__ = "0.y.z"`.
4. The commit has a changelog entry: `git show <commit>:CHANGELOG.md` has `## [0.y.z] - YYYY-MM-DD`, opening with `### Breaking changes` then `### Allow-list and Device Role`. If you have a checkout of exactly that commit, `uv run --locked python -m scripts.release_gate check --tag v0.y.z` runs the same gate as the workflow.
5. The tag is new: `git ls-remote --tags origin v0.y.z` prints nothing.
6. Tag exactly that commit: `git tag -a v0.y.z <commit> -m "Network Analyser 0.y.z"`
7. Push **only the tag**: `git push origin refs/tags/v0.y.z`. Never `--tags`, never a branch in the same push.
8. Give the operator the link to the run on the repository's Actions tab.

## 3. What the workflow does

Triggered only by pushing a tag matching `v0.[0-9]+.[0-9]+`; nothing runs on ordinary pushes or pull requests. The `build` job (read-only token) on `windows-2025`:

1. checks out the tagged commit, without keeping credentials, and refuses it unless it is on `main`;
2. installs the CPython patch in `.python-version` with `actions/setup-python` (the python.org installer);
3. runs the release gate: the tag is `v0.y.z`, equals `pyproject.toml`'s version, and has a `CHANGELOG.md` entry that follows the template;
4. installs uv (pinned version and checksum, no cache);
5. runs `build.ps1 -Python <that interpreter>` under Windows PowerShell 5.1, so every local gate runs unchanged: clean checkout, python.org signature and exact patch, `uv sync --locked --no-build`, the six security tests, the licence check, PyInstaller `--onedir --noupx`, version resource, zip and `SHA256SUMS.txt`;
6. writes the release notes and hands the zip, sums and notes to the `publish` job.

The `publish` job (the only one with `contents: write`) checks the zip against `SHA256SUMS.txt`, prints the zip's SHA-256 in the **run summary**, and runs `gh release create --latest` with the zip and `SHA256SUMS.txt`. A tag that already has a release fails here; nothing is overwritten.

Every action is pinned to a full commit SHA. To update one, resolve the new tag's commit with `git ls-remote --tags https://github.com/<owner>/<action>` (take the `^{}` line for an annotated tag), read the action's `action.yml` at that commit, and update the SHA and the version comment together. To bump uv, change `version` and `checksum` together; the checksum is the `uv-x86_64-pc-windows-msvc.zip` line of that uv release's `sha256.sum`.

## 4. Check the download and smoke-test it (operator)

1. Download `network-analyser-<version>-win-x64.zip` from the release.
2. In PowerShell: `(Get-FileHash -Algorithm SHA256 .\network-analyser-<version>-win-x64.zip).Hash.ToLowerInvariant()`. Compare it with the SHA-256 in the **workflow run summary**, not only the release notes: notes can be edited later, the run summary cannot.
3. Install it (below) and run it with `--version`. Then it can be used on real networks.

If a release misbehaves, edit its notes to say so and ship the fix as the next patch. Nothing is deleted.

## 5. Install

- Unzip each version into its own folder, `%LOCALAPPDATA%\Programs\NetworkAnalyser\<version>\`, never over an older one:
  `Expand-Archive -Path .\network-analyser-<version>-win-x64.zip -DestinationPath "$env:LOCALAPPDATA\Programs\NetworkAnalyser\<version>"`
- There is no installer, no PATH change and no admin rights. Run `network-analyser.exe` by its full path or from a shortcut, as a standard user.
- Every version shares the Trust Store, Run register and Run folders in the per-user data folder, so upgrading keeps them. Old version folders stay until the operator deletes them.
- The build is unsigned in v1: SmartScreen warns about an unknown publisher for each new version. If Smart App Control or an IT policy blocks the exe, a `.pyd` or a DLL, record it on the lab checklist: that is the trigger to bring signing forward (#32).

## 6. One-time setup on GitHub (operator)

- **Required: two-factor sign-in on the GitHub account** (#32). With no code signature, the account is the lock on the release files.
- **Immutable releases**, if GitHub offers them for this private repository on your plan (Settings, General, Releases). With them on, a published release's files and tag can't be changed. The workflow uploads the files before publishing, so it works either way.
- Recommended: a tag ruleset (Settings, Rules, Rulesets) for `v*` tags that blocks updates, deletions and force-pushes, matching "nothing is deleted".
- Recommended: Settings, Actions, General: keep the default workflow token read-only (the workflow asks for `contents: write` only in its publish job) and require actions to be pinned to a full-length commit SHA.
- Windows runner minutes count double against a private repository's Actions allowance.
