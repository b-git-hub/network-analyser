"""The release gate and release notes (ticket #47, decision #32 sections 2, 4 and 5)."""

from pathlib import Path

import pytest

from scripts.release_gate import (
    BuiltZip,
    built_zip,
    changelog_problems,
    check_release,
    main,
    release_notes,
)
from tests.support.source_scan import REPO_ROOT

PYPROJECT = '[project]\nname = "network-analyser"\nversion = "0.4.0"\n'

CHANGELOG = """\
# Changelog

## [Unreleased]

### Breaking changes

None.

### Allow-list and Device Role

None.

## [0.4.0] - 2026-12-01

### Breaking changes

- The Run folder layout changed: Backups now sit under `backups/`.

### Allow-list and Device Role

- Added `show inventory`.

### Fixed

- A parser fix.

## [0.3.1] - 2026-11-20

### Breaking changes

None.

### Allow-list and Device Role

None.
"""


def test_a_tag_that_matches_the_version_and_its_changelog_entry_passes() -> None:
    assert check_release("v0.4.0", PYPROJECT, CHANGELOG) == []


def test_only_a_semver_0_y_z_tag_is_released() -> None:
    for tag in ("0.4.0", "v1.0.0", "v0.4", "v0.04.0", "v0.4.0-rc1", "v0.4.0 "):
        assert check_release(tag, PYPROJECT, CHANGELOG) == [
            f"The tag must be v0.y.z (SemVer 0.y.z, decision #32), not {tag!r}."
        ]


def test_the_tag_must_match_the_version_in_pyproject() -> None:
    assert check_release("v0.3.1", PYPROJECT, CHANGELOG) == [
        "The tag is v0.3.1 but pyproject.toml says version 0.4.0."
    ]


def test_the_version_needs_a_dated_changelog_entry() -> None:
    undated = CHANGELOG.replace("## [0.4.0] - 2026-12-01", "## [0.4.0]")

    assert check_release("v0.4.0", PYPROJECT, undated) == [
        "CHANGELOG.md has no entry for 0.4.0: add a heading '## [0.4.0] - YYYY-MM-DD'."
    ]


def test_the_released_entry_must_be_the_newest_and_higher_than_every_older_one() -> None:
    older_on_top = CHANGELOG.replace("## [0.3.1] - 2026-11-20", "## [0.5.0] - 2026-11-20")

    assert check_release("v0.4.0", PYPROJECT, older_on_top) == [
        (
            "CHANGELOG.md lists 0.5.0 below 0.4.0: entries go newest first, and a release"
            " must be higher than every earlier one."
        )
    ]


def test_breaking_changes_then_the_allow_list_must_open_every_entry() -> None:
    swapped = CHANGELOG.replace("### Fixed", "### Breaking changes", 1).replace(
        "### Breaking changes\n\n- The Run", "### Fixed\n\n- The Run", 1
    )
    emptied = CHANGELOG.replace("- Added `show inventory`.", "")

    assert check_release("v0.4.0", PYPROJECT, swapped) == [
        (
            "CHANGELOG.md [0.4.0] must open with '### Breaking changes' then"
            " '### Allow-list and Device Role' (write 'None.' when there are none)."
        )
    ]
    assert check_release("v0.4.0", PYPROJECT, emptied) == [
        (
            "CHANGELOG.md [0.4.0] has an empty '### Allow-list and Device Role' section:"
            " write 'None.' when there is nothing to say."
        )
    ]


def test_a_breaking_change_needs_a_minor_bump() -> None:
    for patch_version in ("0.4.1", "0.4.10"):
        patch = CHANGELOG.replace("[0.4.0]", f"[{patch_version}]")
        pyproject = PYPROJECT.replace("0.4.0", patch_version)

        assert check_release(f"v{patch_version}", pyproject, patch) == [
            (
                f"CHANGELOG.md [{patch_version}] lists breaking changes, so the version must bump"
                " the minor (0.y.0), not the patch (decision #32 section 5)."
            )
        ]


def test_every_entry_including_unreleased_follows_the_template() -> None:
    broken = CHANGELOG.replace("## [Unreleased]\n\n### Breaking changes", "## [Unreleased]\n")

    assert changelog_problems(CHANGELOG) == []
    assert changelog_problems(broken) == [
        (
            "CHANGELOG.md [Unreleased] must open with '### Breaking changes' then"
            " '### Allow-list and Device Role' (write 'None.' when there are none)."
        )
    ]


def test_the_repos_changelog_follows_the_template() -> None:
    assert changelog_problems((REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")) == []


BUILT = BuiltZip(
    name="network-analyser-0.4.0-win-x64.zip",
    sha256="ab" * 32,
    zip_bytes=31 * 1024 * 1024,
    folder_bytes=88 * 1024 * 1024,
)
RUN_URL = "https://github.com/example/network-analyser/actions/runs/1"


def test_release_notes_put_breaking_changes_first_and_state_the_fixed_facts() -> None:
    notes = release_notes(CHANGELOG, "0.4.0", BUILT, RUN_URL)

    lines = notes.splitlines()
    assert lines[0] == "# Network Analyser 0.4.0"
    assert next(line for line in lines[1:] if line.startswith("#")) == "## Breaking changes"
    for fact in (
        "- The Run folder layout changed: Backups now sit under `backups/`.",
        "- A parser fix.",
        "Windows 11 64-bit, 8 GiB of RAM and 4 logical cores",
        "not code-signed",
        "SmartScreen",
        f"`{'ab' * 32}`",
        f"[workflow run summary]({RUN_URL})",
        "Get-FileHash -Algorithm SHA256 .\\network-analyser-0.4.0-win-x64.zip",
        "31.0 MB zip, 88.0 MB unpacked",
        "%LOCALAPPDATA%\\Programs\\NetworkAnalyser\\0.4.0\\",
        "Trust Store, Run register and Run folders",
    ):
        assert fact in notes
    assert notes.index("## Breaking changes") < notes.index("## Allow-list and Device Role")
    assert notes.index("## Allow-list and Device Role") < notes.index("## Fixed")
    assert "0.3.1" not in notes
    assert "Unreleased" not in notes


def test_an_allow_list_change_reminds_the_operator_to_re_apply_the_device_role() -> None:
    reminder = "Re-apply the Device Role"

    changed = release_notes(CHANGELOG, "0.4.0", BUILT, RUN_URL)
    unchanged = release_notes(
        CHANGELOG.replace("- Added `show inventory`.", "None."), "0.4.0", BUILT, RUN_URL
    )

    allow_list = changed[changed.index("## Allow-list") : changed.index("## Fixed")]
    assert reminder in allow_list
    assert "`network-analyser role-snippet`" in allow_list
    assert reminder not in unchanged


def _repo(root: Path) -> Path:
    (root / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (root / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8")
    return root


def test_the_check_command_exits_0_only_when_the_gate_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _repo(tmp_path)

    passed = main(["check", "--tag", "v0.4.0", "--repo-root", str(root)])
    passed_out = capsys.readouterr().out
    failed = main(["check", "--tag", "v0.3.1", "--repo-root", str(root)])
    failed_out = capsys.readouterr().out

    assert passed == 0
    assert "Release gate passed for v0.4.0 (CHANGELOG.md entry dated 2026-12-01)." in passed_out
    assert failed == 1
    assert "FAILED: The tag is v0.3.1 but pyproject.toml says version 0.4.0." in failed_out


def test_the_notes_command_writes_notes_for_the_built_zip(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    dist = tmp_path / "dist"
    (dist / "network-analyser" / "_internal").mkdir(parents=True)
    (dist / "network-analyser" / "network-analyser.exe").write_bytes(b"12345")
    (dist / "network-analyser" / "_internal" / "x.py").write_bytes(b"678")
    (dist / "network-analyser-0.4.0-win-x64.zip").write_bytes(b"abc")
    out = tmp_path / "notes.md"

    code = main(
        [
            "notes",
            "--tag",
            "v0.4.0",
            "--repo-root",
            str(root),
            "--dist-dir",
            str(dist),
            "--run-url",
            RUN_URL,
            "--out",
            str(out),
        ]
    )

    notes = out.read_text(encoding="utf-8")
    assert code == 0
    assert notes.startswith("# Network Analyser 0.4.0\n")
    assert "`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`" in notes
    assert built_zip(dist, "0.4.0") == BuiltZip(
        name="network-analyser-0.4.0-win-x64.zip",
        sha256="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        zip_bytes=3,
        folder_bytes=8,
    )
