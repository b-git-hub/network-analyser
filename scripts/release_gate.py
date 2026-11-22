"""The release workflow's own gate and its release notes (ticket #47, decision #32).

    python -m scripts.release_gate check --tag v0.3.1
    python -m scripts.release_gate notes --tag v0.3.1 --dist-dir dist --run-url <url>
        --out <file>

`check` is decision #32's first gate, which only the workflow runs: the tag is v0.y.z, equals
pyproject.toml's version, and has a CHANGELOG.md entry that follows the template (breaking
changes first, then the allow-list, and a breaking change bumps the minor). It uses only the
standard library, so it runs before `uv sync`.
`notes` writes the GitHub Release notes for the zip build.ps1 made: the version's changelog
entry, then the system requirements, the unsigned-build warning, the download check, the sizes
and the install steps (stories 171, 175-177, 179).
"""

import argparse
import hashlib
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_TAG = re.compile(r"v(0\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))")
BREAKING = "Breaking changes"
ALLOW_LIST = "Allow-list and Device Role"
NONE = "None."

_RELEASED = re.compile(
    r"\[(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\] - (?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})"
)


@dataclass(frozen=True, slots=True)
class Section:
    """A `### ` subsection of a changelog entry."""

    heading: str
    body: str


@dataclass(frozen=True, slots=True)
class Entry:
    """A `## ` entry of CHANGELOG.md: `[Unreleased]`, or a released version and its date."""

    heading: str
    version: str | None
    date: str | None
    sections: tuple[Section, ...]


def _sections(text: str) -> tuple[Section, ...]:
    parts = re.split(r"^### ", text, flags=re.MULTILINE)[1:]
    sections = []
    for part in parts:
        heading, _, body = part.partition("\n")
        sections.append(Section(heading=heading.strip(), body=body.strip()))
    return tuple(sections)


def changelog_entries(changelog_text: str) -> list[Entry]:
    """Split CHANGELOG.md into its `## ` entries, newest first as written."""
    entries = []
    for part in re.split(r"^## ", changelog_text, flags=re.MULTILINE)[1:]:
        heading, _, body = part.partition("\n")
        heading = heading.strip()
        released = _RELEASED.fullmatch(heading)
        entries.append(
            Entry(
                heading=heading,
                version=released.group("version") if released else None,
                date=released.group("date") if released else None,
                sections=_sections(body),
            )
        )
    return entries


def check_release(tag: str, pyproject_text: str, changelog_text: str) -> list[str]:
    """Return one line per reason the tag may not be released; empty means it may."""
    match = _TAG.fullmatch(tag)
    if match is None:
        return [f"The tag must be v0.y.z (SemVer 0.y.z, decision #32), not {tag!r}."]
    version = match.group(1)
    problems: list[str] = []
    project_version = tomllib.loads(pyproject_text)["project"]["version"]
    if project_version != version:
        problems.append(f"The tag is {tag} but pyproject.toml says version {project_version}.")
    entries = changelog_entries(changelog_text)
    released = [e for e in entries if e.version == version]
    if not released:
        problems.append(
            f"CHANGELOG.md has no entry for {version}: add a heading '## [{version}] - YYYY-MM-DD'."
        )
        return problems
    entry = released[0]
    older = entries[entries.index(entry) + 1 :]
    problems.extend(
        f"CHANGELOG.md lists {e.version} below {version}: entries go newest first, and a release"
        " must be higher than every earlier one."
        for e in older
        if e.version is not None and _numbers(e.version) >= _numbers(version)
    )
    problems.extend(entry_problems(entry))
    if _breaking(entry) and _numbers(version)[2] != 0:
        problems.append(
            f"CHANGELOG.md [{version}] lists breaking changes, so the version must bump the minor"
            " (0.y.0), not the patch (decision #32 section 5)."
        )
    return problems


def changelog_problems(changelog_text: str) -> list[str]:
    """Return how each entry, `[Unreleased]` included, departs from the template."""
    return [
        problem for entry in changelog_entries(changelog_text) for problem in entry_problems(entry)
    ]


def entry_problems(entry: Entry) -> list[str]:
    """Return how an entry departs from the template: breaking changes, then the allow-list."""
    opening = tuple(section.heading for section in entry.sections[:2])
    if opening != (BREAKING, ALLOW_LIST):
        return [
            (
                f"CHANGELOG.md {entry.heading.split(' ')[0]} must open with '### {BREAKING}' then"
                f" '### {ALLOW_LIST}' (write '{NONE}' when there are none)."
            )
        ]
    return [
        f"CHANGELOG.md {entry.heading.split(' ')[0]} has an empty '### {section.heading}'"
        f" section: write '{NONE}' when there is nothing to say."
        for section in entry.sections
        if not section.body
    ]


@dataclass(frozen=True, slots=True)
class BuiltZip:
    """The release zip as built: its file name, SHA-256 and sizes."""

    name: str
    sha256: str
    zip_bytes: int
    folder_bytes: int


_DEVICE_ROLE_REMINDER = (
    "**Re-apply the Device Role:** the allow-list changed, so before the first Run with this"
    " version, run `network-analyser role-snippet` and apply its output on every device the"
    " tool logs into."
)

_BEFORE_YOU_INSTALL = """\
## Before you install

- **System requirements:** Windows 11 64-bit, 8 GiB of RAM and 4 logical cores. Windows 10 \
and Windows Server are not supported; below that spec the tool still starts, but nothing is \
promised.
- **Unsigned build:** this build is not code-signed (decision #32). SmartScreen warns about \
an unknown publisher for every new version, and Smart App Control or an IT policy (AppLocker, \
WDAC) may block the exe or its DLL and `.pyd` files.
- **Check the download** before you unzip it: in PowerShell run \
`Get-FileHash -Algorithm SHA256 .\\{zip_name}` and compare the hash with the SHA-256 in the \
[workflow run summary]({run_url}), which cannot be edited after the run. It should be \
`{sha256}`.
- **Size:** {zip_mb} zip, {folder_mb} unpacked.

## Install

1. Unzip into a folder of its own, never over an older version: \
`%LOCALAPPDATA%\\Programs\\NetworkAnalyser\\{version}\\`. For example: \
`Expand-Archive -Path .\\{zip_name} -DestinationPath \
"$env:LOCALAPPDATA\\Programs\\NetworkAnalyser\\{version}"`.
2. There is no installer, no PATH change and no admin rights. Run the exe by its full path, or \
from a shortcut, as a standard user. To check it starts: \
`& "$env:LOCALAPPDATA\\Programs\\NetworkAnalyser\\{version}\\network-analyser.exe" --version`.
3. Every version shares the Trust Store, Run register and Run folders in your per-user data \
folder. Older version folders stay until you delete them.
"""


def release_notes(changelog_text: str, version: str, built: BuiltZip, run_url: str) -> str:
    """Return the GitHub Release notes: the version's changelog entry, then the fixed facts."""
    entry = next(e for e in changelog_entries(changelog_text) if e.version == version)
    parts = [f"# Network Analyser {version}"]
    for section in entry.sections:
        parts.append(f"## {section.heading}\n\n{section.body}")
        if section.heading == ALLOW_LIST and section.body != NONE:
            parts.append(_DEVICE_ROLE_REMINDER)
    parts.append(
        _BEFORE_YOU_INSTALL.format(
            version=version,
            zip_name=built.name,
            sha256=built.sha256,
            run_url=run_url,
            zip_mb=_megabytes(built.zip_bytes),
            folder_mb=_megabytes(built.folder_bytes),
        ).strip()
    )
    return "\n\n".join(parts) + "\n"


def _megabytes(size: int) -> str:
    return f"{size / (1024 * 1024):.1f} MB"


def _breaking(entry: Entry) -> bool:
    return any(s.heading == BREAKING and s.body != NONE for s in entry.sections)


def _numbers(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


_CHUNK = 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def built_zip(dist_dir: Path, version: str) -> BuiltZip:
    """Describe the zip and build folder that build.ps1 left in `dist_dir`."""
    zip_path = dist_dir / f"network-analyser-{version}-win-x64.zip"
    folder = dist_dir / "network-analyser"
    return BuiltZip(
        name=zip_path.name,
        sha256=_sha256(zip_path),
        zip_bytes=zip_path.stat().st_size,
        folder_bytes=sum(p.stat().st_size for p in folder.rglob("*") if p.is_file()),
    )


def _read(root: Path, name: str) -> str:
    return (root / name).read_text(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    """Run `check` or `notes`; return 0 on success, 1 if the gate refuses the tag."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="the tag, version and CHANGELOG.md gate")
    notes = commands.add_parser("notes", help="write the GitHub Release notes")
    for command in (check, notes):
        command.add_argument("--tag", required=True)
        command.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    notes.add_argument("--dist-dir", type=Path, required=True)
    notes.add_argument("--run-url", required=True)
    notes.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    changelog = _read(args.repo_root, "CHANGELOG.md")
    problems = check_release(args.tag, _read(args.repo_root, "pyproject.toml"), changelog)
    if problems:
        for problem in problems:
            print(f"FAILED: {problem}")
        return 1
    version = args.tag.removeprefix("v")
    if args.command == "check":
        date = next(e.date for e in changelog_entries(changelog) if e.version == version)
        print(f"Release gate passed for {args.tag} (CHANGELOG.md entry dated {date}).")
        return 0
    text = release_notes(changelog, version, built_zip(args.dist_dir, version), args.run_url)
    args.out.write_text(text, encoding="utf-8", newline="\n")
    print(f"Release notes: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
