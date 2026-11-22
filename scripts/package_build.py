"""Zip the one-folder build and write SHA256SUMS.txt (ticket #44, decision #32).

    python -m scripts.package_build --build-dir dist/network-analyser --dist-dir dist
        --version 0.3.1

The zip holds the build folder's contents at its root, so it unzips straight into
the per-version folder under `%LOCALAPPDATA%/Programs/NetworkAnalyser/` (decision #32
section 8).
SHA256SUMS.txt lists every file in the build folder by its path inside the zip, then the
zip itself. Before zipping, it checks that every LGPL module sits beside the exe as plain
source files.
"""

import argparse
import hashlib
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

from scripts.third_party_notices import REPO_ROOT, collect, plain_file_modules

ZIP_SIZE_TARGET_BYTES = 100 * 1024 * 1024  # decision #32 section 7: a warning, not a blocker
_CHUNK = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Packaged:
    """What `package` wrote."""

    zip_path: Path
    sums_path: Path
    zip_sha256: str
    zip_bytes: int
    folder_bytes: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _files(folder: Path) -> list[tuple[str, Path]]:
    found = [(p.relative_to(folder).as_posix(), p) for p in folder.rglob("*") if p.is_file()]
    return sorted(found)


def package(build_dir: Path, dist_dir: Path, version: str) -> Packaged:
    """Write `network-analyser-<version>-win-x64.zip` and SHA256SUMS.txt into `dist_dir`."""
    files = _files(build_dir)
    zip_path = dist_dir / f"network-analyser-{version}-win-x64.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, path in files:
            archive.write(path, name)
    zip_sha256 = _sha256(zip_path)
    lines = [f"{_sha256(path)}  {name}" for name, path in files]
    lines.append(f"{zip_sha256}  {zip_path.name}")
    sums_path = dist_dir / "SHA256SUMS.txt"
    sums_path.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    return Packaged(
        zip_path=zip_path,
        sums_path=sums_path,
        zip_sha256=zip_sha256,
        zip_bytes=zip_path.stat().st_size,
        folder_bytes=sum(path.stat().st_size for _, path in files),
    )


def missing_plain_files(build_dir: Path, modules: list[str]) -> list[str]:
    """Name each module that is not in `_internal` as a .py package or module."""
    internal = build_dir / "_internal"
    return [
        module
        for module in modules
        if not (internal / module / "__init__.py").is_file()
        and not (internal / f"{module}.py").is_file()
    ]


def _megabytes(size: int) -> str:
    return f"{size / (1024 * 1024):.1f} MB"


def main(argv: list[str] | None = None) -> int:
    """Check the LGPL plain files, then zip and hash the build folder."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args(argv)

    review, _ = collect(REPO_ROOT)
    modules = plain_file_modules(review)
    missing = missing_plain_files(args.build_dir, modules)
    if review.refusals or not modules or missing:
        print(f"FAILED: LGPL modules not kept as plain files: {', '.join(missing) or '-'}")
        return 1

    result = package(args.build_dir, args.dist_dir, args.version)
    print(f"LGPL modules kept as plain files: {', '.join(modules)}")
    print(f"Build folder: {_megabytes(result.folder_bytes)} unpacked")
    print(f"Zip: {result.zip_path} ({_megabytes(result.zip_bytes)})")
    print(f"Zip SHA-256: {result.zip_sha256}")
    print(f"Sums: {result.sums_path}")
    if result.zip_bytes > ZIP_SIZE_TARGET_BYTES:
        print(
            f"WARNING: the zip is {_megabytes(result.zip_bytes)}, over the 100 MB target"
            " (a warning, not a blocker; decision #32)."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
