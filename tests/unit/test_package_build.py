"""The release zip and SHA256SUMS.txt (ticket #44, decision #32 section 2 gate 7)."""

import hashlib
import zipfile
from pathlib import Path

from scripts.package_build import missing_plain_files, package


def _make_build_folder(root: Path) -> Path:
    folder = root / "dist" / "network-analyser"
    (folder / "_internal" / "alpha").mkdir(parents=True)
    (folder / "network-analyser.exe").write_bytes(b"synthetic exe")
    (folder / "_internal" / "alpha" / "__init__.py").write_text("x = 1\n")
    (folder / "THIRD-PARTY-NOTICES.txt").write_text("notices\n")
    return folder


def test_the_zip_holds_the_build_folder_contents_at_its_root(tmp_path: Path) -> None:
    folder = _make_build_folder(tmp_path)

    result = package(folder, tmp_path / "dist", "0.4.2")

    assert result.zip_path == tmp_path / "dist" / "network-analyser-0.4.2-win-x64.zip"
    with zipfile.ZipFile(result.zip_path) as archive:
        assert archive.namelist() == [
            "THIRD-PARTY-NOTICES.txt",
            "_internal/alpha/__init__.py",
            "network-analyser.exe",
        ]
        assert archive.read("network-analyser.exe") == b"synthetic exe"


def test_the_sums_cover_every_file_in_the_folder_and_the_zip_itself(tmp_path: Path) -> None:
    folder = _make_build_folder(tmp_path)

    result = package(folder, tmp_path / "dist", "0.4.2")

    def sha(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    zip_hash = sha(result.zip_path.read_bytes())
    assert result.sums_path == tmp_path / "dist" / "SHA256SUMS.txt"
    assert result.sums_path.read_text(encoding="ascii").splitlines() == [
        f"{sha(b'notices\n')}  THIRD-PARTY-NOTICES.txt",
        f"{sha(b'x = 1\n')}  _internal/alpha/__init__.py",
        f"{sha(b'synthetic exe')}  network-analyser.exe",
        f"{zip_hash}  network-analyser-0.4.2-win-x64.zip",
    ]
    assert result.zip_sha256 == zip_hash
    assert result.folder_bytes == len(b"notices\n") + len(b"x = 1\n") + len(b"synthetic exe")
    assert result.zip_bytes == result.zip_path.stat().st_size


def test_plain_file_modules_must_sit_beside_the_exe_as_source(tmp_path: Path) -> None:
    folder = _make_build_folder(tmp_path)
    (folder / "_internal" / "bravo.py").write_text("y = 2\n")

    assert missing_plain_files(folder, ["alpha", "bravo", "charlie"]) == ["charlie"]
