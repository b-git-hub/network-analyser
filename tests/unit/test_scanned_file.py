"""The one scanned writer for the Run folder's plaintext files (#48 follow-up, #52).

Text passes through the Run's secret scan and is written temp-then-rename, so a file is
either whole or not there. JSON data is scanned value by value before it is encoded, because
JSON's escapes could hide a secret holding a quote or backslash from a scan of the text.
"""

import json
from pathlib import Path

import pytest

from network_analyser import run_output
from network_analyser.credentials import Secret, SecretScan

CANARY = 'CANARY-pw-"9b\\q'


def _scan() -> SecretScan:
    scan = SecretScan()
    scan.watch(Secret(CANARY))
    return scan


def _folder(tmp_path: Path) -> run_output.RunFolder:
    return run_output.RunFolder(path=tmp_path, io_path=tmp_path)


def test_text_is_written_whole_with_secrets_blocked(tmp_path: Path) -> None:
    scan = _scan()

    hits = run_output.write_scanned_text(_folder(tmp_path), "notes.txt", f"a {CANARY} b", scan)

    assert hits == 1
    assert (tmp_path / "notes.txt").read_text(encoding="utf-8") == "a [blocked] b"
    assert scan.hits == 1
    assert [p.name for p in tmp_path.iterdir()] == ["notes.txt"]  # no temp file left


def test_json_values_are_scanned_before_escaping_could_hide_a_secret(tmp_path: Path) -> None:
    data = {"hostname": CANARY, "names": [f"x{CANARY}y"], CANARY: 1, "count": 2}

    hits = run_output.write_scanned_json(_folder(tmp_path), "topology.json", data, _scan())

    text = (tmp_path / "topology.json").read_text(encoding="utf-8")
    assert hits == 3
    assert json.loads(text) == {
        "hostname": "[blocked]",
        "names": ["x[blocked]y"],
        "[blocked]": 1,
        "count": 2,
    }
    assert CANARY not in text
    assert json.dumps(CANARY)[1:-1] not in text


def test_a_file_that_already_exists_is_replaced(tmp_path: Path) -> None:
    (tmp_path / "topology.json").write_text("old", encoding="utf-8")

    run_output.write_scanned_json(_folder(tmp_path), "topology.json", {"a": 1}, SecretScan())

    assert json.loads((tmp_path / "topology.json").read_text(encoding="utf-8")) == {"a": 1}


@pytest.mark.parametrize("name", ["../escape.txt", "sub/name.json", "", "a."])
def test_only_a_plain_file_name_in_the_run_folder_is_written(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError, match="not a plain file name"):
        run_output.write_scanned_text(_folder(tmp_path), name, "x", SecretScan())
