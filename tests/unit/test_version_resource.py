"""The exe's Windows version resource carries the same 0.y.z as --version (story 178, #44)."""

import ast

import pytest

from scripts.version_resource import version_file_text


def _string_table(text: str) -> dict[object, object]:
    """Return the name -> value pairs of every StringStruct(name, value) in the text."""
    return {
        ast.literal_eval(node.args[0]): ast.literal_eval(node.args[1])
        for node in ast.walk(ast.parse(text, mode="eval"))
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "StringStruct"
    }


def _keyword(text: str, name: str) -> object:
    for node in ast.walk(ast.parse(text, mode="eval")):
        if isinstance(node, ast.keyword) and node.arg == name:
            return ast.literal_eval(node.value)
    raise AssertionError(name)


def test_the_resource_names_the_version_as_text_and_as_numbers() -> None:
    text = version_file_text("0.12.3")

    strings = _string_table(text)
    assert strings["FileVersion"] == "0.12.3"
    assert strings["ProductVersion"] == "0.12.3"
    assert strings["ProductName"] == "Network Analyser"
    assert strings["OriginalFilename"] == "network-analyser.exe"
    assert _keyword(text, "filevers") == (0, 12, 3, 0)
    assert _keyword(text, "prodvers") == (0, 12, 3, 0)


@pytest.mark.parametrize("version", ["1.0.0", "0.1", "0.1.0-rc1", "0.1.0'"])
def test_anything_but_a_0_y_z_version_is_refused(version: str) -> None:
    with pytest.raises(ValueError, match=r"SemVer 0\.y\.z"):
        version_file_text(version)
