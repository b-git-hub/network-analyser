r"""Paths over 260 characters work on Windows through the `\\?\` form (#42, story 122).

The Windows behaviour itself is checked by hand on a Windows PC (lab checklist, G3).
"""

import pytest

from network_analyser import _winsys


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        pytest.param("C:\\Users\\op\\runs", "\\\\?\\C:\\Users\\op\\runs", id="drive path"),
        pytest.param("C:/Users/op/runs", "\\\\?\\C:\\Users\\op\\runs", id="forward slashes"),
        pytest.param("D:\\a\\.\\b\\..\\c", "\\\\?\\D:\\a\\c", id="dot parts resolved"),
        pytest.param("\\\\files\\team\\runs", "\\\\?\\UNC\\files\\team\\runs", id="network share"),
        pytest.param("\\\\?\\C:\\already", "\\\\?\\C:\\already", id="already long"),
    ],
)
def test_an_absolute_windows_path_gets_the_extended_length_prefix(path: str, expected: str) -> None:
    assert _winsys.extended_length(path) == expected


def test_a_path_far_over_260_characters_keeps_every_part() -> None:
    deep = "C:\\" + "\\".join(["a-very-long-folder-name"] * 20)

    long_form = _winsys.extended_length(deep)

    assert len(deep) > 260
    assert long_form == "\\\\?\\" + deep


@pytest.mark.parametrize("path", ["runs\\here", "\\no-drive", "C:relative"])
def test_a_relative_path_is_refused(path: str) -> None:
    with pytest.raises(ValueError, match="absolute"):
        _winsys.extended_length(path)
