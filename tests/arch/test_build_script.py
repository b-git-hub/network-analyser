"""build.ps1 must run on the operator's Windows PowerShell 5.1 (ticket #44, CLAUDE.md).

PowerShell 7 accepts syntax that 5.1 rejects, and 5.1 reads a script without a byte-order
mark in the system code page, so these cheap static rules catch what a Linux run cannot.
The full 5.1 syntax check is PSScriptAnalyzer's PSUseCompatibleSyntax rule, run by hand.
"""

import re

from tests.support.source_scan import REPO_ROOT

BUILD_SCRIPT = REPO_ROOT / "build.ps1"


def _code_lines(text: str) -> list[tuple[int, str]]:
    """Return the script's lines outside its comment-based help block and # comments."""
    lines: list[tuple[int, str]] = []
    in_block = False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("<#"):
            in_block = True
        if in_block:
            in_block = not stripped.endswith("#>")
            continue
        if not stripped.startswith("#"):
            lines.append((number, line))
    return lines


def pipeline_chain_operators(text: str) -> list[int]:
    """Return the line numbers using `&&` or `||`, which Windows PowerShell 5.1 rejects."""
    return [number for number, line in _code_lines(text) if re.search(r"&&|\|\|", line)]


def test_the_script_is_plain_ascii_and_requires_powershell_5_1() -> None:
    raw = BUILD_SCRIPT.read_bytes()

    assert raw.isascii()
    assert raw.decode("ascii").splitlines()[0] == "#Requires -Version 5.1"


def test_the_script_uses_no_pipeline_chain_operators() -> None:
    assert pipeline_chain_operators(BUILD_SCRIPT.read_text(encoding="ascii")) == []


def test_the_pipeline_chain_rule_catches_a_planted_violation() -> None:
    planted = "<#\nhelp text may say a && b\n#>\ngit status && git log\n# a || b\nx || y\n"

    assert pipeline_chain_operators(planted) == [4, 6]


def test_powershell_scripts_keep_crlf_line_endings_on_checkout() -> None:
    attributes = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()

    assert "*.ps1 text eol=crlf" in attributes
