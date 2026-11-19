"""Keep the CML lab's Device Role in step with `role-snippet` (#53; ADR 0005).

    python -m scripts.lab_roles          # rewrite lab/network-analyser-lab.yaml in place
    python -m scripts.lab_roles --check  # exit 1 if the lab file is out of step

The lab's account `netanalyser` holds the role `network-analyser role-snippet` prints,
generated from the allow-list. When a ticket changes the allow-list,
tests/unit/test_lab_role.py fails until this script has been run. Only the role body is
rewritten: the IOS-XE view keeps its lab secret `CHANGE_ME`, which the snippet leaves to be
typed by hand, and the account lines stay as they are.
"""

import argparse
import sys
from pathlib import Path
from typing import Final

from network_analyser import platforms
from network_analyser.platforms.roles import ROLE_NAME
from network_analyser.records import Platform

REPO_ROOT: Final = Path(__file__).resolve().parent.parent
LAB_FILE: Final = REPO_ROOT / "lab" / "network-analyser-lab.yaml"
LAB_USERNAME: Final = "netanalyser"
LAB_SECRET: Final = "CHANGE_ME"  # noqa: S105  # the lab placeholder, never a real secret

_IOS_XE_START: Final = f"parser view {ROLE_NAME}"
_NX_OS_START: Final = f"role name {ROLE_NAME}"


def _pasted_lines(platform: Platform) -> list[str]:
    """The lines of the snippet a device acts on: the role itself."""
    text = platforms.role_snippet(platform, LAB_USERNAME, tacacs=False)
    return [line for line in text.splitlines() if line.strip() and not line.startswith("!")]


def regenerate(text: str) -> str:
    """Return the lab file with every Device Role block replaced by the snippet's."""
    ios_xe = _pasted_lines(Platform.IOS_XE)
    nx_os = _pasted_lines(Platform.NX_OS)
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        indent = line[: len(line) - len(line.lstrip(" "))]
        index += 1
        if line.strip() == _IOS_XE_START:
            out += [f"{indent}{ios_xe[0]}\n", f"{indent} secret {LAB_SECRET}\n"]
            out += [f"{indent}{body}\n" for body in ios_xe[1:]]
            while index < len(lines) and lines[index].startswith(f"{indent} "):
                index += 1  # the old body, up to the view's closing "!"
        elif line.strip() == _NX_OS_START:
            out += [f"{indent}{role}\n" for role in nx_os]
            while index < len(lines) and lines[index].startswith(f"{indent}  "):
                index += 1  # the old description and rules
        else:
            out.append(line)
    return "".join(out)


def main(argv: list[str] | None = None) -> int:
    """Rewrite the lab file, or with --check say whether it is in step."""
    parser = argparse.ArgumentParser(prog="python -m scripts.lab_roles")
    parser.add_argument("--check", action="store_true", help="change nothing; exit 1 if stale")
    args = parser.parse_args(argv)
    text = LAB_FILE.read_text(encoding="utf-8")
    fresh = regenerate(text)
    if args.check:
        if fresh != text:
            print("lab file Device Role is out of step: run python -m scripts.lab_roles")
            return 1
        return 0
    if fresh != text:
        LAB_FILE.write_text(fresh, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
