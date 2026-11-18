"""Where the per-user folder is, and Windows long paths (spec #37 "Per-user data"; #26).

The only file that reads the environment, and only `LOCALAPPDATA`, by literal name
(CODING_STANDARDS.md, "Secrets"). Nothing secret is ever read from the environment.
"""

import os
import sys
from pathlib import Path, PureWindowsPath

_EXTENDED = "\\\\?\\"
_EXTENDED_UNC = _EXTENDED + "UNC\\"


def local_app_data() -> Path | None:
    """Return `%LOCALAPPDATA%` as an absolute path, or None when it is unset or not absolute.

    Read the same way on every OS, so tests on Linux point it at a temporary folder.
    """
    value = os.environ.get("LOCALAPPDATA")
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else None


def extended_length(path: str) -> str:
    r"""Return a Windows absolute path in its `\\?\` extended-length form (#26, story 122).

    With the prefix, Windows file calls accept paths longer than 260 characters without the
    `LongPathsEnabled` registry setting. `C:\a` becomes `\\?\C:\a`, `\\server\share\a` becomes
    `\\?\UNC\server\share\a`, and a path that already has the prefix is returned unchanged.
    The prefix turns off Windows' own clean-up of the path, so `/`, `.` and `..` are resolved
    here first.

    Raises:
        ValueError: the path is not an absolute Windows path.
    """
    if path.startswith(_EXTENDED):
        return path
    pure = PureWindowsPath(path)
    if not pure.is_absolute():
        msg = "a long path must be absolute"
        raise ValueError(msg)
    parts: list[str] = []
    for part in pure.parts[1:]:
        if part == "..":
            if parts:
                parts.pop()
        elif part != ".":
            parts.append(part)
    normal = str(PureWindowsPath(pure.anchor, *parts))
    if normal.startswith("\\\\"):
        return _EXTENDED_UNC + normal[2:]
    return _EXTENDED + normal


if sys.platform == "win32":

    def os_path(path: Path) -> Path:
        r"""Return the form of an absolute path to hand to file calls: `\\?\` on Windows."""
        return Path(extended_length(str(path)))

else:

    def os_path(path: Path) -> Path:
        """Return the path unchanged: only Windows has the 260-character limit."""
        return path
