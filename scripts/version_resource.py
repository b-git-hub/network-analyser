"""The exe's Windows version resource, in PyInstaller's version-file format (ticket #44).

scripts/network_analyser.spec writes it at build time from `network_analyser.__version__`,
so the resource and `--version` cannot disagree (story 178). build.ps1 then reads the
resource back from the built exe and fails if it differs.
"""

import re

_SEMVER_0_Y_Z = re.compile(r"0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")

_TEMPLATE = """\
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({numbers}),
    prodvers=({numbers}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('FileDescription', 'Network Analyser'),
        StringStruct('FileVersion', '{version}'),
        StringStruct('InternalName', 'network-analyser'),
        StringStruct('OriginalFilename', 'network-analyser.exe'),
        StringStruct('ProductName', 'Network Analyser'),
        StringStruct('ProductVersion', '{version}'),
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def version_file_text(version: str) -> str:
    """Return the version file for a SemVer 0.y.z version (decision #32)."""
    if not _SEMVER_0_Y_Z.fullmatch(version):
        msg = f"the version must be SemVer 0.y.z, not {version!r}"
        raise ValueError(msg)
    numbers = ", ".join([*version.split("."), "0"])
    return _TEMPLATE.format(version=version, numbers=numbers)
