"""The tool reads the registry and never writes it (spec #37, stories 18-19; decision #6).

The crash-dump guard reads HKLM; Windows Error Reporting is suppressed with SetErrorMode,
never with WerAddExcludedApplication, which writes to the registry. This scan finds any
registry-writing call or access right, whether through `winreg` or by name through `ctypes`.
"""

import ast
import textwrap

from tests.support.source_scan import source_files

# winreg names that create, change, delete, load or save keys, or ask for write access.
WINREG_WRITES = frozenset(
    {
        "CreateKey",
        "CreateKeyEx",
        "DeleteKey",
        "DeleteKeyEx",
        "DeleteValue",
        "SetValue",
        "SetValueEx",
        "SaveKey",
        "LoadKey",
        "FlushKey",
        "DisableReflectionKey",
        "EnableReflectionKey",
        "KEY_WRITE",
        "KEY_SET_VALUE",
        "KEY_CREATE_SUB_KEY",
        "KEY_CREATE_LINK",
        "KEY_ALL_ACCESS",
    }
)
# Win32 functions reached through ctypes that write the registry.
WIN32_WRITE_PREFIXES = (
    "RegCreateKey",
    "RegSetValue",
    "RegSetKeyValue",
    "RegDeleteKey",
    "RegDeleteValue",
    "RegDeleteTree",
    "RegSaveKey",
    "RegRestoreKey",
    "RegLoadKey",
    "RegReplaceKey",
    "RegCopyTree",
    "WerAddExcludedApplication",
    "WerRemoveExcludedApplication",
)


def registry_writes(relative: str, tree: ast.Module) -> list[str]:
    """Find every name, attribute or string in a file that would write the registry."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        name: str | None = None
        if isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.Name):
            name = node.id
        elif isinstance(node, ast.alias):
            name = node.name.rsplit(".", 1)[-1]
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            name = node.value
        if name is not None and (name in WINREG_WRITES or name.startswith(WIN32_WRITE_PREFIXES)):
            found.append((getattr(node, "lineno", 0), name))
    return [f"{relative}:{line} {name}" for line, name in sorted(found)]


def test_the_package_never_writes_the_registry() -> None:
    broken = [v for source in source_files() for v in registry_writes(source.relative, source.tree)]

    assert broken == []


def test_a_planted_registry_write_is_caught() -> None:
    code = textwrap.dedent("""
        import winreg
        from winreg import SetValueEx
        winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, "x", 0, winreg.KEY_WRITE)
        winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, "x", 0, winreg.KEY_READ)
        getattr(ctypes.windll.wer, "WerAddExcludedApplication")
        ctypes.windll.advapi32.RegSetValueExW
    """)

    found = registry_writes("_winsys/wer.py", ast.parse(code))

    assert found == [
        "_winsys/wer.py:3 SetValueEx",
        "_winsys/wer.py:4 CreateKeyEx",
        "_winsys/wer.py:4 KEY_WRITE",
        "_winsys/wer.py:6 WerAddExcludedApplication",
        "_winsys/wer.py:7 RegSetValueExW",
    ]
