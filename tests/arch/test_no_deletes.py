"""The tool never deletes a Run folder or a Backup (spec #37 story 104; decided on #26).

A static rule: calls that remove files or folders appear only in the files listed in
DELETE_OWNERS, each for a named file of the tool's own that is never a Run folder or a
Backup. A ticket that adds one adds it here and says why in the commit. Like the other
rules, it runs over the real package and over a planted snippet.
"""

import ast
import textwrap

from tests.support.source_scan import source_files

DELETE_OWNERS: frozenset[str] = frozenset(
    {
        # #42: removes its own "can a Run folder be written here" probe, made before any
        # prompt and never a Run folder.
        "run_output/folder.py",
        # #58: removes the change-pending marker and the previous check file when a change
        # of the Backup Passphrase finishes: the tool's own bookkeeping in the per-user
        # folder, never a Run folder or a Backup.
        "backup_store/change_pending.py",
        # #103: removes the Cisco API key file for `cisco-key remove` and when the operator
        # starts over (deleting the check file): the tool's own key file, never a Run folder
        # or a Backup.
        "backup_store/cisco_key.py",
    }
)
_DELETE_METHODS = frozenset({"unlink", "rmdir"})  # Path.unlink(), Path.rmdir()
_DELETE_FUNCTIONS = {
    "os": frozenset({"remove", "unlink", "rmdir", "removedirs"}),
    "shutil": frozenset({"rmtree"}),
}


def deletes(relative: str, tree: ast.Module) -> list[str]:
    """Find calls that remove files or folders outside DELETE_OWNERS."""
    if relative in DELETE_OWNERS:
        return []
    return [
        f"{relative}:{node.lineno} deletes"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _deletes(node.func)
    ]


def _deletes(func: ast.expr) -> bool:
    if not isinstance(func, ast.Attribute):
        return isinstance(func, ast.Name) and func.id == "rmtree"
    module = func.value.id if isinstance(func.value, ast.Name) else None
    if module in _DELETE_FUNCTIONS:
        return func.attr in _DELETE_FUNCTIONS[module]
    return func.attr in _DELETE_METHODS | {"rmtree"}


def test_the_package_deletes_only_in_the_named_owners() -> None:
    broken = [v for source in source_files() for v in deletes(source.relative, source.tree)]

    assert broken == []


def test_deletes_are_caught_outside_the_owners() -> None:
    code = textwrap.dedent("""
        import os, shutil
        from pathlib import Path
        from shutil import rmtree
        Path("a").unlink()
        Path("a").rmdir()
        os.remove("a")
        os.rmdir("a")
        shutil.rmtree("a")
        rmtree("a")
        os.path.join("a", "b")
        Path("a").exists()
    """)

    found = deletes("backup_store/relock.py", ast.parse(code))

    assert found == [f"backup_store/relock.py:{line} deletes" for line in range(5, 11)]
