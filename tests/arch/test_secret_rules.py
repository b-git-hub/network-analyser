"""Static rules that keep secrets and exception text in memory (CLAUDE.md, spec #37).

Each rule is a function from one parsed file to its violations. Every rule runs over the real
package (which must be clean) and over a planted snippet (which must be caught), so a rule
that silently stopped matching would fail too.
"""

import ast
import textwrap
from collections.abc import Callable

import pytest

from tests.support.source_scan import parents, source_files

type Rule = Callable[[str, ast.Module], list[str]]

# == Rule: reveal() ==
# Who may unwrap a Secret (decided 2026-11-18 for spec #37): Credential Set passwords live
# only in `credentials` and `device_gateway`; the Backup Passphrase lives only in
# `backup_store`. The cli masked reader returns a Secret and never unwraps it.
REVEAL_OWNERS = ("credentials/", "device_gateway/", "backup_store/")


def reveal_outside_owners(relative: str, tree: ast.Module) -> list[str]:
    """Find `.reveal()` calls outside the modules that may hold a secret's value."""
    if relative.startswith(REVEAL_OWNERS):
        return []
    return [
        f"{relative}:{node.lineno} calls .reveal()"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "reveal"
    ]


# == Rule: environment ==
# Secrets never come from the environment (CLAUDE.md). Only `_winsys` reads environment
# variables at all, and only these named, non-secret ones (per-user folder; report and audit
# log, decision #30).
ENV_OWNER = "_winsys/"
ENV_NAMES = frozenset({"LOCALAPPDATA", "USERDOMAIN", "COMPUTERNAME"})
_ENV_MODULES = frozenset({"os", "posix", "nt"})
_ENV_ATTRIBUTES = frozenset({"environ", "environb", "getenv", "getenvb", "putenv", "unsetenv"})


def environment_reads(relative: str, tree: ast.Module) -> list[str]:
    """Find environment access, except `_winsys` reading one of ENV_NAMES by literal name."""
    up = parents(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in _ENV_MODULES:
            found.extend(
                f"{relative}:{node.lineno} imports {node.module}.{alias.name}"
                for alias in node.names
                if alias.name in _ENV_ATTRIBUTES or alias.name == "*"
            )
        elif (
            isinstance(node, ast.Attribute)
            and node.attr in _ENV_ATTRIBUTES
            and isinstance(node.value, ast.Name)
            and node.value.id in _ENV_MODULES
            and not (relative.startswith(ENV_OWNER) and _reads_allowed_name(node, up))
        ):
            found.append(f"{relative}:{node.lineno} uses {node.value.id}.{node.attr}")
    return found


def _reads_allowed_name(node: ast.Attribute, up: dict[ast.AST, ast.AST]) -> bool:
    parent = up.get(node)
    if node.attr == "getenv" and isinstance(parent, ast.Call):
        return _is_allowed_name(parent.args[0] if parent.args else None)
    if node.attr != "environ":
        return False
    if isinstance(parent, ast.Subscript) and isinstance(parent.ctx, ast.Load):
        return _is_allowed_name(parent.slice)
    grandparent = up.get(parent) if parent is not None else None
    if isinstance(parent, ast.Attribute) and parent.attr == "get":
        return isinstance(grandparent, ast.Call) and _is_allowed_name(
            grandparent.args[0] if grandparent.args else None
        )
    return False


def _is_allowed_name(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value in ENV_NAMES


# == Rule: exception text ==
# Exception text can quote device output or a secret (decision #30, section 12), so a caught
# exception is mapped to a fixed message, never shown or stored. Inside `except ... as e:`,
# `e` may only be re-raised, chained, type-checked, passed to one of these functions, or have
# one of these numeric attributes read.
EXCEPTION_SAFE_CALLS = frozenset({"type", "isinstance", "describe_internal_error", "fixed_message"})
EXCEPTION_SAFE_ATTRIBUTES = frozenset({"code", "errno", "winerror"})


def exception_text_used(relative: str, tree: ast.Module) -> list[str]:
    """Find uses of a caught exception that could show or keep its text."""
    up = parents(tree)
    handlers = [
        (handler.name, node)
        for handler in ast.walk(tree)
        if isinstance(handler, ast.ExceptHandler) and handler.name is not None
        for statement in handler.body
        for node in ast.walk(statement)
    ]
    return [
        f"{relative}:{node.lineno} uses the text of `{name}`"
        for name, node in handlers
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Load)
        and not _safe_exception_use(node, up)
    ]


def _safe_exception_use(node: ast.Name, up: dict[ast.AST, ast.AST]) -> bool:
    parent = up.get(node)
    if isinstance(parent, ast.Raise):
        return True
    if isinstance(parent, ast.Attribute):
        return parent.attr in EXCEPTION_SAFE_ATTRIBUTES
    if isinstance(parent, ast.Call) and node in parent.args:
        func = parent.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
        return name in EXCEPTION_SAFE_CALLS
    return False


# == Rule: file writes ==
# Files are written only by the writer helpers, which scan for secrets and write temp-then-
# rename (decision #30; CLAUDE.md: no plaintext config on disk). A ticket that adds a writer
# adds its file here, and says why in the commit.
WRITE_OWNERS: frozenset[str] = frozenset(
    {
        # #42: opens the single-instance lock file; never writes into it.
        "_winsys/lock.py",
        # #42: the "can a Run folder be written here" probe file, written before any prompt,
        # so it holds only a fixed word, never a secret.
        "run_output/folder.py",
        # #42: the Run register, paths only, temp-then-rename. #48's secret scan is not
        # built yet; the register holds no typed secret (labels pass the allow-list).
        "backup_store/register.py",
    }
)
_WRITE_CALLS = frozenset({"write_text", "write_bytes", "symlink_to", "hardlink_to", "touch"})
_WRITE_FUNCTIONS = {
    "os": frozenset({"open", "replace", "rename", "renames", "link", "symlink", "makedirs"}),
    "shutil": frozenset({"copy", "copy2", "copyfile", "copytree", "move"}),
    "tempfile": frozenset({"mkstemp", "mkdtemp", "TemporaryFile", "NamedTemporaryFile"}),
}


def file_writes(relative: str, tree: ast.Module) -> list[str]:
    """Find calls that write, create or move files outside the writer helpers."""
    if relative in WRITE_OWNERS:
        return []
    return [
        f"{relative}:{node.lineno} writes a file"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _writes(node)
    ]


def _writes(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name) and func.id == "open":
        return _write_mode(call, position=1)
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr == "open" and not (isinstance(func.value, ast.Name) and func.value.id == "os"):
        return _write_mode(call, position=0)  # Path.open(mode)
    if func.attr in _WRITE_CALLS:
        return True
    module = func.value.id if isinstance(func.value, ast.Name) else None
    return module is not None and func.attr in _WRITE_FUNCTIONS.get(module, frozenset())


def _write_mode(call: ast.Call, position: int) -> bool:
    mode: ast.expr | None = call.args[position] if len(call.args) > position else None
    mode = next((k.value for k in call.keywords if k.arg == "mode"), mode)
    if mode is None:
        return False  # the default mode reads
    if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)):
        return True  # a computed mode might write
    return any(flag in mode.value for flag in "wax+")


# == The tests ==
RULES: dict[str, Rule] = {
    "reveal": reveal_outside_owners,
    "environment": environment_reads,
    "exception text": exception_text_used,
    "file writes": file_writes,
}


@pytest.mark.parametrize("rule", RULES.values(), ids=RULES.keys())
def test_the_package_keeps_the_rule(rule: Rule) -> None:
    broken = [v for source in source_files() for v in rule(source.relative, source.tree)]

    assert broken == []


def _scan(rule: Rule, relative: str, code: str) -> list[str]:
    found = rule(relative, ast.parse(textwrap.dedent(code)))
    return sorted(found, key=lambda v: int(v.split(":")[1].split()[0]))


def test_reveal_is_caught_outside_its_owners_and_allowed_inside() -> None:
    code = "def login(s):\n    return s.reveal()\n"

    assert _scan(reveal_outside_owners, "cli/prompts.py", code) == [
        "cli/prompts.py:2 calls .reveal()"
    ]
    assert _scan(reveal_outside_owners, "device_gateway/ssh.py", code) == []
    assert _scan(reveal_outside_owners, "backup_store/lock.py", code) == []


def test_environment_reads_are_caught_except_named_ones_in_winsys() -> None:
    code = """
        import os
        from os import environ
        a = os.environ["LOCALAPPDATA"]
        b = os.environ.get("COMPUTERNAME")
        c = os.getenv("USERDOMAIN")
        d = os.environ.get("NA_PASSWORD")
        e = os.environ
        f = dict(os.environ)
    """

    assert _scan(environment_reads, "credentials/sets.py", code) == [
        "credentials/sets.py:3 imports os.environ",
        "credentials/sets.py:4 uses os.environ",
        "credentials/sets.py:5 uses os.environ",
        "credentials/sets.py:6 uses os.getenv",
        "credentials/sets.py:7 uses os.environ",
        "credentials/sets.py:8 uses os.environ",
        "credentials/sets.py:9 uses os.environ",
    ]
    assert _scan(environment_reads, "_winsys/paths.py", code) == [
        "_winsys/paths.py:3 imports os.environ",
        "_winsys/paths.py:7 uses os.environ",
        "_winsys/paths.py:8 uses os.environ",
        "_winsys/paths.py:9 uses os.environ",
    ]


def test_using_the_text_of_a_caught_exception_is_caught() -> None:
    code = """
        try:
            pass
        except OSError as e:
            print(e)
            msg = f"failed: {e}"
            detail = e.args
            raise RuntimeError(str(e)) from e
        except ValueError as e:
            if isinstance(e, KeyError) or type(e) is ValueError:
                raise
            code = e.errno
            describe_internal_error(e)
            raise FixedError(fixed_message(e)) from e
    """

    assert _scan(exception_text_used, "device_gateway/ssh.py", code) == [
        "device_gateway/ssh.py:5 uses the text of `e`",
        "device_gateway/ssh.py:6 uses the text of `e`",
        "device_gateway/ssh.py:7 uses the text of `e`",
        "device_gateway/ssh.py:8 uses the text of `e`",
    ]


def test_file_writes_are_caught_outside_the_writer_helpers() -> None:
    code = """
        import os, shutil, tempfile
        from pathlib import Path
        open("a.txt")
        open("a.txt", "rb")
        open("a.txt", "w")
        open("a.txt", mode="ab")
        Path("a").open("x")
        Path("a").write_text("config")
        os.replace("a", "b")
        shutil.copy("a", "b")
        tempfile.mkstemp()
        open("a.txt", flags)
    """

    assert _scan(file_writes, "topology/save.py", code) == [
        "topology/save.py:6 writes a file",
        "topology/save.py:7 writes a file",
        "topology/save.py:8 writes a file",
        "topology/save.py:9 writes a file",
        "topology/save.py:10 writes a file",
        "topology/save.py:11 writes a file",
        "topology/save.py:12 writes a file",
        "topology/save.py:13 writes a file",
    ]
