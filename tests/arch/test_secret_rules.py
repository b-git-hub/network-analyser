"""Static rules that keep secrets and exception text in memory (CLAUDE.md, spec #37).

Each rule is a function from one parsed file to its violations. Every rule runs over the real
package (which must be clean) and over a planted snippet (which must be caught), so a rule
that silently stopped matching would fail too.
"""

import ast
import builtins
import textwrap
from collections.abc import Callable

import pytest

from tests.support.source_scan import PACKAGE, parents, source_files

type Rule = Callable[[str, ast.Module], list[str]]

# == Rule: reveal() ==
# Who may unwrap a Secret (decided 2026-11-18 for spec #37): Credential Set passwords live
# only in `credentials` and `device_gateway`; the Backup Passphrase lives only in
# `backup_store`. #95 adds the Cisco API Key's owners (ADR 0008): `advisories` reveals the
# client ID, secret and token to make one request, and `backup_store` unlocks the key file.
# The cli masked reader returns a Secret and never unwraps it.
REVEAL_OWNERS = ("credentials/", "device_gateway/", "backup_store/", "advisories/")


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
# one of these numeric attributes read. Functions are named in full (module path and name),
# so a function elsewhere that merely shares a name is not trusted (#38 retro).
EXCEPTION_SAFE_CALLS = frozenset(
    {
        "builtins.type",
        "builtins.isinstance",
        # The top-level handler: the type and a file:line stack only (story 91).
        "network_analyser.cli.crash.describe_internal_error",
        # The tool's own errors, raised with fixed text.
        "network_analyser.cli.run_folder.fixed_message",
        # A caught exception's type and the fixed message for it (story 166, #48).
        "network_analyser.records.events.error_event",
        # #49: the fixed message per Netmiko and Paramiko exception type, via error_event.
        "network_analyser.device_gateway.ssh.library_error",
        # #95: the connection failure's fixed reason, never the exception's text.
        "network_analyser.advisories.transport._failure",
    }
)
# `lineno` and `colno` are where a TOML run file failed to parse (#41): numbers only.
EXCEPTION_SAFE_ATTRIBUTES = frozenset({"code", "errno", "winerror", "lineno", "colno"})


def exception_text_used(relative: str, tree: ast.Module) -> list[str]:
    """Find uses of a caught exception that could show or keep its text."""
    up = parents(tree)
    names = _qualified_names(relative, tree)
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
        and not _safe_exception_use(node, up, names)
    ]


def _safe_exception_use(node: ast.Name, up: dict[ast.AST, ast.AST], names: dict[str, str]) -> bool:
    parent = up.get(node)
    if isinstance(parent, ast.Raise):
        return True
    if isinstance(parent, ast.Attribute):
        return parent.attr in EXCEPTION_SAFE_ATTRIBUTES
    if isinstance(parent, ast.Call) and node in parent.args:
        return _called(parent.func, names) in EXCEPTION_SAFE_CALLS
    return False


def _qualified_names(relative: str, tree: ast.Module) -> dict[str, str]:
    """Map each name bound at the top of a file to the full name of what it stands for."""
    parts = [PACKAGE, *relative.removesuffix(".py").split("/")]
    is_package = parts[-1] == "__init__"
    if is_package:
        parts.pop()
    names = {n: f"builtins.{n}" for n in dir(builtins)}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                names[bound] = alias.name if alias.asname else bound
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                anchor = parts if is_package else parts[:-1]
                anchor = anchor[: len(anchor) - (node.level - 1)]
                base = ".".join([*anchor, node.module] if node.module else anchor)
            for alias in node.names:
                names[alias.asname or alias.name] = f"{base}.{alias.name}"
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names[node.name] = f"{'.'.join(parts)}.{node.name}"
    return names


def _called(func: ast.expr, names: dict[str, str]) -> str | None:
    """Return the full name of a called function, or None when it cannot be told."""
    if isinstance(func, ast.Name):
        return names.get(func.id)
    if isinstance(func, ast.Attribute):
        base = _called(func.value, names)
        return None if base is None else f"{base}.{func.attr}"
    return None


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
        # #42: the Run register, paths only, temp-then-rename. #48: a new entry holding a
        # typed secret is refused, never written.
        "backup_store/register.py",
        # #45: the Backup check file, temp-then-rename. It holds only age ciphertext of a
        # fixed, known phrase; the passphrase itself never reaches the file.
        "backup_store/check_file.py",
        # #46: the Trust Store, OpenSSH known_hosts lines of public host keys only,
        # temp-then-rename. It never holds a secret, so #48's scan has nothing to find.
        "trust_store/store.py",
        # #48: audit.log, created exclusively and appended to one line at a time. Every
        # value and every line passes through the secret scan; only schema fields of plain
        # data are written, never device output.
        "run_output/audit.py",
        # #52: the one scanned writer for the Run folder's plaintext files (topology.json,
        # the diagrams, and the Run report). Every string passes through the secret scan
        # before any escaping, then the whole text again; temp-then-rename.
        "run_output/scanned_file.py",
        # #51: Backups and manifest.age, temp-then-rename, never replacing a file. Only age
        # ciphertext is written: each config is locked in memory first, so no plaintext
        # config ever reaches the disk. Ciphertext cannot hold a typed secret to scan for,
        # and a file name that holds one is never used.
        "backup_store/locker.py",
        # #58: the change-pending marker (start time, paths and SHA-256 fingerprints of
        # locked files; a path holding a typed secret is left out) and the copy of the check
        # file (age ciphertext of a fixed phrase), temp-then-rename.
        "backup_store/change_pending.py",
        # #58: re-locked Backups and manifests, temp-then-rename over the original. Each is
        # unlocked, re-locked and checked in memory first, so only age ciphertext is written.
        # Also each Run folder's re-lock record: paths and fingerprints, through the scan.
        "backup_store/relock.py",
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
    assert _scan(reveal_outside_owners, "advisories/session.py", code) == []


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
        from network_analyser.cli.crash import describe_internal_error
        from network_analyser.cli.run_folder import fixed_message
        from network_analyser.records import events
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
            events.error_event(e, step="x", ip=None, messages={})
            raise FixedError(fixed_message(e)) from e
    """

    assert _scan(exception_text_used, "device_gateway/ssh.py", code) == [
        "device_gateway/ssh.py:8 uses the text of `e`",
        "device_gateway/ssh.py:9 uses the text of `e`",
        "device_gateway/ssh.py:10 uses the text of `e`",
        "device_gateway/ssh.py:11 uses the text of `e`",
    ]


def test_a_mapper_is_trusted_by_its_full_name_not_by_its_name_alone() -> None:
    code = """
        from network_analyser.topology.helpers import fixed_message
        def describe_internal_error(error):
            return str(error)
        try:
            pass
        except OSError as e:
            fixed_message(e)
            describe_internal_error(e)
            library_error(e)
    """

    assert _scan(exception_text_used, "topology/build.py", code) == [
        "topology/build.py:8 uses the text of `e`",
        "topology/build.py:9 uses the text of `e`",
        "topology/build.py:10 uses the text of `e`",
    ]


def test_the_gateways_own_mapper_is_trusted_where_it_is_defined() -> None:
    code = """
        def library_error(error):
            return error_event(error)
        try:
            pass
        except OSError as e:
            library_error(e)
    """

    assert _scan(exception_text_used, "device_gateway/ssh.py", code) == []


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
