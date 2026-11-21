"""A static scan of the package's own source, for the architecture and security tests.

The scan reads files with `ast`; it never imports them, so a module that would misbehave on
import cannot hide from it.
"""

import ast
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "network_analyser"
PACKAGE_ROOT = REPO_ROOT / PACKAGE

# The eleven modules of spec #37 ("Modules and their interfaces"), ADR 0003, plus the 0.2.0
# `advisories` (#95) and `analysis` (#94) modules of spec #92.
MODULES = frozenset(
    {
        "cli",
        "scope",
        "credentials",
        "trust_store",
        "device_gateway",
        "platforms",
        "discovery",
        "backup_store",
        "topology",
        "diagram",
        "run_output",
        "advisories",
        "analysis",
    }
)
# Leaf modules that import nothing from the package (CODING_STANDARDS.md, "Layout").
LEAF_MODULES = frozenset({"records", "_winsys"})


@dataclass(frozen=True)
class SourceFile:
    """One .py file of the package, parsed."""

    path: Path
    relative: str
    """Its path below the package folder, with forward slashes, e.g. `cli/app.py`."""
    dotted: str
    """Its dotted module name, e.g. `network_analyser.cli.app`."""
    module: str | None
    """The top-level module it belongs to, or None for files in the package folder itself."""
    tree: ast.Module


def source_files(root: Path = PACKAGE_ROOT) -> list[SourceFile]:
    """Parse every .py file under `root`, a folder laid out like the package."""
    files: list[SourceFile] = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        parts = [root.name, *relative.with_suffix("").parts]
        if parts[-1] == "__init__":
            parts.pop()
        module = relative.parts[0] if len(relative.parts) > 1 else None
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        files.append(SourceFile(path, relative.as_posix(), ".".join(parts), module, tree))
    return files


def imported_names(source: SourceFile) -> Iterator[tuple[str, int]]:
    """Yield (absolute dotted name, line) for every import, including dynamic ones.

    `importlib.import_module("x")` and `__import__("x")` with a literal name count too; one
    with a computed name is yielded as `<dynamic import with a computed name>`.
    """
    is_package = source.path.name == "__init__.py"
    for node in ast.walk(source.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_from(source.dotted, is_package=is_package, node=node)
            yield base, node.lineno
            for alias in node.names:
                yield f"{base}.{alias.name}", node.lineno
        elif isinstance(node, ast.Call) and _is_dynamic_import(node.func):
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                yield first.value, node.lineno
            else:
                yield "<dynamic import with a computed name>", node.lineno


def _resolve_from(dotted: str, *, is_package: bool, node: ast.ImportFrom) -> str:
    if node.level == 0:
        return node.module or ""
    anchor = dotted.split(".")
    if not is_package:
        anchor.pop()
    for _ in range(node.level - 1):
        anchor.pop()
    return ".".join([*anchor, node.module] if node.module else anchor)


def _is_dynamic_import(func: ast.expr) -> bool:
    if isinstance(func, ast.Name):
        return func.id in {"__import__", "import_module"}
    if isinstance(func, ast.Attribute):
        return func.attr in {"import_module", "__import__"}
    return False


def internal_module(name: str) -> str | None:
    """Return the package module a dotted import name points into, if it points into one."""
    parts = name.split(".")
    if parts[0] == PACKAGE and len(parts) > 1 and parts[1] in MODULES | LEAF_MODULES:
        return parts[1]
    return None


def parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Map every node of `tree` to the node that contains it."""
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
