"""Calls between modules go one way, and each third-party library has one owner (ADR 0003).

Changing ALLOWED or OWNERS is a design decision: say why in the commit, and keep
CODING_STANDARDS.md ("Layout") in step.
"""

import graphlib

from tests.support.source_scan import (
    LEAF_MODULES,
    MODULES,
    PACKAGE_ROOT,
    imported_names,
    internal_module,
    source_files,
)

# Which package modules each module may import (spec #37 "Modules and their interfaces";
# decisions #9 and #30). `cli` is the composition root. Anything not listed is forbidden.
ALLOWED: dict[str, frozenset[str]] = {
    "records": frozenset(),
    "_winsys": frozenset(),
    "scope": frozenset({"records"}),
    "credentials": frozenset({"records"}),
    "trust_store": frozenset({"records"}),
    "platforms": frozenset({"records"}),
    "topology": frozenset({"records"}),
    "diagram": frozenset({"records"}),  # reads only the Topology file
    "backup_store": frozenset({"records", "credentials"}),
    "run_output": frozenset({"records", "credentials", "_winsys"}),
    "device_gateway": frozenset({"records", "scope", "trust_store", "credentials", "platforms"}),
    "discovery": frozenset(
        {
            "records",
            "scope",
            "credentials",
            "device_gateway",
            "platforms",
            "backup_store",
            "topology",
        }
    ),
    "cli": (MODULES | LEAF_MODULES) - {"cli"},
}

# Third-party and risky stdlib imports, and the only places that may make them. An owner
# ending in "/" is a whole module; otherwise it is one file below the package folder.
OWNERS: dict[str, frozenset[str]] = {
    "netmiko": frozenset({"device_gateway/ssh.py"}),
    "paramiko": frozenset({"device_gateway/ssh.py"}),
    "socket": frozenset({"device_gateway/ssh.py"}),
    "pyrage": frozenset({"backup_store/"}),
    "textfsm": frozenset({"platforms/"}),
    "ntc_templates": frozenset({"platforms/"}),
    "ctypes": frozenset({"_winsys/"}),
    "msvcrt": frozenset({"_winsys/"}),
    "winreg": frozenset({"_winsys/"}),
    "tomllib": frozenset({"cli/"}),
    "logging": frozenset({"cli/library_loggers.py"}),
    "faulthandler": frozenset({"cli/app.py"}),  # only to switch it off
    "getpass": frozenset(),
    "http": frozenset(),
    "urllib": frozenset(),
    "requests": frozenset(),
    "ftplib": frozenset(),
    "telnetlib": frozenset(),
    "pickle": frozenset(),
    "shelve": frozenset(),
    "marshal": frozenset(),
    "subprocess": frozenset(),
}

# Files directly in the package folder, and the package modules they may import.
ROOT_FILES: dict[str, frozenset[str]] = {
    "__init__.py": frozenset(),
    "__main__.py": frozenset({"cli"}),
    "_version.py": frozenset(),
}


def test_the_package_holds_exactly_the_planned_modules() -> None:
    folders = {p.name for p in PACKAGE_ROOT.iterdir() if p.is_dir() and p.name != "__pycache__"}
    files = {p.name for p in PACKAGE_ROOT.glob("*.py")}

    assert folders == MODULES | LEAF_MODULES
    assert files == set(ROOT_FILES)
    assert (PACKAGE_ROOT / "platforms" / "ios_xe" / "__init__.py").is_file()
    assert (PACKAGE_ROOT / "platforms" / "nxos" / "__init__.py").is_file()


def test_the_allowed_imports_form_a_one_way_graph() -> None:
    graphlib.TopologicalSorter(ALLOWED).prepare()  # raises CycleError on a cycle


def test_every_module_imports_only_the_modules_it_may() -> None:
    broken: list[str] = []
    for source in source_files():
        allowed = ROOT_FILES[source.relative] if source.module is None else ALLOWED[source.module]
        for name, line in imported_names(source):
            target = internal_module(name)
            if target is not None and target != source.module and target not in allowed:
                broken.append(f"{source.relative}:{line} imports {name}")

    assert broken == []


def test_each_library_is_imported_only_by_its_owner() -> None:
    broken: list[str] = []
    for source in source_files():
        for name, line in imported_names(source):
            owners = OWNERS.get(name.split(".")[0])
            if owners is not None and not any(_owns(o, source.relative) for o in owners):
                broken.append(f"{source.relative}:{line} imports {name}")

    assert broken == []


def _owns(owner: str, relative: str) -> bool:
    return relative.startswith(owner) if owner.endswith("/") else relative == owner
