"""Calls between modules go one way, and each third-party library has one owner (ADR 0003).

Changing ALLOWED or OWNERS is a design decision: say why in the commit, and keep
CODING_STANDARDS.md ("Layout") in step.
"""

import graphlib
from pathlib import Path

from tests.support.source_scan import (
    LEAF_MODULES,
    MODULES,
    PACKAGE_ROOT,
    SourceFile,
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
    "analysis": frozenset({"records"}),  # pure: no HTTP client, SSH library or device code
    "diagram": frozenset({"records"}),  # reads only the Topology file
    "backup_store": frozenset({"records", "credentials"}),
    "run_output": frozenset({"records", "credentials", "_winsys"}),
    # #95: the one egress module. `credentials` is for `Secret` only (the Cisco API Key),
    # never a password path; `_winsys` reads Windows' proxy setting (story 17).
    "advisories": frozenset({"records", "credentials", "_winsys"}),
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
    # #55: the Sweep opens its own TCP socket and closes it before key exchange, so the
    # probe cannot go through Paramiko (that handshake is the key exchange).
    # #95: the fenced transport is the only other socket, and the only TLS.
    "socket": frozenset(
        {"device_gateway/ssh.py", "device_gateway/probe.py", "advisories/transport.py"}
    ),
    # #95: the one HTTP client, and the Windows certificate store (ADR 0009).
    "http": frozenset({"advisories/transport.py"}),
    "truststore": frozenset({"advisories/"}),
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


# #95: `advisories` takes the lookup questions, never a device record (stories 12-14).
DEVICE_RECORDS = frozenset(
    {
        "network_analyser.records.device",
        "network_analyser.records.collected",
        "network_analyser.records.topology",
        "network_analyser.records.run_request",
    }
)
EGRESS_MODULE = "advisories"


def device_record_imports(files: list[SourceFile]) -> list[str]:
    """Find an import of a device record in the module that goes online."""
    return [
        f"{source.relative}:{line} imports {name}"
        for source in files
        if source.module == EGRESS_MODULE
        for name, line in imported_names(source)
        if any(name.startswith(prefix) for prefix in DEVICE_RECORDS)
    ]


def test_advisories_sees_no_device_record() -> None:
    assert device_record_imports(source_files()) == []


def test_the_scan_catches_a_device_record_in_advisories(tmp_path: Path) -> None:
    package = tmp_path / "network_analyser"
    (package / "advisories").mkdir(parents=True)
    (package / "advisories" / "__init__.py").write_text(
        "from network_analyser.records.device import DeviceRecord\n", encoding="utf-8"
    )

    assert device_record_imports(source_files(package)) == [
        "advisories/__init__.py:1 imports network_analyser.records.device",
        "advisories/__init__.py:1 imports network_analyser.records.device.DeviceRecord",
    ]


# #95: the egress module holds the Cisco API Key's Secret, never a Credential Set password or
# a device session (story 41; ADR 0008).
PASSWORD_OR_DEVICE = (
    "network_analyser.credentials.sets",
    "network_analyser.credentials.CredentialSet",
    "network_analyser.credentials.LoginLease",
    "network_analyser.device_gateway",
)


def password_or_device_imports(files: list[SourceFile]) -> list[str]:
    """Find a Credential Set password path or a device import in `advisories`."""
    return [
        f"{source.relative}:{line} imports {name}"
        for source in files
        if source.module == EGRESS_MODULE
        for name, line in imported_names(source)
        if any(name.startswith(prefix) for prefix in PASSWORD_OR_DEVICE)
    ]


def test_advisories_imports_no_password_path_and_no_device_gateway() -> None:
    assert password_or_device_imports(source_files()) == []


def test_the_scan_catches_a_password_path_in_advisories(tmp_path: Path) -> None:
    package = tmp_path / "network_analyser"
    (package / "advisories").mkdir(parents=True)
    (package / "advisories" / "__init__.py").write_text(
        "from network_analyser.credentials.sets import CredentialSets\n"
        "from network_analyser.device_gateway import visit\n",
        encoding="utf-8",
    )

    assert password_or_device_imports(source_files(package)) == [
        "advisories/__init__.py:1 imports network_analyser.credentials.sets",
        "advisories/__init__.py:1 imports network_analyser.credentials.sets.CredentialSets",
        "advisories/__init__.py:2 imports network_analyser.device_gateway",
        "advisories/__init__.py:2 imports network_analyser.device_gateway.visit",
    ]
