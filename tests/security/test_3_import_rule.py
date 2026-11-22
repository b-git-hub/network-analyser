"""Security test 3, the import rule (spec #37, Testing Decisions; ADR 0003).

A static scan shows that only `device_gateway` imports Netmiko or Paramiko, so no other
module can open a session to a device around the gatekeeper. The same scan holds the online
fence: only `advisories/transport.py` imports an HTTP client, TLS or the Windows certificate
store, and `socket` is imported only by the two gateway files that need it and that one
transport (#132, #149).
"""

from pathlib import Path

import pytest

from tests.support.source_scan import SourceFile, imported_names, source_files

SSH_LIBRARIES = frozenset({"netmiko", "paramiko"})
GATEKEEPER = "device_gateway"
FENCE_FILE = "advisories/transport.py"
"""The one module that may open the outbound HTTPS connection (CODING_STANDARDS.md)."""
ONLINE_LIBRARIES = frozenset({"http", "ssl", "truststore"})
SOCKET_OWNERS = frozenset(
    {"device_gateway/ssh.py", "device_gateway/probe.py", "advisories/transport.py"}
)

pytestmark = pytest.mark.security


def ssh_library_imports_outside_the_gatekeeper(files: list[SourceFile]) -> list[str]:
    """Return 'module:line imports name' for every SSH-library import outside the gatekeeper.

    A dynamic import with a computed name counts too: the scan cannot prove what it loads.
    """
    found: list[tuple[str, int, str]] = []
    for source in files:
        if source.module == GATEKEEPER:
            continue
        for name, line in imported_names(source):
            if name.split(".")[0] in SSH_LIBRARIES or name.startswith("<dynamic"):
                found.append((source.dotted, line, name))
    return [f"{dotted}:{line} imports {name}" for dotted, line, name in sorted(found)]


def test_only_device_gateway_imports_netmiko_or_paramiko() -> None:
    files = source_files()

    assert len(files) >= 11, "the scan found too few files to be looking in the right place"
    assert ssh_library_imports_outside_the_gatekeeper(files) == []


def test_the_scan_catches_every_way_of_importing_them(tmp_path: Path) -> None:
    package = tmp_path / "network_analyser"
    (package / "topology").mkdir(parents=True)
    (package / "device_gateway").mkdir()
    (package / "topology" / "__init__.py").write_text(
        "import paramiko\n"
        "import netmiko.cisco as nc\n"
        "from netmiko import ConnectHandler\n"
        "import importlib\n"
        "importlib.import_module('paramiko.client')\n"
        "__import__('netmiko')\n"
        "name = 'para' + 'miko'\n"
        "importlib.import_module(name)\n",
        encoding="utf-8",
    )
    (package / "device_gateway" / "__init__.py").write_text(
        "import netmiko\nimport paramiko\n", encoding="utf-8"
    )

    found = ssh_library_imports_outside_the_gatekeeper(source_files(package))

    assert found == [
        "network_analyser.topology:1 imports paramiko",
        "network_analyser.topology:2 imports netmiko.cisco",
        "network_analyser.topology:3 imports netmiko",
        "network_analyser.topology:3 imports netmiko.ConnectHandler",
        "network_analyser.topology:5 imports paramiko.client",
        "network_analyser.topology:6 imports netmiko",
        "network_analyser.topology:8 imports <dynamic import with a computed name>",
    ]


def imports_outside_the_online_fence(files: list[SourceFile]) -> list[str]:
    """Return 'module:line imports name' for every online or socket import outside its owner."""
    found: list[str] = []
    for source in files:
        for name, line in imported_names(source):
            top = name.split(".")[0]
            online = top in ONLINE_LIBRARIES and source.relative != FENCE_FILE
            socketed = top == "socket" and source.relative not in SOCKET_OWNERS
            if online or socketed:
                found.append(f"{source.relative}:{line} imports {name}")
    return found


def test_only_the_fenced_transport_imports_an_http_client_tls_or_the_certificate_store() -> None:
    files = source_files()

    assert len(files) >= 11, "the scan found too few files to be looking in the right place"
    assert imports_outside_the_online_fence(files) == []


def test_the_scan_catches_an_online_import_anywhere_else(tmp_path: Path) -> None:
    package = tmp_path / "network_analyser"
    (package / "topology").mkdir(parents=True)
    (package / "advisories").mkdir()
    (package / "topology" / "__init__.py").write_text(
        "import http.client\nimport ssl\nimport truststore\nimport socket\n",
        encoding="utf-8",
    )
    (package / "advisories" / "transport.py").write_text(
        "import http.client\nimport ssl\nimport truststore\nimport socket\n",
        encoding="utf-8",
    )
    (package / "advisories" / "__init__.py").write_text("import ssl\n", encoding="utf-8")

    assert imports_outside_the_online_fence(source_files(package)) == [
        "advisories/__init__.py:1 imports ssl",
        "topology/__init__.py:1 imports http.client",
        "topology/__init__.py:2 imports ssl",
        "topology/__init__.py:3 imports truststore",
        "topology/__init__.py:4 imports socket",
    ]
