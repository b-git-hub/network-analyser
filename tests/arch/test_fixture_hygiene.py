"""Real device data never goes into the repo (CLAUDE.md; spec #37, #28).

Tests, the package and the CML lab file may hold only documentation addresses (RFC 5737)
and a few fixed special addresses, and every secret in the lab file is `CHANGE_ME`.
"""

import ipaddress
import re
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from tests.support.source_scan import PACKAGE_ROOT, REPO_ROOT

DOCUMENTATION = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
# Addresses tests need to prove a refusal (spec #37, story 41): 0.0.0.0, loopback,
# multicast and broadcast.
REFUSAL_TARGETS = tuple(
    ipaddress.ip_network(n)
    for n in ("0.0.0.0/32", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32")
)
LAB_FOLDER = REPO_ROOT / "lab"
PLACEHOLDER = "CHANGE_ME"
_TEXT_SUFFIXES = frozenset({".py", ".json", ".txt", ".toml", ".yaml", ".yml", ".html", ".md"})
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _is_mask(address: ipaddress.IPv4Address) -> bool:
    """Say whether a dotted quad is a netmask (255.255.255.0) or wildcard mask (0.0.0.255)."""
    bits = f"{int(address):032b}"
    return "01" not in bits or "10" not in bits


def ipv4_literals(text: str) -> Iterator[tuple[int, ipaddress.IPv4Address]]:
    """Yield (line, address) for every dotted-quad IPv4 literal in `text`."""
    for number, line in enumerate(text.splitlines(), start=1):
        for match in _IPV4.finditer(line):
            try:
                yield number, ipaddress.IPv4Address(match.group())
            except ipaddress.AddressValueError:
                continue  # not an address, e.g. a version number like 300.1.2.3


def forbidden_addresses(text: str, *, allow_refusal_targets: bool) -> list[str]:
    """Return 'line: address' for every IPv4 literal outside the allowed ranges."""
    allowed = DOCUMENTATION + (REFUSAL_TARGETS if allow_refusal_targets else ())
    return [
        f"{line}: {address}"
        for line, address in ipv4_literals(text)
        if not (_is_mask(address) or any(address in network for network in allowed))
    ]


def _text_files(folder: Path) -> Iterator[Path]:
    if folder.is_dir():
        yield from (
            p
            for p in sorted(folder.rglob("*"))
            if p.is_file() and p.suffix in _TEXT_SUFFIXES and "__pycache__" not in p.parts
        )


def _files(*folders: Path) -> list[Path]:
    return [p for folder in folders for p in _text_files(folder)]


@pytest.mark.parametrize(
    "path",
    _files(REPO_ROOT / "tests", PACKAGE_ROOT),
    ids=lambda p: p.relative_to(REPO_ROOT).as_posix(),
)
def test_code_and_fixtures_hold_only_documentation_addresses(path: Path) -> None:
    text = path.read_text(encoding="utf-8")

    assert forbidden_addresses(text, allow_refusal_targets=True) == []


def test_the_lab_holds_only_documentation_addresses() -> None:
    broken = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{found}"
        for path in _files(LAB_FOLDER)
        for found in forbidden_addresses(
            path.read_text(encoding="utf-8"), allow_refusal_targets=False
        )
        if not found.endswith(": 0.0.0.0")
    ]

    assert broken == []


def test_the_address_scan_catches_real_looking_addresses() -> None:
    real_looking = ".".join(["10", "20", "30", "40"])  # noqa: FLY002 (built, so this file passes)
    text = f"seed 192.0.2.10\nmask 255.255.255.0 wildcard 0.0.0.255\nreal {real_looking}\n"

    assert forbidden_addresses(text, allow_refusal_targets=True) == [f"3: {real_looking}"]
    assert forbidden_addresses("loop 127.0.0.1\n", allow_refusal_targets=False) == ["1: 127.0.0.1"]


# Secret-bearing Cisco config lines (decision #5's list), each capturing the secret value.
_SECRET_VALUES = (
    re.compile(r"(?:^|\s)(?:secret|password)\s+(?:\d+\s+)?(?!strength-check\b)(\S+)"),
    re.compile(r"(?:^|\s)key-string\s+(?:\d+\s+)?(\S+)"),
    re.compile(r"(?:^|\s)(?:community|pre-shared-key|localizedkey|auth-key)\s+(?:\d+\s+)?(\S+)"),
    re.compile(r"(?:tacacs-server|radius-server|server-private|host)\b.*\skey\s+(?:\d+\s+)?(\S+)"),
    # A bare `key` line (under `tacacs server`), but not a key chain's `key 1`.
    re.compile(r"^key\s+(?:[067]\s+)?(?!\d+$|chain\b)(\S+)"),
)


def secrets_not_placeholder(config: str) -> list[str]:
    """Return 'line: value' for every secret value in a device config that is not CHANGE_ME."""
    found: list[str] = []
    for number, raw in enumerate(config.splitlines(), start=1):
        line = raw.strip()
        if not line or line[0] in "!#" or line.startswith("no "):
            continue
        found.extend(
            f"{number}: {match.group(1)}"
            for pattern in _SECRET_VALUES
            for match in pattern.finditer(line)
            if match.group(1) != PLACEHOLDER
        )
    return found


def _lab_configs(lab: object) -> Iterator[tuple[str, str]]:
    """Yield (node label, config text) from a CML lab file's nodes."""
    nodes = lab.get("nodes", []) if isinstance(lab, dict) else []
    for node in nodes:
        label = str(node.get("label", "?"))
        configuration = node.get("configuration")
        if isinstance(configuration, str):
            yield label, configuration
        elif isinstance(configuration, list):
            for part in configuration:
                yield f"{label}/{part.get('name', '?')}", str(part.get("content", ""))


def test_every_secret_in_the_lab_is_a_placeholder() -> None:
    broken: list[str] = []
    for path in sorted([*LAB_FOLDER.glob("*.yaml"), *LAB_FOLDER.glob("*.yml")]):
        lab = yaml.safe_load(path.read_text(encoding="utf-8"))
        broken.extend(
            f"{path.name} {label} line {found}"
            for label, config in _lab_configs(lab)
            for found in secrets_not_placeholder(config)
        )

    assert broken == []


def test_the_secret_scan_catches_a_real_looking_secret() -> None:
    config = (
        "enable algorithm-type scrypt secret CHANGE_ME\n"
        "username admin password 0 Hunter2-real\n"
        "! a comment: every password, secret and key is CHANGE_ME\n"
        "password strength-check\n"
        " key-string 7 0822455D0A16\n"
        "snmp-server community not-public RO\n"
        "tacacs server ISE\n"
        " key CHANGE_ME\n"
        "tacacs-server host 192.0.2.5 key s3cret\n"
        "key chain OSPF-KEYS\n"
        " key 1\n"
        "radius server NPS\n"
        " key 7 104D000A0618\n"
    )

    assert secrets_not_placeholder(config) == [
        "2: Hunter2-real",
        "5: 0822455D0A16",
        "6: not-public",
        "9: s3cret",
        "13: 104D000A0618",
    ]
