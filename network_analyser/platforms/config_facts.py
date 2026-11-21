"""Secret-free config facts, read from a running config at capture time (#96).

`read_config_facts(platform, text)` turns the raw running config into plain `ConfigFact`s:
counts, booleans and fixed keywords only. A config line, secret, hash, key or community string
is never kept. It is called inside the visit, after the Backup has been accepted, and the raw
config still goes only to the Backup sink (CODING_STANDARDS §3).

The fact names are the published vocabulary in docs/config-facts.md; later hardening Checks
read exactly these.
"""

import re
from typing import Final

from network_analyser.records import Platform
from network_analyser.records.config_facts import (
    ENABLE_PASSWORD,
    ENABLE_SECRET,
    HTTP_SERVER,
    INSECURE_MODE,
    IP_SOURCE_ROUTE,
    LEGACY_SERVICES,
    SECRET_TYPE_0,
    SECRET_TYPE_4,
    SECRET_TYPE_5,
    SECRET_TYPE_6,
    SECRET_TYPE_7,
    SECRET_TYPE_8,
    SECRET_TYPE_9,
    SNMP_GLOBAL_ENFORCE_PRIV,
    SNMP_V1_V2C_COMMUNITIES,
    SNMP_V1_V2C_READ_WRITE_COMMUNITIES,
    SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME,
    SNMP_V1_V2C_READ_WRITE_NO_ACL,
    SNMP_V3_CONFIGURED,
    SNMP_V3_GROUPS_WITHOUT_PRIV,
    SNMP_V3_USERS,
    SNMP_V3_USERS_WITHOUT_PRIV,
    TELNET_LINES,
    ConfigFact,
    FactValue,
)
from network_analyser.records.unknown import Unknown

_VTY_HEADER: Final = re.compile(r"line\s+vty\b", re.IGNORECASE)
_TRANSPORT_INPUT: Final = re.compile(r"transport\s+input\s+(.+)", re.IGNORECASE)
_SECRET_LINE: Final = re.compile(r"(?<![\w-])(?:password|secret)\s+([0-9])(?=\s|$)", re.IGNORECASE)
_ENABLE_SECRET: Final = re.compile(r"^enable\s+secret(?:\s|$)", re.IGNORECASE)
_ENABLE_PASSWORD: Final = re.compile(r"^enable\s+password(?:\s|$)", re.IGNORECASE)
_SNMP_COMMUNITY: Final = re.compile(r"^snmp-server\s+community\s+(\S+)(.*)$", re.IGNORECASE)
_SNMP_USER: Final = re.compile(r"^snmp-server\s+user\s+\S+\s+(.*)$", re.IGNORECASE)
_SNMP_GROUP: Final = re.compile(r"^snmp-server\s+group\s+\S+\s+(.*)$", re.IGNORECASE)
_DEFAULT_COMMUNITY_NAMES: Final = frozenset({"public", "private"})
_SECRET_TYPES: Final = (
    (0, SECRET_TYPE_0),
    (4, SECRET_TYPE_4),
    (5, SECRET_TYPE_5),
    (6, SECRET_TYPE_6),
    (7, SECRET_TYPE_7),
    (8, SECRET_TYPE_8),
    (9, SECRET_TYPE_9),
)
_NO_VTY: Final = "no line vty block in the running config"
_LEGACY_PREFIXES: Final = (
    ("service pad", "PAD"),
    ("service finger", "finger"),
    ("ip finger", "finger"),
    ("service tcp-small-servers", "TCP small servers"),
    ("service udp-small-servers", "UDP small servers"),
    ("ip bootp server", "BOOTP"),
    ("router odr", "ODR"),
    ("ip odr", "ODR"),
    ("ip rcmd", "rcmd"),
    ("ftp-server enable", "FTP"),
    ("tftp-server", "TFTP"),
    ("feature ftp", "FTP"),
    ("feature tftp", "TFTP"),
)


def read_config_facts(platform: Platform, text: str) -> tuple[ConfigFact, ...]:
    """Return `text`'s secret-free facts for `platform`, in name order.

    The config must already have passed `backup_problem`: an empty or missing config leaves
    every fact unread, which Analysis reads as `Unknown`, never as "off".
    """
    if not text.strip():
        return ()
    lines = [line.rstrip() for line in text.splitlines()]
    facts: dict[str, FactValue] = {
        **_secret_facts(lines),
        IP_SOURCE_ROUTE: _source_routing(lines),
        LEGACY_SERVICES: _legacy_services(lines),
        HTTP_SERVER: _http_server(lines),
        TELNET_LINES: _telnet_lines(platform, lines),
        **_snmp_facts(lines),
    }
    if platform is Platform.IOS_XE:
        facts[ENABLE_SECRET] = any(_ENABLE_SECRET.match(line.strip()) for line in lines)
        facts[ENABLE_PASSWORD] = any(_ENABLE_PASSWORD.match(line.strip()) for line in lines)
        facts[INSECURE_MODE] = any(line.strip().lower() == "system mode insecure" for line in lines)
    else:
        facts[SNMP_GLOBAL_ENFORCE_PRIV] = any(
            line.strip().lower() == "snmp-server globalenforcepriv" for line in lines
        )
    return tuple(ConfigFact(name, value) for name, value in sorted(facts.items()))


def _secret_facts(lines: list[str]) -> dict[str, int]:
    """Count the numbered `password`/`secret` lines by their type number."""
    counts = dict.fromkeys((number for number, _ in _SECRET_TYPES), 0)
    for line in lines:
        for match in _SECRET_LINE.finditer(line):
            number = int(match.group(1))
            if number in counts:
                counts[number] += 1
    return {name: counts[number] for number, name in _SECRET_TYPES}


def _source_routing(lines: list[str]) -> bool:
    """Whether IP source routing is on. Its default is on, so only the `no` form turns it off."""
    for line in lines:
        text = line.strip().lower()
        if text == "no ip source-route":
            return False
    return True


def _legacy_services(lines: list[str]) -> tuple[str, ...]:
    """The legacy services the config explicitly turns on, by fixed keyword."""
    found: list[str] = []
    for line in lines:
        text = line.strip().lower()
        for prefix, keyword in _LEGACY_PREFIXES:
            if text.startswith(prefix) and keyword not in found:
                found.append(keyword)
    return tuple(found)


def _http_server(lines: list[str]) -> bool:
    return any(line.strip().lower() in {"ip http server", "feature http-server"} for line in lines)


def _telnet_lines(platform: Platform, lines: list[str]) -> tuple[str, ...] | Unknown:
    """The vty blocks where Telnet is permitted; `Unknown` when no vty block is shown.

    A vty block with no `transport input` line permits Telnet, because the default is `all`.
    NX-OS needs `feature telnet` as well, and without it Telnet is off whatever the vty says.
    """
    if platform is Platform.NX_OS and not any(
        line.strip().lower() == "feature telnet" for line in lines
    ):
        return ()
    blocks = _vty_blocks(lines)
    if not blocks:
        return Unknown(_NO_VTY)
    return tuple(
        header
        for header, settings in blocks
        if _transport_permits_telnet(_setting(settings, "transport input"))
    )


def _vty_blocks(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Every top-level `line vty` block with its indented settings, in config order."""
    blocks: list[tuple[str, list[str]]] = []
    header: str | None = None
    settings: list[str] = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        text = raw.strip()
        if not raw[:1].isspace():
            if header is not None:
                blocks.append((header, settings))
                header, settings = None, []
            if _VTY_HEADER.match(text):
                header = _vty_header(text)
            continue
        if header is not None:
            settings.append(text)
    if header is not None:
        blocks.append((header, settings))
    return blocks


def _vty_header(text: str) -> str:
    """`line vty 0 4` rebuilt from its line numbers, so no raw config text is kept."""
    numbers = [part for part in text.split()[2:] if part.isdigit()]
    return "line vty" + (f" {' '.join(numbers)}" if numbers else "")


def _setting(settings: list[str], command: str) -> str | None:
    """The first setting that starts with `command`, or None."""
    return next((item for item in settings if item.lower().startswith(command)), None)


def _transport_permits_telnet(setting: str | None) -> bool:
    """Whether a `transport input` line, or the default `all`, lets Telnet in."""
    if setting is None:
        return True
    match = _TRANSPORT_INPUT.match(setting)
    if match is None:
        return True
    allowed = {token.lower() for token in match.group(1).split()}
    return "all" in allowed or "telnet" in allowed


def _snmp_facts(lines: list[str]) -> dict[str, FactValue]:
    """Count SNMPv1/v2c communities and SNMPv3 users and groups, without any name."""
    communities = read_write = default_name = no_acl = 0
    users = users_without_priv = groups = groups_without_priv = 0
    for line in lines:
        text = line.strip()
        community = _SNMP_COMMUNITY.match(text)
        if community is not None:
            communities += 1
            name, tail = community.group(1).strip('"'), community.group(2).split()
            writable, acl = _community_access(tail)
            if writable:
                read_write += 1
                default_name += int(name.lower() in _DEFAULT_COMMUNITY_NAMES)
                no_acl += int(acl is None)
            continue
        user = _SNMP_USER.match(text)
        if user is not None:
            users += 1
            users_without_priv += int(
                "priv" not in {token.lower() for token in user.group(1).split()}
            )
            continue
        group = _SNMP_GROUP.match(text)
        if group is not None:
            tokens = [token.lower() for token in group.group(1).split()]
            if "v3" in tokens:
                groups += 1
                after = tokens.index("v3") + 1
                level = tokens[after] if after < len(tokens) else ""
                groups_without_priv += int(level != "priv")
    return {
        SNMP_V1_V2C_COMMUNITIES: communities,
        SNMP_V1_V2C_READ_WRITE_COMMUNITIES: read_write,
        SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME: default_name,
        SNMP_V1_V2C_READ_WRITE_NO_ACL: no_acl,
        SNMP_V3_CONFIGURED: users + groups > 0,
        SNMP_V3_USERS: users,
        SNMP_V3_USERS_WITHOUT_PRIV: users_without_priv,
        SNMP_V3_GROUPS_WITHOUT_PRIV: groups_without_priv,
    }


def _community_access(tail: list[str]) -> tuple[bool, str | None]:
    """Whether an `snmp-server community` tail is read-write, and its access list if any."""
    for index, token in enumerate(tail):
        if token.upper() in {"RO", "RW"}:
            acl = tail[index + 1] if index + 1 < len(tail) else None
            return token.upper() == "RW", acl
    return False, None
