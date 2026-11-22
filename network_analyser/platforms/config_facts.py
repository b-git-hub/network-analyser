"""Secret-free config facts, read from a running config at capture time (#96).

`read_config_facts(platform, text)` turns the raw running config into plain `ConfigFact`s:
counts, booleans and fixed keywords only. A config line, secret, hash, key or community string
is never kept. It is called inside the visit, after the Backup has been accepted, and the raw
config still goes only to the Backup sink (CODING_STANDARDS §3).

The fact names are the published vocabulary in docs/config-facts.md; later hardening Checks
read exactly these.
"""

import re
from dataclasses import dataclass
from ipaddress import ip_address
from itertools import pairwise
from typing import Final

from network_analyser.platforms.routing_auth import routing_authentication_missing
from network_analyser.records import Platform
from network_analyser.records.analysis import SNMP_V3_USER_CRYPTO
from network_analyser.records.config_facts import (
    AAA_ACCOUNTING,
    AAA_AUTHORIZATION,
    AAA_CENTRAL_LOGIN,
    AAA_LOGIN_FALLBACK_NONE,
    AAA_NEW_MODEL,
    ENABLE_PASSWORD,
    ENABLE_SECRET,
    EXEC_TIMEOUT_DISABLED_LINES,
    FHRP_GROUPS,
    FHRP_GROUPS_WITHOUT_AUTHENTICATION,
    HTTP_SERVER,
    ICMP_REDIRECTS_L3_INTERFACES,
    ICMP_UNREACHABLES_L3_INTERFACES,
    INSECURE_MODE,
    IP_SOURCE_ROUTE,
    LEGACY_SERVICES,
    LOGIN_BLOCK_FOR,
    NTP_AUTHENTICATED,
    NTP_CONFIGURED,
    NTP_MD5_AUTHENTICATION,
    PASSWORD_STRENGTH_CHECK,
    PROXY_ARP_L3_INTERFACES,
    REMOTE_SYSLOG_SERVERS,
    ROUTING_AUTHENTICATION_MISSING,
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
    SSH_VERSION,
    TELNET_LINES,
    TYPE_6_ENABLED,
    VTY_ACCESS_CLASS_MISSING_LINES,
    ConfigFact,
    FactValue,
)
from network_analyser.records.unknown import Unknown

_LINE_HEADER: Final = re.compile(r"line\s+(con(?:sole)?|vty|aux|tty)\b", re.IGNORECASE)
_TRANSPORT_INPUT: Final = re.compile(r"transport\s+input\s+(.+)", re.IGNORECASE)
_ACCESS_CLASS_IN: Final = re.compile(r"^access-class\s+\S+\s+in(?:\s|$)", re.IGNORECASE)
_EXEC_TIMEOUT: Final = re.compile(r"^exec-timeout\s+(\S+)(?:\s+(\S+))?", re.IGNORECASE)
_SSH_VERSION: Final = re.compile(r"^ip\s+ssh\s+version\s+([12])\s*$", re.IGNORECASE)
_AAA_LOGIN: Final = re.compile(r"^aaa\s+authentication\s+login\s+\S+\s+(.*)$", re.IGNORECASE)
_AAA_AUTHORIZATION: Final = re.compile(r"^aaa\s+authorization\b", re.IGNORECASE)
_AAA_ACCOUNTING: Final = re.compile(r"^aaa\s+accounting\b", re.IGNORECASE)
_SECRET_LINE: Final = re.compile(
    r"(?<![\w-])(?:password|secret)\s+(?:level\s+\d+\s+)?([0-9])(?=\s|$)", re.IGNORECASE
)
_KEY_LINE: Final = re.compile(
    r"(?<![\w-])(?:key|key-string|md5|authentication-key)\s+([0-9])(?=\s+\S)", re.IGNORECASE
)
_CLEARTEXT_LINE_PASSWORD: Final = re.compile(r"^password\s+(?![0-9](?:\s|$))\S", re.IGNORECASE)
_ENABLE_SECRET: Final = re.compile(r"^enable\s+secret(?:\s|$)", re.IGNORECASE)
_ENABLE_PASSWORD: Final = re.compile(r"^enable\s+password(?:\s|$)", re.IGNORECASE)
_SNMP_COMMUNITY: Final = re.compile(r"^snmp-server\s+community\s+(\S+)(.*)$", re.IGNORECASE)
_SNMP_USER: Final = re.compile(r"^snmp-server\s+user\s+\S+\s+(.*)$", re.IGNORECASE)
_SNMP_GROUP: Final = re.compile(r"^snmp-server\s+group\s+\S+\s+(.*)$", re.IGNORECASE)
_DEFAULT_COMMUNITY_NAMES: Final = frozenset({"public", "private"})
_SNMP_V1_V2C_KEYWORDS: Final = frozenset({"v1", "v2c"})
_NXOS_ACL_KEYWORDS: Final = frozenset({"use-acl", "use-ipv4acl", "use-ipv6acl"})
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
_NXOS_AUTH: Final = {"md5": "MD5", "sha": "SHA", "sha-256": "SHA-256"}
_NXOS_SNMP_USER_UNREADABLE: Final = "an NX-OS snmp-server user line was not understood"
_NXOS_TYPE_6_UNKNOWN: Final = (
    "the NX-OS command that enables AES type 6 encryption is not confirmed"
)
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
_NTP_SERVER: Final = re.compile(r"^ntp\s+(?:server|peer)\s+\S+(.*)$", re.IGNORECASE)
_NTP_MASTER: Final = re.compile(r"^ntp\s+master(?:\s|$)", re.IGNORECASE)
_NTP_KEY: Final = re.compile(r"^ntp\s+authentication-key\s+(\d+)\s+(\S+)", re.IGNORECASE)
_NTP_TRUSTED_KEY: Final = re.compile(
    r"^ntp\s+trusted-key\s+(\d+)(?:\s*-\s*(\d+))?\s*$", re.IGNORECASE
)
_NTP_AUTHENTICATE: Final = re.compile(r"^ntp\s+authenticate\s*$", re.IGNORECASE)
_L3_ADDRESS: Final = re.compile(r"^ip\s+(?:address|unnumbered)\s+", re.IGNORECASE)
_FLAT_FHRP: Final = re.compile(r"^(standby|vrrp|glbp)\s+(\d+)\s+(.+)$", re.IGNORECASE)
_BLOCK_FHRP: Final = re.compile(r"^(hsrp|vrrp)\s+(\d+)\s*$", re.IGNORECASE)


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
        LEGACY_SERVICES: _legacy_services(lines),
        HTTP_SERVER: _http_server(lines),
        TELNET_LINES: _telnet_lines(platform, lines),
        VTY_ACCESS_CLASS_MISSING_LINES: _vty_access_class_missing(lines),
        EXEC_TIMEOUT_DISABLED_LINES: _exec_timeout_disabled(lines),
        **_aaa_facts(lines),
        **_snmp_facts(platform, lines),
        **_service_facts(platform, lines),
    }
    if platform is Platform.IOS_XE:
        facts[IP_SOURCE_ROUTE] = _source_routing(lines)
        facts[ENABLE_SECRET] = any(_ENABLE_SECRET.match(line.strip()) for line in lines)
        facts[ENABLE_PASSWORD] = any(_ENABLE_PASSWORD.match(line.strip()) for line in lines)
        facts[INSECURE_MODE] = any(line.strip().lower() == "system mode insecure" for line in lines)
        facts[LOGIN_BLOCK_FOR] = any(
            line.strip().lower().startswith("login block-for") for line in lines
        )
        facts[SSH_VERSION] = _ssh_version(lines)
        facts[AAA_NEW_MODEL] = any(line.strip().lower() == "aaa new-model" for line in lines)
        facts[TYPE_6_ENABLED] = any(
            line.strip().lower() == "password encryption aes" for line in lines
        )
    else:
        facts[SNMP_V3_USER_CRYPTO] = _nxos_snmp_user_crypto(lines)
        facts[SNMP_GLOBAL_ENFORCE_PRIV] = any(
            line.strip().lower() == "snmp-server globalenforcepriv" for line in lines
        )
        facts[PASSWORD_STRENGTH_CHECK] = not any(
            line.strip().lower() == "no password strength-check" for line in lines
        )
        facts[TYPE_6_ENABLED] = Unknown(_NXOS_TYPE_6_UNKNOWN)
    return tuple(ConfigFact(name, value) for name, value in sorted(facts.items()))


def _secret_facts(lines: list[str]) -> dict[str, int]:
    """Count secrets by their type number: `password`/`secret` lines, keys, cleartext lines.

    Three forms are read. A `password` or `secret` line carries a type number, with an optional
    `level N` before it. A `key`, `key-string`, `md5` or `authentication-key` keyword followed
    by a type number and a value is a typed key (a bare `key 7` is a key id, and an NTP key
    line puts its key number there, so neither counts). A `password` line under `line` with no
    type number is cleartext, because IOS prints it that way without `service
    password-encryption`.
    """
    counts = dict.fromkeys((number for number, _ in _SECRET_TYPES), 0)
    for line in lines:
        patterns = (_SECRET_LINE,) if _is_ntp_line(line) else (_SECRET_LINE, _KEY_LINE)
        for pattern in patterns:
            for match in pattern.finditer(line):
                number = int(match.group(1))
                if number in counts:
                    counts[number] += 1
    counts[0] += _cleartext_line_passwords(lines)
    return {name: counts[number] for number, name in _SECRET_TYPES}


def _is_ntp_line(line: str) -> bool:
    return line.strip().lower().startswith("ntp ")


def _cleartext_line_passwords(lines: list[str]) -> int:
    """How many `line` blocks hold a `password` with no type number."""
    return sum(
        1
        for _, _, settings in _line_blocks(lines)
        for setting in settings
        if _CLEARTEXT_LINE_PASSWORD.match(setting)
    )


def _source_routing(lines: list[str]) -> bool:
    """Whether IP source routing is on, on IOS/IOS-XE only.

    The IOS default is on, so only the `no` form turns it off. NX-OS has no such default we
    can prove, so it is not read there.
    """
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
    return [(header, settings) for kind, header, settings in _line_blocks(lines) if kind == "vty"]


def _line_blocks(lines: list[str]) -> list[tuple[str, str, list[str]]]:
    """Every top-level `line` block as (kind, header, settings), in config order."""
    blocks: list[tuple[str, str, list[str]]] = []
    header: str | None = None
    kind = ""
    settings: list[str] = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        text = raw.strip()
        if not raw[:1].isspace():
            if header is not None:
                blocks.append((kind, header, settings))
                header, kind, settings = None, "", []
            match = _LINE_HEADER.match(text)
            if match is not None:
                word = match.group(1).lower()
                kind = "con" if word.startswith("con") else word
                header = _line_header(word, text)
            continue
        if header is not None:
            settings.append(text)
    if header is not None:
        blocks.append((kind, header, settings))
    return blocks


def _line_header(kind: str, text: str) -> str:
    """`line vty 0 4` or `line console` rebuilt from its numbers, so no raw text is kept."""
    numbers = [part for part in text.split()[2:] if part.isdigit()]
    return f"line {kind}" + (f" {' '.join(numbers)}" if numbers else "")


def _vty_header(text: str) -> str:
    """`line vty 0 4` rebuilt from its line numbers, so no raw config text is kept."""
    return _line_header("vty", text)


def _setting(settings: list[str], command: str) -> str | None:
    """The first setting that starts with `command`, or None."""
    return next((item for item in settings if item.lower().startswith(command)), None)


def _vty_access_class_missing(lines: list[str]) -> tuple[str, ...] | Unknown:
    """The vty blocks with no inbound `access-class`; `Unknown` when no vty block is shown."""
    blocks = _vty_blocks(lines)
    if not blocks:
        return Unknown(_NO_VTY)
    return tuple(
        header
        for header, settings in blocks
        if not any(_ACCESS_CLASS_IN.match(setting) for setting in settings)
    )


def _exec_timeout_disabled(lines: list[str]) -> tuple[str, ...]:
    """The console and vty blocks that explicitly disable the idle timeout (`exec-timeout 0`).

    An absent line is the vendor default (10 minutes on IOS/IOS-XE), not a hit; an AUX line's
    `exec-timeout 0 1` is a hardening recommendation (research #76, X12), not a hit. A timeout
    of 0 minutes and some seconds (`exec-timeout 0 30`) is a real timeout, not a disabled one.
    """
    disabled: list[str] = []
    for kind, header, settings in _line_blocks(lines):
        if kind not in {"con", "vty"}:
            continue
        setting = _setting(settings, "exec-timeout")
        match = None if setting is None else _EXEC_TIMEOUT.match(setting)
        if match is not None and match.group(1) == "0" and match.group(2) in {None, "0"}:
            disabled.append(header)
    return tuple(disabled)


def _ssh_version(lines: list[str]) -> int:
    """`ip ssh version`'s value; 0 when the line is absent (the release's default then applies)."""
    version = 0
    for line in lines:
        match = _SSH_VERSION.match(line.strip())
        if match is not None:
            version = int(match.group(1))
    return version


def _aaa_facts(lines: list[str]) -> dict[str, FactValue]:
    """Read AAA from the config: no method-list name, server group or key is kept."""
    fallback_none = 0
    central_login = False
    authorization = False
    accounting = False
    for line in lines:
        text = line.strip()
        login = _AAA_LOGIN.match(text)
        if login is not None:
            methods = {token.lower() for token in login.group(1).split()}
            fallback_none += int("none" in methods)
            central_login = central_login or "group" in methods
        elif _AAA_AUTHORIZATION.match(text):
            authorization = True
        elif _AAA_ACCOUNTING.match(text):
            accounting = True
    return {
        AAA_LOGIN_FALLBACK_NONE: fallback_none,
        AAA_CENTRAL_LOGIN: central_login,
        AAA_AUTHORIZATION: authorization,
        AAA_ACCOUNTING: accounting,
    }


def _transport_permits_telnet(setting: str | None) -> bool:
    """Whether a `transport input` line, or the default `all`, lets Telnet in."""
    if setting is None:
        return True
    match = _TRANSPORT_INPUT.match(setting)
    if match is None:
        return True
    allowed = {token.lower() for token in match.group(1).split()}
    return "all" in allowed or "telnet" in allowed


def _service_facts(platform: Platform, lines: list[str]) -> dict[str, FactValue]:
    """NTP, remote syslog, routing authentication, FHRP and ICMP facts (#101)."""
    return {
        **_ntp_facts(lines),
        REMOTE_SYSLOG_SERVERS: _remote_syslog_servers(lines),
        ROUTING_AUTHENTICATION_MISSING: routing_authentication_missing(lines),
        **_fhrp_facts(lines),
        **_icmp_facts(platform, lines),
    }


def _ntp_facts(lines: list[str]) -> dict[str, FactValue]:
    """Whether NTP is configured, and whether its used key authenticates it, and how.

    NTP authenticates only with `ntp authenticate` set and a server or peer that names a key
    that is also trusted (`ntp trusted-key 1 - 3` trusts every key from 1 to 3); a key line
    alone authenticates nothing. MD5 is reported separately so the Check can name it.
    """
    configured = authenticate = False
    keys: dict[int, str] = {}
    trusted: list[tuple[int, int]] = []
    referenced: list[int] = []
    for line in lines:
        text = line.strip()
        if _NTP_AUTHENTICATE.match(text):
            authenticate = True
            continue
        if _NTP_MASTER.match(text):
            configured = True
            continue
        server = _NTP_SERVER.match(text)
        if server is not None:
            configured = True
            key = _ntp_key_reference(server.group(1))
            if key is not None:
                referenced.append(key)
            continue
        key_line = _NTP_KEY.match(text)
        if key_line is not None:
            keys[int(key_line.group(1))] = key_line.group(2).lower()
            continue
        trusted_line = _NTP_TRUSTED_KEY.match(text)
        if trusted_line is not None:
            first = int(trusted_line.group(1))
            trusted.append((first, int(trusted_line.group(2) or first)))
    algorithms = {
        keys[key]
        for key in referenced
        if authenticate and key in keys and any(low <= key <= high for low, high in trusted)
    }
    return {
        NTP_CONFIGURED: configured,
        NTP_AUTHENTICATED: bool(algorithms),
        NTP_MD5_AUTHENTICATION: "md5" in algorithms,
    }


def _ntp_key_reference(tail: str) -> int | None:
    """The key number an NTP server or peer line names, or None."""
    tokens = tail.split()
    for index, token in enumerate(tokens):
        if token.lower() == "key" and index + 1 < len(tokens) and tokens[index + 1].isdigit():
            return int(tokens[index + 1])
    return None


def _remote_syslog_servers(lines: list[str]) -> int:
    """How many remote syslog servers are configured, never counting local logging.

    Only a top-level `logging host <x>`, `logging server <x>` or `logging <IP address>` is a
    server. Every other `logging` word (`on`, `userinfo`, `buffered`) and every indented line,
    such as `logging enable` under `archive` / `log config`, is local.
    """
    count = 0
    for line in lines:
        if line[:1].isspace():
            continue
        tokens = line.strip().lower().split()
        if len(tokens) < 2 or tokens[0] != "logging":  # noqa: PLR2004 (`logging` and a value)
            continue
        if tokens[1] in {"host", "server"}:
            count += int(len(tokens) > 2)  # noqa: PLR2004 (a named server follows)
        elif _is_ip_address(tokens[1]):
            count += 1
    return count


def _is_ip_address(text: str) -> bool:
    try:
        ip_address(text)
    except ValueError:
        return False
    return True


def _fhrp_facts(lines: list[str]) -> dict[str, FactValue]:
    """How many FHRP groups are configured, and how many have no authentication."""
    groups: dict[tuple[str, str, int], list[bool]] = {}
    for header, body in _interface_blocks(lines):
        current: tuple[str, str, int] | None = None
        current_indent = -1
        for indent, text in body:
            block = _BLOCK_FHRP.match(text)
            if block is not None:
                current = (header.lower(), block.group(1).upper(), int(block.group(2)))
                groups.setdefault(current, [False, False])
                current_indent = indent
                continue
            flat = _FLAT_FHRP.match(text)
            if flat is not None:
                key = (header.lower(), flat.group(1).upper(), int(flat.group(2)))
                state = groups.setdefault(key, [False, False])
                command = flat.group(3).lower()
                if command.startswith("ip "):
                    state[0] = True
                elif command.startswith("authentication"):
                    state[1] = True
                current = None
                continue
            if current is not None and indent > current_indent:
                command = text.lower()
                if command.startswith(("ip ", "address ")):
                    groups[current][0] = True
                elif command.startswith("authentication"):
                    groups[current][1] = True
            else:
                current = None
    configured = [state for state in groups.values() if state[0]]
    return {
        FHRP_GROUPS: len(configured),
        FHRP_GROUPS_WITHOUT_AUTHENTICATION: sum(
            1 for _, authenticated in configured if not authenticated
        ),
    }


def _icmp_facts(platform: Platform, lines: list[str]) -> dict[str, FactValue]:
    """How many live L3 interfaces have each insecure ICMP setting, by the Platform's default.

    A shut-down interface and a loopback send no ICMP to a neighbour, so neither is counted.
    The running config cannot show line state, so the Check also needs a live L3 interface.
    """
    redirects = unreachables = proxy_arp = 0
    for header, body in _interface_blocks(lines):
        commands = {text.lower() for _, text in body}
        if "shutdown" in commands or _is_loopback(header):
            continue
        if not any(_L3_ADDRESS.match(text) for _, text in body):
            continue
        redirects += int("no ip redirects" not in commands)
        unreachables += int("no ip unreachables" not in commands)
        if platform is Platform.NX_OS:
            proxy_arp += int("ip proxy-arp" in commands)
        else:
            proxy_arp += int("no ip proxy-arp" not in commands)
    return {
        ICMP_REDIRECTS_L3_INTERFACES: redirects,
        ICMP_UNREACHABLES_L3_INTERFACES: unreachables,
        PROXY_ARP_L3_INTERFACES: proxy_arp,
    }


def _is_loopback(header: str) -> bool:
    """Whether an `interface <name>` header names a loopback."""
    return header.lower().startswith("interface loopback")


def _interface_blocks(lines: list[str]) -> list[tuple[str, list[tuple[int, str]]]]:
    """Every top-level `interface` block, as its header and (indent, stripped) settings."""
    blocks: list[tuple[str, list[tuple[int, str]]]] = []
    header: str | None = None
    body: list[tuple[int, str]] = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        text = raw.strip()
        if not raw[:1].isspace():
            if header is not None:
                blocks.append((header, body))
                header, body = None, []
            if text.lower().startswith("interface "):
                header = text
            continue
        if header is not None:
            body.append((len(raw) - len(raw.lstrip()), text))
    if header is not None:
        blocks.append((header, body))
    return blocks


def _snmp_facts(platform: Platform, lines: list[str]) -> dict[str, FactValue]:
    """Count SNMPv1/v2c communities and SNMPv3 users and groups, without any name."""
    communities = _snmp_communities(platform, lines)
    read_write = [community for community in communities if community.writable]
    users = users_without_priv = groups = groups_without_priv = 0
    for line in lines:
        text = line.strip()
        user = _SNMP_USER.match(text)
        if user is not None:
            words = {token.lower() for token in user.group(1).split()}
            if words & _SNMP_V1_V2C_KEYWORDS:
                continue
            users += 1
            users_without_priv += int("priv" not in words)
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
        SNMP_V1_V2C_COMMUNITIES: len(communities),
        SNMP_V1_V2C_READ_WRITE_COMMUNITIES: len(read_write),
        SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME: sum(1 for item in read_write if item.default_name),
        SNMP_V1_V2C_READ_WRITE_NO_ACL: sum(1 for item in read_write if not item.has_acl),
        SNMP_V3_CONFIGURED: users + groups > 0,
        SNMP_V3_USERS: users,
        SNMP_V3_USERS_WITHOUT_PRIV: users_without_priv,
        SNMP_V3_GROUPS_WITHOUT_PRIV: groups_without_priv,
    }


def _nxos_snmp_user_crypto(lines: list[str]) -> FactValue:
    """One `<auth>/<privacy>` keyword pair per NX-OS `snmp-server user` line (story 60).

    The line reads `snmp-server user <name> [<role>] auth {md5|sha|sha-256} <key> [priv
    [aes-128] <key>] ...`. A `priv` with no `aes-128` is DES, the NX-OS default. The pair is
    read by position, so a key can never be mistaken for a keyword, and it holds no name or
    key. A line that cannot be read makes the whole fact `Unknown`, never a pass.
    """
    pairs: list[str] = []
    for line in lines:
        user = _SNMP_USER.match(line.strip())
        if user is None:
            continue
        pair = _nxos_user_pair(user.group(1).lower().split())
        if pair is None:
            return Unknown(_NXOS_SNMP_USER_UNREADABLE)
        pairs.append(pair)
    return tuple(pairs)


def _nxos_user_pair(tokens: list[str]) -> str | None:
    """`<auth>/<privacy>` from the tokens after an NX-OS user's name, or None if unreadable."""
    if "auth" not in tokens:
        return None if "priv" in tokens else "none/none"
    after = tokens.index("auth") + 1
    auth = _NXOS_AUTH.get(tokens[after]) if after < len(tokens) else None
    if auth is None:
        return None
    privacy = "none"
    if tokens[after + 2 : after + 3] == ["priv"]:
        privacy = "AES128" if tokens[after + 3 : after + 4] == ["aes-128"] else "DES"
    return f"{auth}/{privacy}"


@dataclass(slots=True)
class _Community:
    """One SNMPv1/v2c community's access, with no name kept beyond whether it is a default."""

    default_name: bool
    writable: bool = False
    has_acl: bool = False


def _snmp_communities(platform: Platform, lines: list[str]) -> list[_Community]:
    """Every community once, with its access merged from all the lines that name it.

    NX-OS prints the access list as a second line (`snmp-server community X use-ipv4acl A`),
    so its lines are joined by community name. IOS puts everything on one line, so each line
    is its own community.
    """
    found: dict[str | tuple[str, int], _Community] = {}
    for index, line in enumerate(lines):
        match = _SNMP_COMMUNITY.match(line.strip())
        if match is None:
            continue
        name = match.group(1).strip('"')
        key = name if platform is Platform.NX_OS else (name, index)
        community = found.setdefault(key, _Community(name.lower() in _DEFAULT_COMMUNITY_NAMES))
        writable, has_acl = _community_access(match.group(2).lower().split())
        community.writable = community.writable or writable
        community.has_acl = community.has_acl or has_acl
    return list(found.values())


def _community_access(tail: list[str]) -> tuple[bool, bool]:
    """Whether an `snmp-server community` tail is read-write, and whether it names an ACL.

    IOS says `RO` or `RW` and then the access list. NX-OS says `group <role>`, where
    `network-admin` is the read-write role, and names the access list after `use-acl`,
    `use-ipv4acl` or `use-ipv6acl`. NX-OS never prints `RW`.
    """
    writable = "rw" in tail or any(
        first == "group" and second == "network-admin" for first, second in pairwise(tail)
    )
    has_acl = any(token in _NXOS_ACL_KEYWORDS for token in tail[:-1])
    for index, token in enumerate(tail):
        if token in {"ro", "rw"}:
            has_acl = has_acl or index + 1 < len(tail)
            break
    return writable, has_acl
