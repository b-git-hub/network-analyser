"""Static rules that keep the tool read-only and passwords where they belong (CLAUDE.md; #49).

- No Netmiko call that enters configuration or enable mode, saves or commits is ever made,
  and no Netmiko or Paramiko shortcut that would skip the gateway's checks is used
  (`ConnectHandler`, `SSHClient`, `AutoAddPolicy`, telnet). Story 53-55, ADR 0002.
- Netmiko's session log is never given anything but None (story 165).
- A Credential Set password is handed over (`password_for_login`) only inside `credentials`
  and `device_gateway` (ADR 0003; CODING_STANDARDS.md "Secrets").

Each rule runs over the real package (which must be clean) and over a planted snippet (which
must be caught), so a rule that stopped matching would fail too.
"""

import ast
import textwrap
from collections.abc import Callable

import pytest

from tests.support.source_scan import source_files

type Rule = Callable[[str, ast.Module], list[str]]

# Netmiko methods that change mode or state. `device_gateway/ssh.py` overrides each one to
# refuse; nothing anywhere may call them.
CONFIG_CALLS = frozenset(
    {
        "config_mode",
        "exit_config_mode",
        "check_config_mode",
        "send_config_set",
        "send_config_from_file",
        "enable",
        "exit_enable_mode",
        "save_config",
        "commit",
        "send_multiline",
        "send_multiline_timing",
        "send_command_timing",
    }
)
# Ways round the gateway's own checks: Netmiko's or Paramiko's connection set-up does its own
# host-key policy, key and agent lookups, and Telnet.
SHORTCUTS = frozenset(
    {"ConnectHandler", "SSHClient", "AutoAddPolicy", "WarningPolicy", "telnetlib", "Telnet"}
)
HANDOVER_CALL = "password_for_login"
HANDOVER_OWNERS = ("credentials/", "device_gateway/")


def config_calls(relative: str, tree: ast.Module) -> list[str]:
    """Find calls of Netmiko's mode-changing methods."""
    return [
        f"{relative}:{node.lineno} calls {node.func.attr}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in CONFIG_CALLS
    ]


def shortcuts(relative: str, tree: ast.Module) -> list[str]:
    """Find any use of a connection shortcut that skips the gateway's checks."""
    found = [
        (node.lineno, node.attr if isinstance(node, ast.Attribute) else node.id)
        for node in ast.walk(tree)
        if (isinstance(node, ast.Attribute) and node.attr in SHORTCUTS)
        or (isinstance(node, ast.Name) and node.id in SHORTCUTS)
    ]
    found += [
        (node.lineno, alias.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
        if alias.name.split(".")[-1] in SHORTCUTS
    ]
    return [f"{relative}:{line} uses {name}" for line, name in sorted(set(found))]


def session_logs(relative: str, tree: ast.Module) -> list[str]:
    """Find a `session_log=` argument that is not the constant None."""
    return [
        f"{relative}:{node.value.lineno} gives a session log"
        for node in ast.walk(tree)
        if isinstance(node, ast.keyword)
        and node.arg == "session_log"
        and not (isinstance(node.value, ast.Constant) and node.value.value is None)
    ]


def password_handovers(relative: str, tree: ast.Module) -> list[str]:
    """Find a password handover outside `credentials` and `device_gateway`."""
    if relative.startswith(HANDOVER_OWNERS):
        return []
    return [
        f"{relative}:{node.lineno} takes a password"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == HANDOVER_CALL
    ]


RULES: dict[str, Rule] = {
    "config calls": config_calls,
    "shortcuts": shortcuts,
    "session logs": session_logs,
    "password handover": password_handovers,
}


@pytest.mark.parametrize("rule", RULES.values(), ids=RULES.keys())
def test_the_package_keeps_the_rule(rule: Rule) -> None:
    files = source_files()

    assert any(f.relative == "device_gateway/ssh.py" for f in files)
    assert [v for source in files for v in rule(source.relative, source.tree)] == []


def _scan(rule: Rule, relative: str, code: str) -> list[str]:
    return rule(relative, ast.parse(textwrap.dedent(code)))


def test_config_mode_calls_are_caught() -> None:
    code = """
        connection.config_mode()
        connection.send_config_set(["hostname x"])
        connection.enable()
        connection.save_config()
        connection.send_command("show version")
    """

    assert _scan(config_calls, "device_gateway/ssh.py", code) == [
        "device_gateway/ssh.py:2 calls config_mode",
        "device_gateway/ssh.py:3 calls send_config_set",
        "device_gateway/ssh.py:4 calls enable",
        "device_gateway/ssh.py:5 calls save_config",
    ]


def test_connection_shortcuts_are_caught() -> None:
    code = """
        from netmiko import ConnectHandler
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    """

    assert _scan(shortcuts, "device_gateway/ssh.py", code) == [
        "device_gateway/ssh.py:2 uses ConnectHandler",
        "device_gateway/ssh.py:4 uses SSHClient",
        "device_gateway/ssh.py:5 uses AutoAddPolicy",
    ]


def test_a_session_log_is_caught() -> None:
    code = """
        Connection(session_log=None)
        Connection(session_log="session.log")
        Connection(session_log=path)
    """

    assert _scan(session_logs, "device_gateway/ssh.py", code) == [
        "device_gateway/ssh.py:3 gives a session log",
        "device_gateway/ssh.py:4 gives a session log",
    ]


def test_a_password_handover_is_caught_outside_its_owners() -> None:
    code = "secret = sets.password_for_login(1)\n"

    assert _scan(password_handovers, "cli/cmd_run.py", code) == [
        "cli/cmd_run.py:1 takes a password"
    ]
    assert _scan(password_handovers, "device_gateway/visit.py", code) == []
    assert _scan(password_handovers, "credentials/sets.py", code) == []
