"""Security test 1, the allow-list gate (spec #37, Testing Decisions; stories 53-56).

At `device_gateway`'s send function, any command not on the Platform's allow-list is
refused, including near-misses and template parameters outside their pattern, and a refused
command never reaches the device. Plain pytest: the device is a recording fake shell.
"""

import dataclasses
from ipaddress import IPv4Address

import pytest

from network_analyser import platforms
from network_analyser.device_gateway import CommandRefusedError, DeviceSession
from network_analyser.device_gateway.link import Reply
from network_analyser.records import Platform
from network_analyser.records.events import AuditEvent, CommandResult, CommandSent, ErrorRaised
from network_analyser.records.run_request import Timeouts

pytestmark = pytest.mark.security

DEVICE = IPv4Address("192.0.2.10")

ALLOWED = {
    Platform.IOS_XE: [
        "terminal length 0",
        "terminal width 511",
        "show version",
        "show privilege",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
        "show running-config view full",
        # The 0.2.0 Analysis commands (#97).
        "show inventory",
        "show snmp user",
        "show ntp associations",
        "show policy-map control-plane",
        "show ip ssh",
        "show system insecure configuration",
    ],
    Platform.NX_OS: [
        "terminal length 0",
        "terminal width 511",
        "show version",
        "show user-account netops-ro",
        "show user-account svc.nexus_2",
        "show cdp neighbors detail | json",
        "show lldp neighbors detail | json",
        "show running-config",
        # The new read-only commands of release 0.2.0 (tickets #97, #98).
        "show inventory | json",
        "show ntp peer-status | json",
        "show copp status | json",
        "show ssh key",
        "show guestshell",
        "show virtual-service list",
    ],
}

NEAR_MISSES = [
    "",
    " ",
    "show version ",
    " show version",
    "show  version",
    "Show version",
    "SHOW VERSION",
    "show ver",
    "sh version",
    "show version\n",
    "show version\r",
    "show version\nconfigure terminal",
    "show version | include Serial",
    "show version | redirect flash:x",
    "show version; configure terminal",
    "show version\x00",
    "show versi\u043en",  # a Cyrillic o
    "terminal length 1",
    "terminal length 0 ",
    "terminal width 512",
    "terminal monitor",
    "configure terminal",
    "conf t",
    "enable",
    "exit",
    "end",
    "write memory",
    "copy running-config startup-config",
    "reload",
    "show running-config all",
    "show running-config view",
    "show running-config view full | include secret",
    "show running-config | redirect flash:x",
    "show running-config interface Vlan1",
    "show startup-config",
    "show privilege\x1b[A",
    "show cdp neighbors",
    "show cdp neighbors detail | json ",
    "show cdp neighbors detail | json | redirect bootflash:x",
    "show cdp neighbors detail | json-pretty",
    "show cdp neighbors detail | include IP",
    "show cdp neighbors GigabitEthernet1/0/1 detail",
    "show lldp neighbors detail | json\nconfigure terminal",
    "show lldp neighbors",
    # Near-misses on the 0.2.0 commands (#97).
    "show inventory all",
    "show snmp user netops-ro",
    "show ntp associations detail",
    "show policy-map control-plane input",
    "show ip ssh vrf Mgmt-intf",
    "show crypto key mypubkey rsa",
    "show system insecure configuration | include Severity",
    "show system insecure configurations",
    "show system insecure-configuration",
    "show system insecure configuration\n",
]
# Near-misses on one Platform that are allowed on the other (#51): IOS-XE is only ever sent
# the full view (story 96), and NX-OS has no CLI views.
PLATFORM_NEAR_MISSES = {
    Platform.IOS_XE: [
        "show running-config",
        # IOS/IOS-XE reads text inventory; the NX-OS JSON form is not on its allow-list (#97).
        "show inventory | json",
    ],
    Platform.NX_OS: [
        "show running-config view full",
        # The new commands are exact strings, JSON form included (#97, #98). SNMPv3 users
        # come from the running config, so there is deliberately no `show snmp user`.
        "show inventory",
        "show inventory | json ",
        "show inventory | json-pretty",
        "show inventory | include PID",
        "show ntp peer-status",
        "show ntp peer-status | json\nconfigure terminal",
        "show copp status",
        "show copp status | json | redirect bootflash:x",
        "show ssh key ",
        "show ssh key rsa",
        "show ssh key | include bitcount",
        "show guestshell detail",
        "show guestshell | json",
        "show virtual-service list | json",
        "show snmp user",
        "show snmp user | json",
    ],
}

BAD_PARAMETERS = [
    "show user-account",
    "show user-account ",
    "show user-account a b",
    "show user-account a|b",
    "show user-account a;reload",
    "show user-account -a",
    "show user-account .a",
    "show user-account " + "a" * 33,
    "show user-account a\nconfigure terminal",
    "show user-account a\n",
    "show user-account user@corp",
    "show user-account \u0430dmin",  # a Cyrillic a
    "show user-account netops-ro | include roles",
]


class RecordingShell:
    """A shell that records every line that reached it."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def prompt(self) -> str | ErrorRaised:
        return "sw-a#"

    def run(self, line: str, timeout: float) -> Reply:
        assert timeout > 0
        self.lines.append(line)
        return Reply("output\nsw-a#", CommandResult.OK)

    def close(self) -> None:
        return None


def _session(platform: Platform | None) -> tuple[DeviceSession, RecordingShell, list[AuditEvent]]:
    events: list[AuditEvent] = []
    session = DeviceSession(DEVICE, events.append, Timeouts())
    shell = RecordingShell()
    session.attach(shell)
    if platform is not None:
        session.identified(platform)
    return session, shell, events


@pytest.mark.parametrize(
    ("platform", "command"),
    [(p, c) for p, commands in ALLOWED.items() for c in commands],
)
def test_an_allow_listed_command_is_sent_and_audited_as_its_exact_string(
    platform: Platform, command: str
) -> None:
    session, shell, events = _session(platform)

    assert session.send(platform, command) == "output"

    assert shell.lines == [command]
    (sent,) = events
    assert isinstance(sent, CommandSent)
    assert sent.command == command


@pytest.mark.parametrize(
    ("platform", "command"),
    [(p, c) for p in Platform for c in NEAR_MISSES + BAD_PARAMETERS + PLATFORM_NEAR_MISSES[p]],
)
def test_anything_else_is_refused_and_never_reaches_the_device(
    platform: Platform, command: str
) -> None:
    session, shell, events = _session(platform)

    with pytest.raises(CommandRefusedError):
        session.send(platform, command)

    assert shell.lines == []
    assert events == []


@pytest.mark.parametrize("command", ["show privilege", "show user-account netops-ro"])
def test_before_identification_only_commands_every_platform_allows_pass(command: str) -> None:
    session, shell, _ = _session(None)

    for common in ("terminal length 0", "terminal width 511", "show version"):
        session.send(None, common)
    with pytest.raises(CommandRefusedError):
        session.send(None, command)

    assert shell.lines == ["terminal length 0", "terminal width 511", "show version"]


@pytest.mark.parametrize(
    ("platform", "command"),
    [
        (Platform.IOS_XE, "show cdp neighbors detail | json"),
        (Platform.IOS_XE, "show lldp neighbors detail | json"),
        (Platform.NX_OS, "show cdp neighbors detail"),
        (Platform.NX_OS, "show lldp neighbors detail"),
    ],
)
def test_each_platform_takes_only_its_own_form_of_the_neighbour_commands(
    platform: Platform, command: str
) -> None:
    session, shell, _ = _session(platform)

    with pytest.raises(CommandRefusedError):
        session.send(platform, command)

    assert shell.lines == []


def test_a_command_meant_for_another_platform_is_refused() -> None:
    session, shell, _ = _session(Platform.NX_OS)

    with pytest.raises(CommandRefusedError):
        session.send(Platform.IOS_XE, "show privilege")
    with pytest.raises(CommandRefusedError):
        session.send(None, "show version")

    assert shell.lines == []


def test_the_librarys_own_writes_pass_the_same_gate() -> None:
    session, _, _ = _session(Platform.IOS_XE)

    assert session.permits("terminal width 511")
    assert not session.permits("exit")
    assert not session.permits("configure terminal")


def test_the_compiled_in_allow_list_cannot_be_widened_at_run_time() -> None:
    allow_list = platforms.ALLOW_LISTS[Platform.NX_OS]
    (template,) = [e for e in allow_list.entries if isinstance(e, platforms.Template)]

    with pytest.raises(TypeError):
        platforms.ALLOW_LISTS[Platform.IOS_XE] = allow_list  # type: ignore[index]  # proving it is read-only
    with pytest.raises(dataclasses.FrozenInstanceError):
        allow_list.entries = ()  # type: ignore[misc]  # proving it is frozen
    with pytest.raises(TypeError):
        template.parameters["username"] = ".*"  # type: ignore[index]  # proving it is read-only


def test_a_template_parameter_may_never_match_a_space() -> None:
    with pytest.raises(ValueError, match="space"):
        platforms.Template("show user-account {username}", {"username": r".+"})
