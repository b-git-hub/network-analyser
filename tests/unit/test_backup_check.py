"""The Backup command and acceptance check in each Platform module (ticket #51; stories 95-97).

A running config counts as a Backup only if no error came back, its framing is right
(header and closing `end` on IOS-XE; a `version` line on NX-OS) and it has a `hostname` line.
Otherwise the check gives a fixed reason that never quotes the device's text.
"""

import pytest

from network_analyser import platforms
from network_analyser.records import Platform
from tests.support import device_text

NO_FULL_CONFIG = "the account cannot read the full running config"
INCOMPLETE = "the running config came back incomplete"
NO_HOSTNAME = "the running config has no hostname line"


def test_ios_xe_is_always_sent_the_full_view_of_the_running_config() -> None:
    assert platforms.backup_command(Platform.IOS_XE) == "show running-config view full"
    assert platforms.permits(Platform.IOS_XE, "show running-config view full")
    assert not platforms.permits(Platform.IOS_XE, "show running-config")


def test_nxos_is_sent_its_running_config_command() -> None:
    assert platforms.backup_command(Platform.NX_OS) == "show running-config"
    assert platforms.permits(Platform.NX_OS, "show running-config")


def test_the_backup_commands_are_never_sent_before_identification() -> None:
    assert not platforms.permits(None, "show running-config")
    assert not platforms.permits(None, "show running-config view full")


@pytest.mark.parametrize(
    ("platform", "config"),
    [
        (Platform.IOS_XE, device_text.IOS_XE_RUNNING_CONFIG),
        (Platform.NX_OS, device_text.NXOS_RUNNING_CONFIG),
    ],
)
def test_a_whole_config_is_a_backup(platform: Platform, config: str) -> None:
    assert platforms.backup_problem(platform, config) is None


@pytest.mark.parametrize("platform", list(Platform))
@pytest.mark.parametrize(
    "reply",
    [
        device_text.COMMAND_AUTHORISATION_FAILED,
        device_text.IOS_XE_INVALID_INPUT,
        device_text.NXOS_PERMISSION_DENIED,
        "",
        "\n\n",
    ],
)
def test_an_error_or_empty_reply_is_not_a_backup(platform: Platform, reply: str) -> None:
    assert platforms.backup_problem(platform, reply) == NO_FULL_CONFIG


def test_a_banner_line_that_looks_like_an_error_is_still_part_of_a_whole_config() -> None:
    config = device_text.IOS_XE_RUNNING_CONFIG.replace(
        "Authorised access only.\n", "% Authorised access only.\n"
    )

    assert platforms.backup_problem(Platform.IOS_XE, config) is None


@pytest.mark.parametrize(
    "config",
    [
        device_text.IOS_XE_RUNNING_CONFIG.removesuffix("end\n"),  # cut short
        device_text.IOS_XE_RUNNING_CONFIG.replace("Current configuration : 330 bytes\n", ""),
        device_text.IOS_XE_RUNNING_CONFIG.replace("Building configuration...\n", "x\n", 1).replace(
            "Current configuration : 330 bytes\n", ""
        ),
        "hostname sw-a\nend\n",  # no header
        device_text.IOS_XE_RUNNING_CONFIG + "interface Vlan1\n",  # more after the end
    ],
)
def test_an_ios_xe_config_without_its_header_and_closing_end_is_incomplete(config: str) -> None:
    assert platforms.backup_problem(Platform.IOS_XE, config) == INCOMPLETE


def test_an_nxos_config_without_its_version_line_is_incomplete() -> None:
    config = device_text.NXOS_RUNNING_CONFIG.replace("version 9.3(8) Bios:version\n", "")

    assert platforms.backup_problem(Platform.NX_OS, config) == INCOMPLETE


@pytest.mark.parametrize(
    ("platform", "config"),
    [
        (Platform.IOS_XE, device_text.IOS_XE_RUNNING_CONFIG.replace("hostname sw-a\n", "")),
        (Platform.NX_OS, device_text.NXOS_RUNNING_CONFIG.replace("hostname nx-a\n", "")),
        (Platform.IOS_XE, device_text.IOS_XE_RUNNING_CONFIG.replace("hostname sw-a", " hostname")),
    ],
)
def test_a_config_without_a_hostname_line_is_not_a_backup(platform: Platform, config: str) -> None:
    assert platforms.backup_problem(platform, config) == NO_HOSTNAME
