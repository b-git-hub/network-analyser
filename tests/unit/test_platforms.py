"""What the tool knows about each Platform: identification, `show version` facts, privilege.

Driven through `platforms`' public interface with synthetic text (tests/support/device_text).
The allow-list itself is security test 1 (tests/security/test_1_allowlist_gate.py).
"""

import pytest

from network_analyser import platforms
from network_analyser.platforms import Hint, Unsupported
from network_analyser.records import Platform
from network_analyser.records.device import LandingPrivilege, Unknown, VersionFacts
from tests.support import device_text

# -- Identification (story 57-58) -------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "platform"),
    [
        (device_text.IOS_XE_SHOW_VERSION, Platform.IOS_XE),
        (device_text.IOL_SHOW_VERSION, Platform.IOS_XE),
        ("IOS-XE Software, Version 16.12.4\n", Platform.IOS_XE),
        (device_text.NXOS_SHOW_VERSION, Platform.NX_OS),
    ],
    ids=["IOS XE", "IOS (IOL)", "IOS-XE spelling", "NX-OS"],
)
def test_show_version_identifies_a_supported_platform(text: str, platform: Platform) -> None:
    assert platforms.identify(text) is platform


@pytest.mark.parametrize(
    ("text", "name"),
    [
        (device_text.ASA_SHOW_VERSION, "ASA"),
        (device_text.IOS_XR_SHOW_VERSION, "IOS-XR"),
        (device_text.UNKNOWN_SHOW_VERSION, "unrecognised"),
        ("", "unrecognised"),
    ],
)
def test_unsupported_platforms_are_rejected_explicitly(text: str, name: str) -> None:
    assert platforms.identify(text) == Unsupported(name)


def test_an_ios_xr_or_asa_banner_wins_over_a_supported_string_further_down() -> None:
    text = device_text.IOS_XR_SHOW_VERSION + "Cisco IOS Software\n"

    assert platforms.identify(text) == Unsupported("IOS-XR")


@pytest.mark.parametrize(
    ("ssh_id", "hint"),
    [
        ("SSH-2.0-CISCO_WLC", Hint.REJECT),
        ("SSH-2.0-Cisco-1.25", Platform.IOS_XE),
        ("SSH-2.0-OpenSSH_8.8 FIPS", Platform.NX_OS),
        ("SSH-2.0-OpenSSH_9.6", None),
        ("", None),
    ],
)
def test_the_ssh_identification_string_is_only_a_hint(
    ssh_id: str, hint: Hint | Platform | None
) -> None:
    assert platforms.ssh_id_hint(ssh_id) == hint


@pytest.mark.parametrize(
    ("prompt", "config"),
    [
        ("sw-a#", False),
        ("sw-a>", False),
        ("sw-a(config)#", True),
        ("sw-a(config-if)#", True),
        ("nx-a(config-router)# ", True),
        ("sw-a(config", False),
    ],
)
def test_a_configuration_mode_prompt_is_recognised(prompt: str, *, config: bool) -> None:
    assert platforms.is_config_prompt(prompt) is config


# -- show version facts -------------------------------------------------------------------------


def test_ios_xe_show_version_gives_hostname_model_version_and_every_stack_serial() -> None:
    facts = platforms.read_version(Platform.IOS_XE, device_text.IOS_XE_SHOW_VERSION)

    assert facts == VersionFacts(
        hostname="sw-a",
        model="C9300-48P",
        software_version="17.9.4a",
        serials=("TEST0000A01", "TEST0000A02"),
    )


def test_ios_xe_sdwan_show_version_records_the_router_operating_mode() -> None:
    facts = platforms.read_version(Platform.IOS_XE, device_text.IOS_XE_SDWAN_SHOW_VERSION)

    assert facts.router_operating_mode == "Controller-Managed"
    assert facts.model == "C8300-1N1S-4T2X"
    assert facts.software_version == "17.9.4a"


def test_a_show_version_without_a_router_operating_mode_records_none() -> None:
    facts = platforms.read_version(Platform.IOS_XE, device_text.IOS_XE_SHOW_VERSION)

    assert facts.router_operating_mode is None


def test_nxos_show_version_gives_hostname_model_version_and_serial() -> None:
    facts = platforms.read_version(Platform.NX_OS, device_text.NXOS_SHOW_VERSION)

    assert facts == VersionFacts(
        hostname="nx-a",
        model="C9300v",
        software_version="9.3(8)",
        serials=("TEST0000N01",),
        hardware_series="Nexus9000",
    )


def test_nxos_show_version_gives_the_nexus_series_the_hardware_line_names() -> None:
    text = "  cisco Nexus3000 C3048TP Chassis\n"

    facts = platforms.read_version(Platform.NX_OS, text)

    assert facts.hardware_series == "Nexus3000"


def test_the_same_nexus_series_named_twice_is_unambiguous() -> None:
    text = "  cisco Nexus9000 C9300v Chassis\n  cisco Nexus9000 C93180YC-EX Chassis\n"

    facts = platforms.read_version(Platform.NX_OS, text)

    assert facts.hardware_series == "Nexus9000"


def test_two_different_nexus_series_in_show_version_are_ambiguous() -> None:
    text = "  cisco Nexus9000 C9300v Chassis\n  cisco Nexus3000 C3048TP Chassis\n"

    facts = platforms.read_version(Platform.NX_OS, text)

    assert facts.hardware_series is None


def test_a_series_name_with_a_space_is_not_a_nexus_token() -> None:
    facts = platforms.read_version(Platform.NX_OS, "  cisco Nexus 9000 Chassis\n")

    assert facts.hardware_series is None


def test_a_non_nexus_platform_names_no_nexus_series() -> None:
    facts = platforms.read_version(Platform.IOS_XE, device_text.IOS_XE_SHOW_VERSION)

    assert facts.hardware_series is None


def test_facts_missing_from_show_version_are_unknown_never_empty() -> None:
    facts = platforms.read_version(Platform.NX_OS, "Cisco Nexus Operating System (NX-OS)\n")

    assert isinstance(facts.hostname, Unknown)
    assert isinstance(facts.model, Unknown)
    assert isinstance(facts.software_version, Unknown)
    assert isinstance(facts.serials, Unknown)


def test_a_hostname_with_control_characters_or_spaces_is_unknown() -> None:
    text = device_text.NXOS_SHOW_VERSION.replace("nx-a", "nx a\x1b[2J")

    facts = platforms.read_version(Platform.NX_OS, text)

    assert isinstance(facts.hostname, Unknown)


# -- Landing privilege (story 59; ADR 0005) -----------------------------------------------------


def test_ios_xe_reports_privilege_with_show_privilege() -> None:
    assert platforms.privilege_command(Platform.IOS_XE, "netops-ro") == "show privilege"


def test_nxos_reports_the_users_roles_with_show_user_account() -> None:
    command = platforms.privilege_command(Platform.NX_OS, "netops-ro")

    assert command == "show user-account netops-ro"


@pytest.mark.parametrize("username", ["net ops", "a|b", "-x", "user@corp.example", "a" * 33])
def test_a_username_outside_the_template_pattern_gives_no_privilege_command(
    username: str,
) -> None:
    assert platforms.privilege_command(Platform.NX_OS, username) is None


@pytest.mark.parametrize(
    ("platform", "text", "expected"),
    [
        (
            Platform.IOS_XE,
            device_text.IOS_XE_PRIVILEGE_15,
            LandingPrivilege("level 15", too_low=False),
        ),
        (
            Platform.IOS_XE,
            device_text.IOS_XE_PRIVILEGE_1,
            LandingPrivilege("level 1", too_low=True),
        ),
        (
            Platform.IOS_XE,
            "Currently in View Context with Privilege Level 15\n",
            LandingPrivilege("view, level 15", too_low=False),
        ),
        (
            Platform.NX_OS,
            device_text.NXOS_USER_ACCOUNT,
            LandingPrivilege("roles NA-READ", too_low=False),
        ),
        (
            Platform.NX_OS,
            "user:netops-ro\n        roles:priv-1\n",
            LandingPrivilege("roles priv-1", too_low=True),
        ),
        (
            Platform.NX_OS,
            "user:netops-ro\n        roles:network-admin priv-15\n",
            LandingPrivilege("roles network-admin, priv-15", too_low=False),
        ),
    ],
    ids=["IOS-XE 15", "IOS-XE 1 too low", "IOS-XE view", "NX-OS role", "NX-OS priv-1", "admin"],
)
def test_landing_privilege_is_recorded_and_flagged_only_when_too_low(
    platform: Platform, text: str, expected: LandingPrivilege
) -> None:
    assert platforms.read_privilege(platform, text) == expected


@pytest.mark.parametrize("platform", list(Platform))
def test_privilege_output_not_understood_is_unknown(platform: Platform) -> None:
    assert isinstance(platforms.read_privilege(platform, "% Invalid input\n"), Unknown)
