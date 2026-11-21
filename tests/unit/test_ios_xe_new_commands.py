"""IOS/IOS-XE's 0.2.0 read-only commands and the out-of-date Device Role (#97).

Driven through `platforms.collect` with synthetic replies (tests/support/ios_xe_text), as
`test_ios_xe_collection` is. The six new commands join the compiled-in allow-list, are read
into the collected record, and `show system insecure configuration` is sent only to IOS-XE
17.18.2 or later (story 68). A device whose Device Role predates a new command raises one
out-of-date record naming the Checks it stopped (story 80), and that command's result is
`Unknown`, never a pass.
"""

from collections.abc import Mapping
from ipaddress import IPv4Address

import pytest

from network_analyser import platforms
from network_analyser.analysis.catalogue import PENDING_CHECK_NAMES
from network_analyser.analysis.checks import CHECKS
from network_analyser.platforms import Collection
from network_analyser.platforms.ios_xe import commands as c
from network_analyser.platforms.ios_xe import identify as ios_xe_identify
from network_analyser.platforms.ios_xe import outdated
from network_analyser.records import Platform
from network_analyser.records.collected import (
    ControlPlanePolicy,
    InsecureConfigurationItem,
    InventoryItem,
    InventoryKind,
    NtpAssociation,
    Reading,
    SnmpUser,
    SshSettings,
)
from network_analyser.records.device import VersionFacts
from network_analyser.records.unknown import Unknown
from tests.support import device_text, ios_xe_text

SHOW_VERSION = "show version"
DENIED = "                 ^\n% Invalid input detected at '^' marker.\n"
NEW_COMMANDS = (
    c.SHOW_INVENTORY,
    c.SHOW_SNMP_USER,
    c.SHOW_NTP_ASSOCIATIONS,
    c.SHOW_POLICY_MAP_CONTROL_PLANE,
    c.SHOW_IP_SSH,
    c.SHOW_SYSTEM_INSECURE_CONFIGURATION,
)


class Device:
    """A fake `send`: answers from `replies`, records what was asked."""

    def __init__(self, replies: Mapping[str, str | Unknown] | None = None) -> None:
        self.replies = dict(ios_xe_text.REPLIES if replies is None else replies)
        self.asked: list[str] = []

    def __call__(self, command: str) -> str | Unknown:
        assert platforms.permits(Platform.IOS_XE, command), command
        self.asked.append(command)
        return self.replies.get(command, DENIED)


def collect(device: Device, version_text: str = device_text.IOS_XE_SHOW_VERSION) -> Collection:
    """Collect as the gateway does, from a `show version` reply at `version_text`."""
    device.replies.setdefault(SHOW_VERSION, version_text)
    return collect_facts(device, platforms.read_version(Platform.IOS_XE, version_text))


def collect_facts(device: Device, facts: VersionFacts) -> Collection:
    """Collect through the public seam with the `show version` facts already read."""
    found = platforms.collect(Platform.IOS_XE, device, facts)
    assert found is not None
    return found


def at_release(release: str) -> str:
    """`sw-a`'s `show version` reply, moved to `release`."""
    return device_text.IOS_XE_SHOW_VERSION.replace("17.09.04a", release).replace("17.9.4a", release)


def replies_at_17_18_2() -> dict[str, str | Unknown]:
    return {
        **ios_xe_text.REPLIES,
        c.SHOW_SYSTEM_INSECURE_CONFIGURATION: ios_xe_text.SHOW_SYSTEM_INSECURE_CONFIGURATION,
    }


def value[T](part: Reading[T] | Unknown | None) -> T:
    assert isinstance(part, Reading), part
    return part.value


# -- The allow-list and what is sent ----------------------------------------------------------


def test_every_new_command_is_on_the_compiled_in_allow_list() -> None:
    assert [
        command for command in NEW_COMMANDS if not platforms.permits(Platform.IOS_XE, command)
    ] == []


def test_every_mapped_check_id_is_a_shipped_or_pending_check() -> None:
    known = {definition.check.id for definition in CHECKS} | set(PENDING_CHECK_NAMES)

    assert {check for checks in outdated.CHECK_IDS_BY_COMMAND.values() for check in checks} <= (
        known
    )


def test_the_new_collection_commands_are_sent_once() -> None:
    device = Device()

    collect(device)

    for command in NEW_COMMANDS[:5]:
        assert device.asked.count(command) == 1, command


@pytest.mark.parametrize(
    ("release", "sent"),
    [
        ("17.18.1", False),
        ("17.18.2", True),
        ("17.18.2a", True),
        ("26.01.01", True),
        ("15.2(7)E7", False),
    ],
)
def test_the_insecure_configuration_command_is_sent_only_from_17_18_2(
    release: str, *, sent: bool
) -> None:
    device = Device(replies_at_17_18_2())

    collect(device, at_release(release))

    assert (c.SHOW_SYSTEM_INSECURE_CONFIGURATION in device.asked) is sent


def test_an_unknown_release_is_never_sent_the_insecure_configuration_command() -> None:
    device = Device(replies_at_17_18_2())
    facts = VersionFacts(
        hostname="sw-a",
        model="C9300-48P",
        software_version=Unknown("software version not found in show version"),
        serials=("TEST0000A01",),
    )

    collection = collect_facts(device, facts)

    assert c.SHOW_SYSTEM_INSECURE_CONFIGURATION not in device.asked
    assert collection.collected.insecure_configuration is None


def test_the_gate_is_false_for_a_release_it_cannot_read() -> None:
    unknown = VersionFacts("sw-a", "C9300-48P", Unknown("not found"), ())

    assert not ios_xe_identify.supports_insecure_configuration(unknown)


# -- Inventory --------------------------------------------------------------------------------


def test_inventory_keeps_chassis_stack_supervisor_and_line_card_pids_only() -> None:
    collected = collect(Device()).collected

    assert value(collected.inventory) == (
        InventoryItem("Chassis", InventoryKind.CHASSIS, "C9300-48P", "TEST0000A01"),
        InventoryItem("Switch 1", InventoryKind.STACK_MEMBER, "C9300-48P", "TEST0000A01"),
        InventoryItem("Switch 2", InventoryKind.STACK_MEMBER, "C9300-48P", "TEST0000A02"),
        InventoryItem(
            "Slot 1 - Supervisor Module", InventoryKind.SUPERVISOR, "C9400-SUP-1XL", "TEST0000A03"
        ),
        InventoryItem(
            "Slot 2 - Line Card 1", InventoryKind.LINE_CARD, "C9400-LC-48U", "TEST0000A04"
        ),
    )


def test_inventory_never_keeps_a_power_supply_fan_or_optic() -> None:
    collected = collect(Device()).collected

    pids = {item.pid for item in value(collected.inventory)}

    assert not pids & {"PWR-C1-715WAC", "C9300-FAN", "SFP-10G-SR"}


def test_inventory_without_a_chassis_is_not_read_as_none() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies[c.SHOW_INVENTORY] = (
        'NAME: "Switch 1 - Power Supply A", DESCR: "Power supply"\n'
        "PID: PWR-C1-715WAC, VID: V01, SN: TEST0000A05\n"
    )

    collection = collect(Device(replies))

    assert collection.collected.inventory == Unknown(f"{c.SHOW_INVENTORY}: not understood")


# -- SNMPv3 users, NTP and CoPP ---------------------------------------------------------------


def test_snmp_users_carry_their_authentication_and_privacy_protocols() -> None:
    collected = collect(Device()).collected

    assert value(collected.snmp_users) == (
        SnmpUser("netops-ro", "SHA-256", "AES256", "NA-RO"),
        SnmpUser("legacy-user", "MD5", "DES", "NA-RO"),
    )


def test_ntp_associations_mark_the_synchronised_peer() -> None:
    collected = collect(Device()).collected

    assert value(collected.ntp_associations) == (
        NtpAssociation(peer=IPv4Address("192.0.2.1"), stratum=1, synchronised=True),
        NtpAssociation(peer=IPv4Address("198.51.100.1"), stratum=2, synchronised=False),
    )


def test_no_ntp_peer_is_no_associations() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies[c.SHOW_NTP_ASSOCIATIONS] = ""

    assert value(collect(Device(replies)).collected.ntp_associations) == ()


def test_control_plane_names_the_applied_service_policy() -> None:
    collected = collect(Device()).collected

    assert value(collected.control_plane) == ControlPlanePolicy(("NA-COPP",))


def test_a_control_plane_without_a_service_policy_has_none() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies[c.SHOW_POLICY_MAP_CONTROL_PLANE] = "Control Plane \n"

    assert value(collect(Device(replies)).collected.control_plane) == ControlPlanePolicy(())


# -- SSH --------------------------------------------------------------------------------------


def test_show_ip_ssh_gives_the_enabled_version_and_rsa_modulus() -> None:
    collected = collect(Device()).collected

    assert value(collected.ssh) == SshSettings(enabled=True, version="2.0", key_bits=2048)


def test_a_release_that_does_not_print_the_modulus_leaves_the_key_size_unknown() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies[c.SHOW_IP_SSH] = ios_xe_text.SHOW_IP_SSH_WITHOUT_MODULUS

    ssh = value(collect(Device(replies)).collected.ssh)

    assert ssh.enabled is True
    assert ssh.version == "1.99"
    assert ssh.key_bits == Unknown("RSA modulus not printed by show ip ssh")


# -- Cisco's insecure-configuration list ------------------------------------------------------


def test_the_insecure_configuration_entries_keep_only_ciscos_own_fields() -> None:
    collection = collect(Device(replies_at_17_18_2()), at_release("17.18.2"))

    assert value(collection.collected.insecure_configuration) == (
        InsecureConfigurationItem(
            module="FTP",
            command="ip ftp source-interface GigabitEthernet0/0",
            reason="No encryption is configured",
            severity="HIGH",
        ),
        InsecureConfigurationItem(
            module="SNMP",
            command="snmp-server community <STRING> RO",
            reason="Legacy protocol poses data confidentiality risks",
            severity="HIGH",
        ),
    )


def test_the_insecure_configuration_reply_never_keeps_the_value_it_echoes() -> None:
    collection = collect(Device(replies_at_17_18_2()), at_release("17.18.2"))

    assert "CANARY-c97" not in repr(collection)


def test_no_insecure_configurations_is_no_items() -> None:
    replies = replies_at_17_18_2()
    replies[c.SHOW_SYSTEM_INSECURE_CONFIGURATION] = (
        ios_xe_text.SHOW_SYSTEM_INSECURE_CONFIGURATION_EMPTY
    )

    collection = collect(Device(replies), at_release("17.18.2"))

    assert value(collection.collected.insecure_configuration) == ()


def test_a_reply_that_is_not_the_insecure_configuration_report_is_not_understood() -> None:
    replies = replies_at_17_18_2()
    replies[c.SHOW_SYSTEM_INSECURE_CONFIGURATION] = "CANARY-out-97e1 not the report\n"

    collection = collect(Device(replies), at_release("17.18.2"))

    assert collection.collected.insecure_configuration == Unknown(
        f"{c.SHOW_SYSTEM_INSECURE_CONFIGURATION}: not understood"
    )
    assert "CANARY-out-97e1" not in repr(collection)


def test_an_incomplete_insecure_configuration_scan_is_not_read_as_a_short_list() -> None:
    replies = replies_at_17_18_2()
    replies[c.SHOW_SYSTEM_INSECURE_CONFIGURATION] = (
        ios_xe_text.SHOW_SYSTEM_INSECURE_CONFIGURATION.replace(
            "Total Active Insecure Commands: 2", "Total Active Insecure Commands: 3"
        )
    )

    collection = collect(Device(replies), at_release("17.18.2"))

    assert collection.collected.insecure_configuration == Unknown(
        f"{c.SHOW_SYSTEM_INSECURE_CONFIGURATION}: not understood"
    )


# -- A Device Role that predates the new commands (story 80) ----------------------------------


def test_a_full_collection_has_an_up_to_date_role() -> None:
    assert outdated.role_out_of_date(collect(Device()).collected) is None


def test_two_denied_new_commands_raise_one_medium_role_finding_naming_their_checks() -> None:
    replies = dict(ios_xe_text.REPLIES)
    del replies[c.SHOW_SNMP_USER]
    del replies[c.SHOW_POLICY_MAP_CONTROL_PLANE]

    collected = collect(Device(replies)).collected
    found = outdated.role_out_of_date(collected)

    assert found is not None
    assert outdated.DEVICE_ROLE_LEVEL == "Medium"
    assert found.commands == (c.SHOW_SNMP_USER, c.SHOW_POLICY_MAP_CONTROL_PLANE)
    assert found.checks == ("config-snmpv3-user-crypto", "config-copp-applied")
    assert found.count == 2


def test_one_denied_new_command_names_one_check_in_the_singular() -> None:
    replies = dict(ios_xe_text.REPLIES)
    del replies[c.SHOW_IP_SSH]

    found = outdated.role_out_of_date(collect(Device(replies)).collected)

    assert found is not None
    assert found.checks == ("config-ssh-key-size",)
    assert found.count == 1


def test_the_refused_commands_result_is_unknown_never_a_pass() -> None:
    replies = dict(ios_xe_text.REPLIES)
    del replies[c.SHOW_NTP_ASSOCIATIONS]

    collected = collect(Device(replies)).collected

    assert collected.ntp_associations == Unknown(f"{c.SHOW_NTP_ASSOCIATIONS}: denied")


def test_every_new_command_that_is_denied_is_named() -> None:
    replies = replies_at_17_18_2()
    for command in NEW_COMMANDS:
        del replies[command]

    found = outdated.role_out_of_date(collect(Device(replies), at_release("17.18.2")).collected)

    assert found is not None
    assert found.checks == (
        "lifecycle-hardware-eox",
        "config-snmpv3-user-crypto",
        "config-ntp-synchronised",
        "config-copp-applied",
        "config-ssh-key-size",
        "config-cisco-insecure-list",
    )


def test_a_command_we_could_not_understand_is_not_an_out_of_date_role() -> None:
    replies = dict(ios_xe_text.REPLIES)
    replies[c.SHOW_SNMP_USER] = "CANARY-out-97e1 not an snmp user table\n"

    collection = collect(Device(replies))

    assert collection.collected.snmp_users == Unknown(f"{c.SHOW_SNMP_USER}: not understood")
    assert outdated.role_out_of_date(collection.collected) is None


def test_a_denied_command_with_no_dependent_check_is_not_an_out_of_date_role() -> None:
    replies = dict(ios_xe_text.REPLIES)
    del replies["show vlan brief"]

    assert outdated.role_out_of_date(collect(Device(replies)).collected) is None
