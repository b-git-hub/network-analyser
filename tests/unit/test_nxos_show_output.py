"""NX-OS: the new read-only commands of ticket #98, through `platforms.collect`.

Each test drives the collector with a scripted `send` answering from hand-written synthetic
replies (tests/support/nxos_show): no device, no SSH, no network. What is asserted is what the
operator's later Analysis gets: the parsed values in the collected record, the Audit-log
problems, and one Device Role out-of-date record when the role refuses a new command.
"""

import json
from collections.abc import Mapping
from ipaddress import IPv4Address

import pytest

from network_analyser import platforms
from network_analyser.platforms import Collection
from network_analyser.platforms.collection import DeviceRoleOutOfDate
from network_analyser.platforms.nxos import outdated
from network_analyser.records import Platform
from network_analyser.records.collected import (
    Collected,
    ControlPlanePolicy,
    InventoryItem,
    InventoryKind,
    Reading,
)
from network_analyser.records.device import Unknown, VersionFacts
from tests.support import nxos_json, nxos_show
from tests.support.nxos_json import NXOS_JSON_REPLIES

VERSION = VersionFacts("nx-a", "N9K-C9300v", "9.3(8)", ("TEST0000N01",))
INVENTORY = "show inventory | json"
NTP = "show ntp peer-status | json"
COPP = "show copp status | json"
SSH = "show ssh key"
GUESTSHELL = "show guestshell"
VIRTUAL_SERVICE_LIST = "show virtual-service list"

CANARY = "CANARY-out-98a4"


class Device:
    """Answers each command from the replies; anything else gets NX-OS's invalid text."""

    def __init__(self, replies: Mapping[str, str | Unknown] | None = None) -> None:
        self.replies = {**NXOS_JSON_REPLIES, **nxos_show.NEW_COMMANDS, **(replies or {})}
        self.sent: list[str] = []

    def send(self, command: str) -> str | Unknown:
        assert platforms.permits(Platform.NX_OS, command), command
        self.sent.append(command)
        return self.replies.get(command, nxos_json.INVALID)

    def collect(self) -> Collection:
        found = platforms.collect(Platform.NX_OS, self.send, VERSION)
        assert found is not None
        return found


def _collected(replies: Mapping[str, str | Unknown] | None = None) -> Collected:
    return Device(replies).collect().collected


def _value[T](part: Reading[T] | Unknown | None) -> T:
    assert isinstance(part, Reading), part
    return part.value


def _out_of_date(replies: Mapping[str, str | Unknown] | None = None) -> DeviceRoleOutOfDate | None:
    return outdated.role_out_of_date(_collected(replies))


# -- What is sent ------------------------------------------------------------------------------


def test_every_new_command_is_sent_once_after_the_topology_collection() -> None:
    device = Device()

    collection = device.collect()

    assert device.sent[-5:] == [INVENTORY, NTP, COPP, SSH, GUESTSHELL]
    for command in (INVENTORY, NTP, COPP, SSH, GUESTSHELL):
        assert device.sent.count(command) == 1
    assert isinstance(collection.collected.inventory, Reading)


def test_the_guest_shell_fallback_is_not_sent_when_the_first_command_answers() -> None:
    device = Device()

    device.collect()

    assert GUESTSHELL in device.sent
    assert VIRTUAL_SERVICE_LIST not in device.sent


def test_the_allow_list_never_asks_for_snmpv3_users() -> None:
    commands = platforms.ALLOW_LISTS[Platform.NX_OS].exact_commands

    assert not [command for command in commands if "snmp" in command.casefold()], (
        "SNMPv3 users come from the running config, not a new command (story 78)"
    )


# -- Inventory ---------------------------------------------------------------------------------


def test_inventory_keeps_chassis_supervisor_and_line_card_but_never_optics_psus_or_fans() -> None:
    items = _value(_collected().inventory)

    assert [item.kind for item in items] == [
        InventoryKind.CHASSIS,
        InventoryKind.SUPERVISOR,
        InventoryKind.LINE_CARD,
    ]
    assert [item.pid for item in items] == ["N9K-C9300v", "N9K-SUP-A", "N9K-X9636C-RX"]
    assert [item.name for item in items] == ["Chassis", "Slot 1", "Slot 2"]
    assert items[0] == InventoryItem("Chassis", InventoryKind.CHASSIS, "N9K-C9300v", "TEST0000N01")


def test_a_stack_member_pid_is_kept_too() -> None:
    reply = json.loads(nxos_show.INVENTORY)
    line_card = reply["TABLE_inv"]["ROW_inv"][2]
    line_card["name"] = "Stack member 2"
    line_card["desc"] = "Nexus 9000v Switch"

    items = _value(_collected({INVENTORY: json.dumps(reply)}).inventory)

    assert [item.kind for item in items] == [
        InventoryKind.CHASSIS,
        InventoryKind.SUPERVISOR,
        InventoryKind.STACK_MEMBER,
    ]


def test_inventory_reads_the_plain_text_form_when_the_reply_is_not_json() -> None:
    items = _value(_collected({INVENTORY: nxos_show.INVENTORY_TEXT}).inventory)

    assert [(item.kind, item.pid) for item in items] == [
        (InventoryKind.CHASSIS, "N9K-C9300v"),
        (InventoryKind.SUPERVISOR, "N9K-SUP-A"),
    ]


def test_inventory_tolerates_extra_and_missing_optional_keys() -> None:
    reply = json.loads(nxos_show.INVENTORY)
    rows = reply["TABLE_inv"]["ROW_inv"]
    rows[0]["vendorid"] = "V02"
    rows[0]["an-extra-key"] = "ignored"
    del rows[0]["desc"]
    del rows[0]["serialnum"]
    reply["an-extra-table"] = {"ROW_an-extra-table": []}

    items = _value(_collected({INVENTORY: json.dumps(reply)}).inventory)

    assert items[0] == InventoryItem(
        "Chassis",
        InventoryKind.CHASSIS,
        "N9K-C9300v",
        Unknown("serial not reported by show inventory"),
    )


def test_a_malformed_pid_is_unknown_never_sent() -> None:
    reply = json.loads(nxos_show.INVENTORY)
    reply["TABLE_inv"]["ROW_inv"][0]["productid"] = "not a pid"

    items = _value(_collected({INVENTORY: json.dumps(reply)}).inventory)

    assert items[0].pid == Unknown("PID not reported by show inventory")


@pytest.mark.parametrize(
    "reply",
    [
        '{"TABLE_inv": {"ROW_inv": {"productid": "N9K-C9300v"}}}',
        "not a reply",
    ],
    ids=["no name", "not text or JSON"],
)
def test_inventory_it_cannot_read_is_unknown_never_guessed(reply: str) -> None:
    assert _collected({INVENTORY: reply}).inventory == Unknown(f"{INVENTORY}: not understood")


# -- NTP synchronisation -----------------------------------------------------------------------


def test_a_selected_peer_means_ntp_is_synchronised() -> None:
    associations = _value(_collected().ntp_associations)

    assert [(a.peer, a.stratum, a.synchronised) for a in associations] == [
        (IPv4Address("192.0.2.1"), 16, True),
        (IPv4Address("192.0.2.2"), 16, False),
    ]
    assert _collected().ntp_associations == Reading((NTP,), associations)


def test_ntp_is_read_from_the_plain_text_form_too() -> None:
    associations = _value(_collected({NTP: nxos_show.NTP_PEER_STATUS_TEXT}).ntp_associations)

    assert [(a.peer, a.stratum, a.synchronised) for a in associations] == [
        (IPv4Address("192.0.2.1"), 16, True),
        (IPv4Address("192.0.2.2"), 16, False),
    ]


def test_the_sync_marker_may_sit_on_another_key() -> None:
    reply = json.loads(nxos_show.NTP_PEER_STATUS_UNSYNCHRONISED)
    reply["TABLE_peer_status"]["ROW_peer_status"][0]["st"] = "*16"

    associations = _value(_collected({NTP: json.dumps(reply)}).ntp_associations)

    assert [a.synchronised for a in associations] == [True]


def test_peers_with_nothing_selected_mean_ntp_is_not_synchronised() -> None:
    associations = _value(
        _collected({NTP: nxos_show.NTP_PEER_STATUS_UNSYNCHRONISED}).ntp_associations
    )

    assert [a.synchronised for a in associations] == [False]


def test_an_empty_ntp_reply_means_no_peers() -> None:
    assert _value(_collected({NTP: ""}).ntp_associations) == ()


def test_ntp_rows_with_no_recognisable_marker_are_unknown() -> None:
    reply = '{"TABLE_peer_status": {"ROW_peer_status": {"vrf": "default"}}}'

    assert _collected({NTP: reply}).ntp_associations == Unknown(f"{NTP}: not understood")


# -- CoPP --------------------------------------------------------------------------------------


def test_an_applied_policy_is_named() -> None:
    assert _value(_collected().control_plane) == ControlPlanePolicy(("copp-system-p-policy",))


def test_copp_is_read_from_the_plain_text_form_too() -> None:
    policy = _value(_collected({COPP: nxos_show.COPP_STATUS_TEXT}).control_plane)

    assert policy.service_policies == ("copp-system-p-policy",)


def test_a_policy_that_is_not_applied_leaves_the_list_empty() -> None:
    policy = _value(_collected({COPP: nxos_show.COPP_STATUS_NOT_APPLIED}).control_plane)

    assert policy.service_policies == ()


def test_a_copp_reply_it_cannot_read_is_unknown_never_a_pass() -> None:
    for reply in ('{"something-else": "yes"}', '{"copp-status": "no idea"}'):
        assert _collected({COPP: reply}).control_plane == Unknown(f"{COPP}: not understood")


# -- SSH key size ------------------------------------------------------------------------------


def test_the_key_size_is_read_from_the_public_key_without_keeping_the_key() -> None:
    settings = _value(_collected().ssh)

    assert settings.key_bits == 2048
    assert settings.enabled == Unknown("not reported by show ssh key")
    assert nxos_show.ssh_rsa_key(2048) not in repr(settings)


def test_a_key_under_2048_bits_is_reported_as_its_real_size() -> None:
    assert _value(_collected({SSH: nxos_show.SSH_KEY_WEAK}).ssh).key_bits == 1024


def test_a_printed_bit_count_is_read_too() -> None:
    reply = "rsa Keys generated:Thu Jan  1 00:00:00 2026\nbitcount: 4096\n"

    assert _value(_collected({SSH: reply}).ssh).key_bits == 4096


def test_a_key_that_is_not_rsa_cannot_decide_the_size() -> None:
    reply = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEYMATERIALONLY\n"

    assert _collected({SSH: reply}).ssh == Unknown(f"{SSH}: not understood")


# -- Guest Shell -------------------------------------------------------------------------------


def test_guest_shell_absent_is_false() -> None:
    found = _collected().guest_shell

    assert isinstance(found, Reading)
    assert (found.commands, found.value) == ((GUESTSHELL,), False)


def test_guest_shell_present_is_true() -> None:
    assert _value(_collected({GUESTSHELL: nxos_show.GUESTSHELL_PRESENT}).guest_shell) is True


def test_a_refused_first_command_falls_back_to_the_virtual_service_list() -> None:
    collected = _collected(
        {
            GUESTSHELL: nxos_json.DENIED,
            VIRTUAL_SERVICE_LIST: nxos_show.VIRTUAL_SERVICE_LIST_PRESENT,
        }
    )

    found = collected.guest_shell
    assert isinstance(found, Reading)
    assert (found.commands, found.value) == ((VIRTUAL_SERVICE_LIST,), True)


def test_the_virtual_service_list_without_guest_shell_is_false() -> None:
    collected = _collected(
        {
            GUESTSHELL: nxos_json.INVALID,
            VIRTUAL_SERVICE_LIST: nxos_show.VIRTUAL_SERVICE_LIST_EMPTY,
        }
    )

    assert _value(collected.guest_shell) is False


def test_both_guest_shell_commands_refused_leaves_it_unknown() -> None:
    collected = _collected({GUESTSHELL: nxos_json.DENIED, VIRTUAL_SERVICE_LIST: nxos_json.DENIED})

    assert collected.guest_shell == Unknown(f"{GUESTSHELL}: denied")


# -- A refused command is never fatal ----------------------------------------------------------


def test_every_new_command_denied_leaves_only_its_own_part_unknown() -> None:
    replies = dict.fromkeys((INVENTORY, NTP, COPP, SSH, GUESTSHELL), nxos_json.DENIED)

    collection = Device(replies).collect()

    assert isinstance(collection.collected.interfaces, Reading)
    assert collection.collected.interfaces.value  # the Topology's data is untouched
    assert collection.collected.inventory == Unknown(f"{INVENTORY}: denied")
    assert {problem.command for problem in collection.problems} == {
        INVENTORY,
        NTP,
        COPP,
        SSH,
        GUESTSHELL,
        VIRTUAL_SERVICE_LIST,
    }


# -- Device Role out of date -------------------------------------------------------------------


def test_a_role_that_refuses_the_new_commands_raises_one_out_of_date_record() -> None:
    replies = dict.fromkeys(
        (INVENTORY, NTP, COPP, SSH, GUESTSHELL, VIRTUAL_SERVICE_LIST), nxos_json.DENIED
    )

    out_of_date = _out_of_date(replies)

    assert out_of_date == DeviceRoleOutOfDate(
        (INVENTORY, NTP, COPP, SSH, GUESTSHELL),
        (
            "Hardware EoX",
            "NTP not synchronised",
            "CoPP not applied",
            "SSH key under 2048 bits",
            "Guest Shell present",
        ),
    )
    assert out_of_date is not None
    assert out_of_date.count == 5
    assert out_of_date.summary == (
        "Device Role is out of date: 5 Checks could not run (Hardware EoX, NTP not"
        " synchronised, CoPP not applied, SSH key under 2048 bits, Guest Shell present)."
        " Re-apply the Device Role printed by role-snippet."
    )


def test_one_out_of_date_record_names_a_check_once_when_both_commands_are_refused() -> None:
    out_of_date = _out_of_date(
        {GUESTSHELL: nxos_json.DENIED, VIRTUAL_SERVICE_LIST: nxos_json.DENIED}
    )

    assert out_of_date == DeviceRoleOutOfDate((GUESTSHELL,), ("Guest Shell present",))
    assert out_of_date is not None
    assert out_of_date.summary.startswith(
        "Device Role is out of date: 1 Check could not run (Guest Shell present)."
    )


def test_a_command_the_device_does_not_have_is_not_a_device_role_problem() -> None:
    out_of_date = _out_of_date({INVENTORY: nxos_json.INVALID, SSH: ""})

    assert out_of_date is None


def test_a_refused_first_command_is_not_out_of_date_when_the_fallback_answers() -> None:
    collected = _collected(
        {
            GUESTSHELL: nxos_json.DENIED,
            VIRTUAL_SERVICE_LIST: nxos_show.VIRTUAL_SERVICE_LIST_PRESENT,
        }
    )

    assert _value(collected.guest_shell) is True
    assert outdated.role_out_of_date(collected) is None


def test_a_healthy_role_raises_no_out_of_date_record() -> None:
    assert _out_of_date() is None


# -- Nothing of the new output is kept or echoed -----------------------------------------------


def test_a_reply_that_cannot_be_read_never_echoes_its_text() -> None:
    reply = f'{{"TABLE_peer_status": {{"ROW_peer_status": {{"peer": "{CANARY}"}}}}}}'

    collection = Device({NTP: reply}).collect()

    assert collection.collected.ntp_associations == Unknown(f"{NTP}: not understood")
    assert CANARY not in repr(collection.problems)
    assert CANARY not in repr(collection.collected.ntp_associations)


def test_an_inventory_name_is_made_printable_and_capped() -> None:
    reply = json.loads(nxos_show.INVENTORY)
    reply["TABLE_inv"]["ROW_inv"][0]["name"] = "Chassis\u001b[2J" + "x" * 300

    item = _value(_collected({INVENTORY: json.dumps(reply)}).inventory)[0]

    assert item.name.startswith("Chassis?[2J")
    assert len(item.name) == 255
