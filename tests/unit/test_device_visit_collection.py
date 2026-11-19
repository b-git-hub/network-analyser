"""Collecting a Visited Device's data inside the visit (#59; spec #37, story 126).

Driven through `device_gateway.visit` with fake devices (tests/support/fake_device) answering
with synthetic IOS/IOS-XE text (tests/support/ios_xe_text). Checks what the device record
carries, what reached the device and what the Audit log says.
"""

from pathlib import Path

import pytest

from network_analyser import device_gateway
from network_analyser.records.collected import NOT_COLLECTED, Collected, Reading
from network_analyser.records.events import (
    CommandResult,
    CommandSent,
    DeviceOutcome,
    ParseFailed,
)
from network_analyser.records.unknown import Unknown
from tests.support import device_text, ios_xe_text
from tests.support.fake_device import NXOS_REPLIES, FakeDevice
from tests.unit.test_device_visit import SEED, Visit

BACKUP = "show running-config view full"


@pytest.fixture
def visit(tmp_path: Path) -> Visit:
    return Visit(tmp_path)


def sw_a(**kwargs: object) -> FakeDevice:
    device = FakeDevice(**kwargs)  # type: ignore[arg-type]  # FakeDevice's own fields
    device.replies.update(ios_xe_text.REPLIES)
    return device


def sent(visit: Visit) -> list[CommandSent]:
    return [e for e in visit.events if isinstance(e, CommandSent)]


def test_a_visited_device_carries_its_collected_data(visit: Visit) -> None:
    device = visit.network.add(str(SEED), sw_a())

    record = visit()

    assert record.outcome is DeviceOutcome.VISITED
    assert record.collected is not None
    assert isinstance(record.collected.interfaces, Reading)
    assert isinstance(record.collected.cdp, Reading)
    assert device.lines[:5] == [
        "terminal length 0",
        "terminal width 511",
        "show version",
        "show privilege",
        BACKUP,
    ]
    assert set(device.lines[5:]) == set(ios_xe_text.REPLIES)
    assert visit.backups == [device_text.IOS_XE_RUNNING_CONFIG]


def test_a_denied_command_is_audited_as_denied_and_never_fatal(visit: Visit) -> None:
    device = sw_a()
    del device.replies["show vlan brief"]
    visit.network.add(str(SEED), device)

    record = visit()

    assert record.outcome is DeviceOutcome.VISITED
    assert record.collected is not None
    assert record.collected.vlans == Unknown(
        "show vlan brief: denied or not supported by the device"
    )
    denied = [e for e in sent(visit) if e.result is CommandResult.DENIED]
    assert [e.command for e in denied] == ["show vlan brief"]
    assert all(e.result is CommandResult.OK for e in sent(visit) if e not in denied)


def test_a_reply_that_cannot_be_parsed_is_audited_without_its_text(visit: Visit) -> None:
    device = sw_a()
    device.replies["show vlan brief"] = "CANARY-out-3f1a not a vlan table\n"
    visit.network.add(str(SEED), device)

    visit()

    failed = [e for e in visit.events if isinstance(e, ParseFailed)]
    assert failed == [
        ParseFailed(SEED, "show vlan brief", "ntc-templates cisco_ios", "not understood")
    ]
    assert "CANARY-out-3f1a" not in repr(visit.events)


def test_a_drop_during_collection_keeps_the_backup_and_what_was_read(visit: Visit) -> None:
    device = visit.network.add(str(SEED), sw_a(hangs_on=frozenset({"show vlan brief"})))

    record = visit()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.partial_reason == "a command timed out, so the session was dropped"
    assert visit.backups == [device_text.IOS_XE_RUNNING_CONFIG]
    assert record.collected is not None
    assert isinstance(record.collected.cdp, Reading)
    assert record.collected.vlans == Unknown(
        "show vlan brief: a command timed out, so the session was dropped"
    )
    assert record.collected.mac == Unknown(
        "show mac address-table: not sent: the session was dropped"
    )
    assert device.lines[-1] == "show vlan brief", "nothing is sent after the drop"
    assert device.open_links == 0


def test_a_device_with_no_full_config_is_still_collected(visit: Visit) -> None:
    device = sw_a()
    device.replies[BACKUP] = "% Permission denied\n"
    visit.network.add(str(SEED), device)

    record = visit()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert visit.backups == []
    assert record.collected is not None
    assert isinstance(record.collected.interfaces, Reading)


def test_nx_os_data_is_not_collected_until_its_own_ticket(visit: Visit) -> None:
    device = visit.network.add(
        str(SEED),
        FakeDevice(ssh_id="SSH-2.0-OpenSSH_8.8 FIPS", prompt="nx-a#", replies=dict(NXOS_REPLIES)),
    )

    record = visit()

    assert record.collected == Collected.nothing(NOT_COLLECTED)
    assert device.lines[-1] == "show running-config"


def test_a_drop_before_collection_leaves_no_collected_data(visit: Visit) -> None:
    visit.network.add(str(SEED), sw_a(hangs_on=frozenset({"show privilege"})))

    record = visit()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.collected is None
    assert device_gateway.CONFIG_MODE != record.partial_reason
