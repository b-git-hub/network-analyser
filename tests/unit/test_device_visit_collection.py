"""A visit collects the Topology's data after the Backup (tickets #59 and #60).

Driven through `device_gateway.visit` with fake devices at the gateway seam
(tests/support/fake_device) answering hand-written NX-OS `| json` replies
(tests/support/nxos_json) or IOS/IOS-XE text (tests/support/ios_xe_text): no SSH server,
no network.
"""

from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import device_gateway, scope, trust_store
from network_analyser.credentials import CredentialSet, CredentialSets, Secret
from network_analyser.device_gateway.gate import DROP_REASONS, CommandTimedOutError
from network_analyser.platforms.ios_xe import commands as ios_xe_commands
from network_analyser.records import Platform, ScopeRecord
from network_analyser.records.backup import BackupCapture
from network_analyser.records.collected import Reading
from network_analyser.records.device import DeviceRecord, Unknown
from network_analyser.records.events import (
    AuditEvent,
    CommandSent,
    DeviceOutcome,
    ParseFailed,
)
from tests.support import device_text, ios_xe_text, nxos_json
from tests.support.fake_device import (
    DEVICE_CANARY,
    IOS_XE_REPLIES,
    NXOS_REPLIES,
    FakeDevice,
    FakeNetwork,
)
from tests.support.nxos_json import NXOS_JSON_REPLIES

SEED = IPv4Address("192.0.2.10")
PARSER = "Network Analyser NX-OS JSON reader"
IOS_PARSER = "Network Analyser IOS/IOS-XE reader (ntc-templates cisco_ios)"
IOS_BACKUP = "show running-config view full"


class Visit:
    def __init__(self, tmp_path: Path) -> None:
        self.network = FakeNetwork()
        self.events: list[AuditEvent] = []
        self.known_hosts = tmp_path / "trust" / "known_hosts"
        self.backups: list[str] = []

    def backup_sink(self, _capture: BackupCapture, config: str) -> None:
        self.backups.append(config)

    def __call__(self) -> DeviceRecord:
        fence = scope.parse(["192.0.2.0/24"], [])
        assert isinstance(fence, ScopeRecord)
        record = device_gateway.visit(
            SEED,
            scope=fence,
            trust=trust_store.load(self.known_hosts, strict=False),
            sets=CredentialSets([CredentialSet("netops-ro", Secret(DEVICE_CANARY), None)]),
            emit=self.events.append,
            failure_budget=3,
            backup_sink=self.backup_sink,
            dial=self.network.dial,
            wait_before_retry=self.network.wait_before_retry,
        )
        assert isinstance(record, DeviceRecord)  # no identity register: never an alias
        return record

    def nexus(self, **changes: str) -> FakeDevice:
        replies = {**NXOS_REPLIES, **NXOS_JSON_REPLIES, **changes}
        return self.network.add(
            str(SEED),
            FakeDevice(ssh_id="SSH-2.0-OpenSSH_8.8 FIPS", prompt="nx-a#", replies=replies),
        )

    def catalyst(
        self, changes: dict[str, str] | None = None, *, hangs_on: frozenset[str] = frozenset()
    ) -> FakeDevice:
        replies = {
            **IOS_XE_REPLIES,
            **ios_xe_text.NEIGHBOUR_REPLIES,
            **ios_xe_text.REPLIES,
            **(changes or {}),
        }
        return self.network.add(str(SEED), FakeDevice(replies=replies, hangs_on=hangs_on))


@pytest.fixture
def visit(tmp_path: Path) -> Visit:
    return Visit(tmp_path)


def test_a_nexus_is_backed_up_then_its_data_collected(visit: Visit) -> None:
    device = visit.nexus()

    record = visit()

    assert record.outcome is DeviceOutcome.VISITED
    assert record.collected is not None
    assert isinstance(record.collected.interfaces, Reading)
    assert isinstance(record.collected.vpc, Reading)
    backup_at = device.lines.index("show running-config")
    assert device.lines[backup_at + 1] == "show feature | json"
    assert sorted(device.lines[backup_at + 1 :]) == sorted(
        c for c in NXOS_JSON_REPLIES if "neighbors detail" not in c
    )
    assert isinstance(record.collected.cdp, Reading)  # read by the crawl, before the Backup
    assert len(record.collected.cdp.value) == 2
    assert visit.backups == [f"{device_text.NXOS_RUNNING_CONFIG}"]
    sent = [e.command for e in visit.events if isinstance(e, CommandSent)]
    assert sent == device.lines
    assert not [e for e in visit.events if isinstance(e, ParseFailed)]


def test_a_denied_command_is_audited_and_never_fatal(visit: Visit) -> None:
    visit.nexus(**{"show vlan brief | json": nxos_json.DENIED})

    record = visit()

    assert record.outcome is DeviceOutcome.VISITED
    assert record.collected is not None
    assert record.collected.vlans == Unknown("show vlan brief | json: denied")
    assert ParseFailed(SEED, "show vlan brief | json", PARSER, "denied") in visit.events
    assert all("Permission" not in repr(e) for e in visit.events)


def test_a_dropped_session_keeps_the_backup_and_what_was_collected(visit: Visit) -> None:
    device = visit.nexus()
    device.hangs_on = frozenset({"show vlan brief | json"})

    record = visit()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.partial_reason == DROP_REASONS[CommandTimedOutError]
    assert visit.backups == [device_text.NXOS_RUNNING_CONFIG]
    assert record.collected is not None
    assert isinstance(record.collected.interfaces, Reading)
    assert record.collected.vlans == Unknown(
        "show vlan brief | json: not read, the session was dropped"
    )
    assert record.collected.vrfs == Unknown("show vrf | json: not read, the session was dropped")
    assert device.lines[-1] == "show vlan brief | json"


# -- IOS/IOS-XE (#59) ------------------------------------------------------------------------


def test_a_catalyst_is_backed_up_then_its_data_collected(visit: Visit) -> None:
    device = visit.catalyst()

    record = visit()

    assert record.outcome is DeviceOutcome.VISITED
    assert record.platform is Platform.IOS_XE
    assert record.collected is not None
    assert isinstance(record.collected.interfaces, Reading)
    assert isinstance(record.collected.stack_members, Reading)
    assert record.collected.vpc is None
    backup_at = device.lines.index(IOS_BACKUP)
    assert device.lines[backup_at + 1] == "show version"  # again, for the stack members
    assert sorted(device.lines[backup_at + 2 :]) == sorted(ios_xe_text.REPLIES)
    assert visit.backups == [device_text.IOS_XE_RUNNING_CONFIG]
    assert not [e for e in visit.events if isinstance(e, ParseFailed)]


def test_the_crawls_neighbour_tables_are_read_once_before_the_backup(visit: Visit) -> None:
    device = visit.catalyst()

    record = visit()

    backup_at = device.lines.index(IOS_BACKUP)
    for command in ios_xe_text.NEIGHBOUR_REPLIES:
        assert device.lines.count(command) == 1
        assert device.lines.index(command) < backup_at
    assert record.collected is not None
    assert isinstance(record.collected.cdp, Reading)
    assert len(record.collected.cdp.value) == 2
    assert isinstance(record.collected.lldp, Reading)


def test_a_denied_ios_command_is_audited_and_never_fatal(visit: Visit) -> None:
    visit.catalyst({"show vlan brief": device_text.IOS_XE_INVALID_INPUT})

    record = visit()

    assert record.outcome is DeviceOutcome.VISITED
    assert record.collected is not None
    assert record.collected.vlans == Unknown("show vlan brief: denied")
    assert isinstance(record.collected.mac, Reading)
    failed = [e for e in visit.events if isinstance(e, ParseFailed)]
    assert failed == [ParseFailed(SEED, "show vlan brief", IOS_PARSER, "denied")]
    assert all("Invalid input" not in repr(e) for e in visit.events)


def test_a_new_command_a_0_1_role_refuses_keeps_the_backup_and_the_run(visit: Visit) -> None:
    command = ios_xe_commands.SHOW_INVENTORY
    visit.catalyst({command: device_text.IOS_XE_INVALID_INPUT})

    record = visit()

    assert record.outcome is DeviceOutcome.VISITED
    assert record.collected is not None
    assert record.collected.inventory == Unknown(f"{command}: denied")
    assert visit.backups == [device_text.IOS_XE_RUNNING_CONFIG]
    assert ParseFailed(SEED, command, IOS_PARSER, "denied") in visit.events


def test_an_ios_reply_that_cannot_be_parsed_is_audited_without_its_text(visit: Visit) -> None:
    visit.catalyst({"show vlan brief": "CANARY-out-3f1a not a vlan table\n"})

    visit()

    failed = [e for e in visit.events if isinstance(e, ParseFailed)]
    assert failed == [ParseFailed(SEED, "show vlan brief", IOS_PARSER, "not understood")]
    assert "CANARY-out-3f1a" not in repr(visit.events)


def test_a_drop_during_ios_collection_keeps_the_backup_and_what_was_read(visit: Visit) -> None:
    device = visit.catalyst(hangs_on=frozenset({"show vlan brief"}))

    record = visit()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.partial_reason == DROP_REASONS[CommandTimedOutError]
    assert visit.backups == [device_text.IOS_XE_RUNNING_CONFIG]
    assert record.collected is not None
    assert isinstance(record.collected.cdp, Reading)
    assert isinstance(record.collected.interfaces, Reading)
    assert record.collected.vlans == Unknown("show vlan brief: not read, the session was dropped")
    assert record.collected.mac == Unknown(
        "show mac address-table: not read, the session was dropped"
    )
    assert device.lines[-1] == "show vlan brief", "nothing is sent after the drop"
    assert device.open_links == 0


def test_a_catalyst_with_no_full_config_is_still_collected(visit: Visit) -> None:
    visit.catalyst({IOS_BACKUP: "% Permission denied\n"})

    record = visit()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert visit.backups == []
    assert record.collected is not None
    assert isinstance(record.collected.interfaces, Reading)
