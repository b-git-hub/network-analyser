"""What one visit does for the crawl (ticket #50; stories 50-52, 63-64, 73).

Driven through `device_gateway.visit` with fake devices at the gateway seam: the CDP and LLDP
tables read after identification, the one connection retry, the Platform gate on the SSH
identification string for Neighbours, the per-device timeout, the identity checks (the
host-key alias before any password, the chassis serial before anything else is collected)
and a Trust Store that cannot be written.
"""

from collections.abc import Callable
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import device_gateway, scope, trust_store
from network_analyser.credentials import CredentialSet, CredentialSets, Secret
from network_analyser.records import HostKey, ScopeRecord
from network_analyser.records.collected import Neighbour, Reading
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.events import (
    AliasFound,
    AuditEvent,
    CommandSent,
    ConnectionAttempted,
    ConnectionResult,
    DeviceOutcome,
    ErrorRaised,
    LoginAttempted,
    ParseFailed,
)
from network_analyser.records.identity import Alias, AliasEvidence
from network_analyser.records.run_request import Timeouts
from network_analyser.records.unknown import Unknown
from network_analyser.trust_store import TrustStore
from tests.support import device_text, ios_xe_text
from tests.support.fake_device import (
    DEVICE_CANARY,
    NXOS_REPLIES,
    FakeDevice,
    FakeNetwork,
    synthetic_key,
)

DEVICE = IPv4Address("192.0.2.10")
OTHER = IPv4Address("192.0.2.20")
WRONG = "CANARY-pw-other-5b2e"
"""A password no Credential Set holds: a synthetic canary."""
NEIGHBOUR_LINES = ["show cdp neighbors detail", "show lldp neighbors detail"]


class Register:
    """A stand-in for discovery's register: who already holds each key and serial."""

    def __init__(self) -> None:
        self.keys: dict[str, IPv4Address] = {}
        self.serials: dict[str, IPv4Address] = {}

    def claim_host_key(self, ip: IPv4Address, key: HostKey) -> IPv4Address:
        return self.keys.setdefault(key.fingerprint, ip)

    def claim_serials(self, ip: IPv4Address, serials: tuple[str, ...]) -> IPv4Address:
        held = next((self.serials[s] for s in serials if s in self.serials), ip)
        for serial in serials:
            self.serials.setdefault(serial, held)
        return held


class Visit:
    def __init__(self, tmp_path: Path) -> None:
        self.network = FakeNetwork()
        self.events: list[AuditEvent] = []
        self.known_hosts = tmp_path / "trust" / "known_hosts"
        self.register = Register()
        self.waits = 0
        self.backups = 0
        self.during_wait: Callable[[], None] = lambda: None
        self.timeouts = Timeouts()
        self.store: TrustStore | None = None

    def take_backup(self, _capture: object, _config: str, /) -> None:
        self.backups += 1

    def wait(self) -> None:
        self.waits += 1
        self.during_wait()

    def __call__(self, ip: IPv4Address = DEVICE, *, id_gate: bool = False) -> DeviceRecord | Alias:
        fence = scope.parse(["192.0.2.0/24"], [])
        assert isinstance(fence, ScopeRecord)
        return device_gateway.visit(
            ip,
            scope=fence,
            trust=self.store or trust_store.load(self.known_hosts),
            sets=CredentialSets([CredentialSet("netops-ro", Secret(DEVICE_CANARY), None)]),
            emit=self.events.append,
            failure_budget=3,
            timeouts=self.timeouts,
            backup_sink=self.take_backup,
            dial=self.network.dial,
            id_gate=id_gate,
            identity=self.register,
            wait_before_retry=self.wait,
        )

    def of[E: AuditEvent](self, kind: type[E]) -> list[E]:
        return [e for e in self.events if isinstance(e, kind)]


@pytest.fixture
def visit(tmp_path: Path) -> Visit:
    return Visit(tmp_path)


def _table(record: DeviceRecord, name: str) -> tuple[Neighbour, ...] | Unknown:
    """The CDP or LLDP table the record holds (`Collected.cdp` / `Collected.lldp`)."""
    assert record.collected is not None
    reading = record.collected.cdp if name == "cdp" else record.collected.lldp
    return reading.value if isinstance(reading, Reading) else reading


def _record(result: DeviceRecord | Alias) -> DeviceRecord:
    assert isinstance(result, DeviceRecord), result
    return result


# -- The CDP and LLDP tables ----------------------------------------------------------------


def test_cdp_then_lldp_neighbours_are_read_after_identification(visit: Visit) -> None:
    device = visit.network.add(str(DEVICE))
    device.replies.update(ios_xe_text.REPLIES)
    device.replies["show cdp neighbors detail"] = device_text.IOS_XE_CDP_DETAIL
    device.replies["show lldp neighbors detail"] = device_text.IOS_XE_LLDP_DETAIL

    record = _record(visit())

    assert record.outcome is DeviceOutcome.VISITED
    backup_at = device.lines.index("show running-config view full")
    assert device.lines[backup_at - 2 : backup_at] == NEIGHBOUR_LINES
    cdp = _table(record, "cdp")
    assert isinstance(cdp, tuple)
    assert [n.name for n in cdp] == ["sw-b.example.test", "SEP00AABBCCDDEE"]
    lldp = _table(record, "lldp")
    assert isinstance(lldp, tuple)
    assert [n.chassis_id for n in lldp] == ["5254.0012.3401", "5254.0012.3402"]
    assert record.collected is not None
    assert isinstance(record.collected.cdp, Reading)
    assert record.collected.cdp.commands == ("show cdp neighbors detail",)
    assert isinstance(record.collected.interfaces, Reading)  # collected after the Backup (#59)
    assert visit.of(ParseFailed) == []


def test_an_nxos_device_is_asked_for_the_json_tables(visit: Visit) -> None:
    replies = dict(NXOS_REPLIES)
    replies["show cdp neighbors detail | json"] = device_text.NXOS_CDP_DETAIL_JSON
    device = visit.network.add(
        str(DEVICE), FakeDevice(ssh_id="SSH-2.0-OpenSSH_8.8 FIPS", prompt="nx-a#", replies=replies)
    )

    record = _record(visit())

    backup_at = device.lines.index("show running-config")  # collection (#60) follows it
    assert device.lines[backup_at - 2 : backup_at] == [f"{line} | json" for line in NEIGHBOUR_LINES]
    cdp = _table(record, "cdp")
    assert isinstance(cdp, tuple)
    assert len(cdp) == 2
    assert _table(record, "lldp") == ()


def test_a_table_the_device_refuses_is_unknown_and_audited_without_output(visit: Visit) -> None:
    device = visit.network.add(str(DEVICE))
    device.replies.update(ios_xe_text.REPLIES)
    device.replies["show cdp neighbors detail"] = "% CDP is not enabled\n"

    record = _record(visit())

    assert record.outcome is DeviceOutcome.VISITED
    assert _table(record, "cdp") == Unknown("CDP is not enabled on the device")
    (failed,) = visit.of(ParseFailed)
    assert failed.command == "show cdp neighbors detail"
    assert "%" not in failed.reason


def test_a_command_timeout_leaves_the_device_partial_and_is_not_retried(visit: Visit) -> None:
    device = visit.network.add(str(DEVICE))
    device.hangs_on = frozenset({"show cdp neighbors detail"})

    record = _record(visit())

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.partial_reason == "a command timed out, so the session was dropped"
    assert record.version is not None
    assert record.landing_privilege is not None
    assert device.lines.count("show cdp neighbors detail") == 1
    assert "show lldp neighbors detail" not in device.lines
    assert _table(record, "lldp") == Unknown("LLDP not read: the session ended first")
    assert visit.backups == 0


def test_the_per_device_timeout_stops_the_examination(visit: Visit) -> None:
    device = visit.network.add(str(DEVICE))
    visit.timeouts = Timeouts(device=0)

    record = _record(visit())

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.partial_reason == "the per-device timeout ran out, so the session was dropped"
    assert device.lines == []


# -- Connections (story 51) -----------------------------------------------------------------


def test_a_connection_failure_is_retried_once_after_the_wait(visit: Visit) -> None:
    device = visit.network.add(str(DEVICE), FakeDevice(connection=ConnectionResult.REFUSED))

    record = _record(visit())

    assert record.unvisited_reason is UnvisitedReason.UNREACHABLE
    assert visit.waits == 1
    assert visit.of(ConnectionAttempted) == [
        ConnectionAttempted(DEVICE, 22, ConnectionResult.REFUSED, retry=False),
        ConnectionAttempted(DEVICE, 22, ConnectionResult.REFUSED, retry=True),
    ]
    assert device.passwords_received == []


def test_a_device_that_answers_the_retry_is_visited(visit: Visit) -> None:
    device = visit.network.add(str(DEVICE), FakeDevice(connection=ConnectionResult.TIMED_OUT))
    visit.during_wait = lambda: setattr(device, "connection", ConnectionResult.CONNECTED)

    record = _record(visit())

    assert record.outcome is DeviceOutcome.VISITED
    assert [e.retry for e in visit.of(ConnectionAttempted)] == [False, True]


def test_a_login_failure_is_never_retried(visit: Visit) -> None:
    device = visit.network.add(str(DEVICE), FakeDevice(password=WRONG))

    record = _record(visit())

    assert record.unvisited_reason is UnvisitedReason.AUTHENTICATION_FAILED
    assert len(visit.of(LoginAttempted)) == 1
    assert len(device.passwords_received) == 1
    assert visit.waits == 0


# -- The identification-string gate for Neighbours (stories 63-64) ----------------------------


@pytest.mark.parametrize("ssh_id", ["SSH-2.0-OpenSSH_9.6", "SSH-2.0-dropbear_2022.83", ""])
def test_a_neighbour_with_no_platform_hint_needs_a_supported_identification_string(
    visit: Visit, ssh_id: str
) -> None:
    device = visit.network.add(str(DEVICE), FakeDevice(ssh_id=ssh_id))

    record = _record(visit(id_gate=True))

    assert record.unvisited_reason is UnvisitedReason.UNSUPPORTED_ADVERTISED
    assert device.passwords_received == []


@pytest.mark.parametrize("ssh_id", ["SSH-2.0-Cisco-1.25", "SSH-2.0-OpenSSH_8.8 FIPS"])
def test_a_neighbour_whose_identification_string_looks_supported_is_logged_into(
    visit: Visit, ssh_id: str
) -> None:
    device = visit.network.add(str(DEVICE), FakeDevice(ssh_id=ssh_id))

    visit(id_gate=True)

    assert device.passwords_received == [DEVICE_CANARY]


def test_a_seed_is_logged_into_whatever_its_identification_string_says(visit: Visit) -> None:
    device = visit.network.add(str(DEVICE), FakeDevice(ssh_id="SSH-2.0-OpenSSH_9.6"))

    record = _record(visit(id_gate=False))

    assert record.outcome is DeviceOutcome.VISITED
    assert device.passwords_received == [DEVICE_CANARY]


# -- One record per device (story 73) -------------------------------------------------------


def test_a_host_key_already_seen_this_run_is_an_alias_left_before_any_password(
    visit: Visit,
) -> None:
    first = visit.network.add(str(DEVICE))
    second = visit.network.add(str(OTHER), FakeDevice(host_key=first.host_key))
    visit()

    result = visit(OTHER)

    assert result == Alias(OTHER, same_as=DEVICE, evidence=AliasEvidence.HOST_KEY)
    assert second.passwords_received == []
    assert second.open_links == 0
    assert visit.of(AliasFound) == [AliasFound(OTHER, DEVICE, "same host key")]
    assert not trust_store.load(visit.known_hosts).key_types(OTHER, 22)


def test_a_serial_already_seen_this_run_is_an_alias_left_before_collection(
    visit: Visit,
) -> None:
    visit.network.add(str(DEVICE))
    second = visit.network.add(str(OTHER))
    second.host_key = HostKey(second.host_key.key_type, _other_key())
    visit()

    result = visit(OTHER)

    assert result == Alias(OTHER, same_as=DEVICE, evidence=AliasEvidence.SERIAL)
    assert "show cdp neighbors detail" not in second.lines
    assert visit.of(AliasFound)[-1] == AliasFound(OTHER, DEVICE, "same chassis serial")


def test_two_devices_with_the_same_hostname_are_two_devices(visit: Visit) -> None:
    visit.network.add(str(DEVICE))
    second = visit.network.add(str(OTHER))
    second.host_key = HostKey(second.host_key.key_type, _other_key())
    second.replies["show version"] = device_text.IOS_XE_SHOW_VERSION.replace(
        "TEST0000A0", "TEST0000C0"
    )
    visit()

    result = _record(visit(OTHER))

    assert result.outcome is DeviceOutcome.VISITED


def _other_key() -> str:
    return synthetic_key(filler=42).base64


# -- The Trust Store cannot be written (#49 follow-up) --------------------------------------


def test_a_trust_store_that_cannot_be_written_stops_the_run_before_any_command(
    visit: Visit,
) -> None:
    visit.store = trust_store.load(visit.known_hosts)
    visit.known_hosts.parent.write_text("", encoding="utf-8")  # a file where its folder goes
    device = visit.network.add(str(DEVICE))

    record = _record(visit())

    assert record.unvisited_reason is UnvisitedReason.RUN_STOPPED
    assert device.lines == []
    (error,) = visit.of(ErrorRaised)
    assert error.message == "the Trust Store could not be written"
    assert visit.of(CommandSent) == []
