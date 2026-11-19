"""Capturing each Visited Device's running config for its Backup (ticket #51; stories 95-97).

Driven through `device_gateway.visit` with fake devices at the gateway seam. The raw config
goes straight from the gateway to the Backup sink and to nothing else (spec-37 call 4): not
the device record, not an Audit log event.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import device_gateway, scope, trust_store
from network_analyser.credentials import CredentialSet, CredentialSets, Secret
from network_analyser.records import Platform, ScopeRecord
from network_analyser.records.backup import BackupCapture
from network_analyser.records.device import DeviceRecord, Unknown
from network_analyser.records.events import AuditEvent, CommandSent, DeviceFinished, DeviceOutcome
from network_analyser.records.run_request import Timeouts
from tests.support import device_text
from tests.support.fake_device import DEVICE_CANARY, NXOS_REPLIES, FakeDevice, FakeNetwork

SEED = IPv4Address("192.0.2.10")
TIMEOUTS = Timeouts(connect=1, login=2, command=3, backup=40)


@dataclass
class Capture:
    """Visits the Seed with fake devices; keeps what reached the Backup sink and the log."""

    tmp_path: Path
    network: FakeNetwork = field(default_factory=FakeNetwork)
    events: list[AuditEvent] = field(default_factory=list)
    backups: list[tuple[BackupCapture, str]] = field(default_factory=list)

    def sink(self, capture: BackupCapture, config: str) -> None:
        self.backups.append((capture, config))

    def __call__(self) -> DeviceRecord:
        fence = scope.parse(["192.0.2.0/24"], [])
        assert isinstance(fence, ScopeRecord)
        return device_gateway.visit(
            SEED,
            scope=fence,
            trust=trust_store.load(self.tmp_path / "known_hosts"),
            sets=CredentialSets([CredentialSet("netops-ro", Secret(DEVICE_CANARY), None)]),
            emit=self.events.append,
            failure_budget=3,
            timeouts=TIMEOUTS,
            dial=self.network.dial,
            backup_sink=self.sink,
        )


@pytest.fixture
def capture(tmp_path: Path) -> Capture:
    return Capture(tmp_path)


def _nxos() -> FakeDevice:
    return FakeDevice(ssh_id="SSH-2.0-OpenSSH_8.8 FIPS", prompt="nx-a#", replies=dict(NXOS_REPLIES))


def test_an_ios_xe_config_goes_to_the_sink_exactly_as_the_device_sent_it(
    capture: Capture,
) -> None:
    device = capture.network.add(str(SEED))
    before = datetime.now(UTC)

    record = capture()

    assert record.outcome is DeviceOutcome.VISITED
    assert device.lines[-1] == "show running-config view full"
    ((identity, config),) = capture.backups
    assert config == device_text.IOS_XE_RUNNING_CONFIG
    assert identity.ip == SEED
    assert identity.platform is Platform.IOS_XE
    assert identity.hostname == "sw-a"
    assert identity.serials == ("TEST0000A01", "TEST0000A02")
    assert identity.command == "show running-config view full"
    assert before <= identity.captured_at <= datetime.now(UTC)
    assert identity.captured_at.tzinfo is UTC


def test_an_nxos_config_goes_to_the_sink(capture: Capture) -> None:
    device = capture.network.add(str(SEED), _nxos())

    capture()

    assert device.lines.count("show running-config") == 1
    ((identity, config),) = capture.backups
    assert config == device_text.NXOS_RUNNING_CONFIG
    assert identity.hostname == "nx-a"
    assert identity.serials == ("TEST0000N01",)


def test_the_config_reaches_nothing_but_the_sink(capture: Capture) -> None:
    capture.network.add(str(SEED))

    record = capture()

    seen = repr(record) + repr(capture.events) + repr([i for i, _ in capture.backups])
    for canary in device_text.CONFIG_CANARIES:
        assert canary not in seen
    sent = [e for e in capture.events if isinstance(e, CommandSent)][-1]
    assert sent.command == "show running-config view full"
    assert sent.bytes_received > 0


def test_the_backup_gets_the_backup_timeout_not_the_command_timeout(capture: Capture) -> None:
    device = capture.network.add(str(SEED))

    capture()

    assert device.timeouts[-1] == TIMEOUTS.backup
    assert set(device.timeouts[:-1]) == {TIMEOUTS.command}


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        (
            device_text.COMMAND_AUTHORISATION_FAILED,
            "the account cannot read the full running config",
        ),
        (
            device_text.IOS_XE_RUNNING_CONFIG.removesuffix("end\n"),
            "the running config came back incomplete",
        ),
        (
            device_text.IOS_XE_RUNNING_CONFIG.replace("hostname sw-a\n", ""),
            "the running config has no hostname line",
        ),
    ],
)
def test_a_missing_backup_leaves_the_device_visited_with_partial_data_and_a_reason(
    capture: Capture, reply: str, reason: str
) -> None:
    device = capture.network.add(str(SEED))
    device.replies["show running-config view full"] = reply

    record = capture()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.partial_reason == reason
    assert record.platform is Platform.IOS_XE
    assert record.version is not None
    assert record.version.hostname == "sw-a"
    assert capture.backups == []
    assert capture.events[-1] == DeviceFinished(SEED, DeviceOutcome.PARTIAL, reason)


def test_a_backup_that_times_out_is_never_handed_on(capture: Capture) -> None:
    capture.network.add(
        str(SEED), FakeDevice(hangs_on=frozenset({"show running-config view full"}))
    )

    record = capture()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.partial_reason == "a command timed out, so the session was dropped"
    assert capture.backups == []


def test_identity_the_device_did_not_give_is_unknown_in_the_capture(capture: Capture) -> None:
    device = capture.network.add(str(SEED))
    device.replies["show version"] = "Cisco IOS XE Software, Version 17.09.04a\n"

    capture()

    ((identity, _),) = capture.backups
    assert isinstance(identity.hostname, Unknown)
    assert isinstance(identity.serials, Unknown)
