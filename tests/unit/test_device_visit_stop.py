"""Ctrl+C as one device's visit sees it (ticket #56; stories 82-84).

Driven through `device_gateway.visit` with a `RunStop` and fake devices at the gateway
seam (tests/support/fake_device). The first Ctrl+C lets a session already open finish but
opens no new connection; the second closes every session at once, and a device already
identified is left partial.
"""

from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import device_gateway, scope, trust_store
from network_analyser.credentials import CredentialSet, CredentialSets, Secret
from network_analyser.device_gateway import RunStop
from network_analyser.records import ScopeRecord
from network_analyser.records.backup import BackupCapture
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.events import (
    AuditEvent,
    CommandSent,
    ConnectionResult,
    DeviceFinished,
    DeviceOutcome,
    LoginAttempted,
    LoginResult,
)
from tests.support.fake_device import DEVICE_CANARY, FakeDevice, FakeNetwork

SEED = IPv4Address("192.0.2.10")
WRONG = "CANARY-pw-wrong-5b2e"


def _scope() -> ScopeRecord:
    fence = scope.parse(["192.0.2.0/24"], [])
    assert isinstance(fence, ScopeRecord)
    return fence


class Visit:
    """Visits one fake device with a `RunStop`, and keeps what was emitted and backed up."""

    def __init__(self, tmp_path: Path) -> None:
        self.network = FakeNetwork()
        self.device = self.network.add(str(SEED), FakeDevice())
        self.stop = RunStop()
        self.events: list[AuditEvent] = []
        self.known_hosts = tmp_path / "known_hosts"
        self.sets = CredentialSets([CredentialSet("netops-ro", Secret(DEVICE_CANARY), None)])
        self.backups: list[BackupCapture] = []
        self.press_on_failed_login = False

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)
        failed = isinstance(event, LoginAttempted) and event.result is LoginResult.FAILED
        if failed and self.press_on_failed_login:
            self.stop.stop_gracefully()

    def backup_sink(self, capture: BackupCapture, _config: str) -> None:
        self.backups.append(capture)

    def __call__(self) -> DeviceRecord:
        record = device_gateway.visit(
            SEED,
            scope=_scope(),
            trust=trust_store.load(self.known_hosts, strict=False),
            sets=self.sets,
            emit=self.emit,
            failure_budget=3,
            backup_sink=self.backup_sink,
            dial=self.network.dial,
            wait_before_retry=self.network.wait_before_retry,
            stop=self.stop,
        )
        assert isinstance(record, DeviceRecord)
        return record

    def finished(self) -> DeviceFinished:
        (event,) = [e for e in self.events if isinstance(e, DeviceFinished)]
        return event


@pytest.fixture
def visit(tmp_path: Path) -> Visit:
    return Visit(tmp_path)


def test_a_visit_after_the_first_ctrl_c_dials_nothing(visit: Visit) -> None:
    visit.stop.stop_gracefully()

    record = visit()

    assert record.outcome is DeviceOutcome.UNVISITED
    assert record.unvisited_reason is UnvisitedReason.RUN_STOPPED
    assert visit.network.dialled == []
    assert visit.finished().reason == "not attempted (Run stopped)"


def test_a_session_open_at_the_first_ctrl_c_finishes_its_work(visit: Visit) -> None:
    visit.device.when_sent["show version"] = visit.stop.stop_gracefully

    record = visit()

    assert record.outcome is DeviceOutcome.VISITED
    assert len(visit.backups) == 1
    assert visit.device.open_links == 0


def test_a_failed_connection_is_not_retried_after_the_first_ctrl_c(visit: Visit) -> None:
    visit.device.connection = ConnectionResult.TIMED_OUT
    visit.network.on_wait = visit.stop.stop_gracefully

    record = visit()

    assert record.unvisited_reason is UnvisitedReason.RUN_STOPPED
    assert visit.network.dialled == [SEED]


def test_no_new_connection_tries_the_next_set_after_the_first_ctrl_c(visit: Visit) -> None:
    visit.sets = CredentialSets(
        [
            CredentialSet("first-ro", Secret(WRONG), None),
            CredentialSet("second-ro", Secret(DEVICE_CANARY), None),
        ]
    )
    visit.press_on_failed_login = True

    record = visit()

    assert record.unvisited_reason is UnvisitedReason.RUN_STOPPED
    assert visit.network.dialled == [SEED]
    assert visit.device.passwords_received == [WRONG]


def test_the_second_ctrl_c_leaves_an_identified_device_partial_with_no_backup(
    visit: Visit,
) -> None:
    visit.device.when_sent["show cdp neighbors detail"] = visit.stop.close_now

    record = visit()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.partial_reason == device_gateway.CLOSED_BY_OPERATOR
    assert record.version is not None
    assert visit.backups == []
    sent = [e.command for e in visit.events if isinstance(e, CommandSent)]
    assert "show running-config view full" not in sent
    assert visit.device.open_links == 0  # closed once, by the stop


def test_the_second_ctrl_c_during_collection_keeps_the_backup_and_leaves_it_partial(
    visit: Visit,
) -> None:
    visit.device.when_sent["show interfaces"] = visit.stop.close_now

    record = visit()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.partial_reason == device_gateway.CLOSED_BY_OPERATOR
    assert len(visit.backups) == 1  # the config was whole before the stop (story 84)
    assert visit.device.open_links == 0


def test_the_second_ctrl_c_before_identification_leaves_the_device_unvisited(
    visit: Visit,
) -> None:
    visit.device.when_sent["terminal length 0"] = visit.stop.close_now

    record = visit()

    assert record.outcome is DeviceOutcome.UNVISITED
    assert record.unvisited_reason is UnvisitedReason.RUN_STOPPED
    assert visit.device.open_links == 0


def test_close_now_closes_every_open_connection_once(visit: Visit) -> None:
    closed: list[str] = []

    class Link:
        def close(self) -> None:
            closed.append("closed")

    link = Link()
    visit.stop.track(link)
    visit.stop.close_now()
    visit.stop.release(link)  # the visit's own close comes later: it is not repeated

    assert closed == ["closed"]
    assert visit.stop.requested
    assert visit.stop.closing
