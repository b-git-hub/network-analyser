"""Credential Sets at the login: order, probation, the failure budget and retirement (#54).

Driven through `device_gateway.visit` with fake devices at the gateway seam
(tests/support/fake_device): no SSH server, no network. Stories 31-37 of spec #37. Each
password is a synthetic canary; the tests check which reached which device, and when.
"""

import threading
import time
from collections.abc import Callable
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import device_gateway, scope, trust_store
from network_analyser.credentials import CredentialSet, CredentialSets, Secret
from network_analyser.records import CredentialSetView, Platform, ScopeRecord
from network_analyser.records.backup import BackupCapture
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.events import (
    AuditEvent,
    ConnectionResult,
    CredentialSetRetired,
    DeviceOutcome,
    LoginAttempted,
    LoginResult,
)
from network_analyser.trust_store import TrustStore
from tests.support.fake_device import DEVICE_CANARY, NXOS_REPLIES, FakeDevice, FakeNetwork

WRONG_A = "CANARY-pw-wrong-a-61c2"
WRONG_B = "CANARY-pw-wrong-b-0f9e"
NO_HINT_SSH_ID = "SSH-2.0-OpenSSH_9.6"
"""An identification string that suggests no Platform and is not rejected."""


def _ip(last: int) -> IPv4Address:
    return IPv4Address(f"192.0.2.{last}")


class Visits:
    """Visits devices with fake ones, sharing one set of Credential Sets like the pool does."""

    def __init__(self, tmp_path: Path, *sets: CredentialSet, budget: int = 3) -> None:
        self.network = FakeNetwork()
        self.events: list[AuditEvent] = []
        self.sets = CredentialSets(sets or [_set("netops-ro", DEVICE_CANARY)])
        self.budget = budget
        self.store: TrustStore = trust_store.load(tmp_path / "trust" / "known_hosts")
        fence = scope.parse(["192.0.2.0/24"], [])
        assert isinstance(fence, ScopeRecord)
        self.scope = fence
        self._lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        with self._lock:
            self.events.append(event)

    def add(self, last: int, **changes: object) -> FakeDevice:
        device = FakeDevice()
        for key, value in changes.items():
            setattr(device, key, value)
        return self.network.add(str(_ip(last)), device)

    def __call__(self, last: int, *, neighbour_hint: Platform | None = None) -> DeviceRecord:
        record = device_gateway.visit(
            _ip(last),
            scope=self.scope,
            trust=self.store,
            sets=self.sets,
            emit=self.emit,
            failure_budget=self.budget,
            backup_sink=_drop_backup,
            dial=self.network.dial,
            wait_before_retry=self.network.wait_before_retry,
            neighbour_hint=neighbour_hint,
        )
        assert isinstance(record, DeviceRecord)
        return record

    def of(self, kind: type[AuditEvent]) -> list[AuditEvent]:
        return [e for e in self.events if isinstance(e, kind)]

    def in_thread(self, last: int) -> tuple[threading.Thread, list[DeviceRecord]]:
        found: list[DeviceRecord] = []
        thread = threading.Thread(target=lambda: found.append(self(last)))
        thread.start()
        return thread, found


def _drop_backup(_capture: BackupCapture, _config: str) -> None:
    return None


def _set(username: str, password: str, limit: Platform | None = None) -> CredentialSet:
    return CredentialSet(username, Secret(password), limit)


def _until(condition: Callable[[], bool]) -> None:
    """Wait, briefly, until `condition` holds (another thread is getting there)."""
    deadline = time.monotonic() + 5
    while not condition():
        assert time.monotonic() < deadline, "timed out waiting"
        time.sleep(0.005)


def _held_open(device: FakeDevice) -> threading.Event:
    """Make `device` hold its password attempt open until the returned event is set."""
    go = threading.Event()

    def hold() -> None:
        go.wait(5)

    device.on_login = hold
    return go


# -- Order (stories 31-33) -----------------------------------------------------------------


def test_a_set_that_worked_is_tried_first_on_the_next_device(tmp_path: Path) -> None:
    visits = Visits(tmp_path, _set("wrong-a", WRONG_A), _set("netops-ro", DEVICE_CANARY))
    first, second = visits.add(10), visits.add(11)

    visits(10)
    record = visits(11)

    assert first.passwords_received == [WRONG_A, DEVICE_CANARY]
    assert second.passwords_received == [DEVICE_CANARY]
    assert record.credential_set == CredentialSetView(2, "netops-ro", None)


def test_every_eligible_set_failing_is_authentication_failed_each_tried_once(
    tmp_path: Path,
) -> None:
    visits = Visits(tmp_path, _set("wrong-a", WRONG_A), _set("wrong-b", WRONG_B))
    device = visits.add(10)

    record = visits(10)

    assert record.unvisited_reason is UnvisitedReason.AUTHENTICATION_FAILED
    assert device.passwords_received == [WRONG_A, WRONG_B]
    assert visits.network.dialled == [_ip(10), _ip(10)]
    assert device.open_links == 0


def test_each_login_is_audited_by_username_and_no_password_appears(tmp_path: Path) -> None:
    visits = Visits(tmp_path, _set("wrong-a", WRONG_A), _set("netops-ro", DEVICE_CANARY))
    visits.add(10)

    visits(10)

    assert visits.of(LoginAttempted) == [
        LoginAttempted(_ip(10), 1, "wrong-a", LoginResult.FAILED),
        LoginAttempted(_ip(10), 2, "netops-ro", LoginResult.SUCCEEDED),
    ]
    shown = repr(visits.events)
    assert WRONG_A not in shown
    assert DEVICE_CANARY not in shown


def test_a_neighbour_hint_makes_a_platform_limited_set_eligible(tmp_path: Path) -> None:
    visits = Visits(tmp_path, _set("netops-ro", DEVICE_CANARY, Platform.NX_OS))
    device = visits.add(10, ssh_id=NO_HINT_SSH_ID, prompt="nx-a#", replies=dict(NXOS_REPLIES))

    record = visits(10, neighbour_hint=Platform.NX_OS)

    assert device.passwords_received == [DEVICE_CANARY]
    assert record.credential_set == CredentialSetView(1, "netops-ro", Platform.NX_OS)


def test_without_a_matching_hint_a_platform_limited_set_is_never_sent(tmp_path: Path) -> None:
    visits = Visits(tmp_path, _set("netops-ro", DEVICE_CANARY, Platform.NX_OS))
    device = visits.add(10, ssh_id=NO_HINT_SSH_ID)

    record = visits(10, neighbour_hint=Platform.IOS_XE)

    assert device.passwords_received == []
    assert record.unvisited_reason is UnvisitedReason.AUTHENTICATION_FAILED


# -- The failure budget and retirement (stories 34, 36, 37) --------------------------------


def test_a_set_is_retired_once_its_budget_is_spent_and_announced_once(tmp_path: Path) -> None:
    visits = Visits(tmp_path, _set("wrong-a", WRONG_A), budget=2)
    for last in (10, 11, 12):
        visits.add(last)

    records = [visits(last) for last in (10, 11, 12)]

    assert visits.of(CredentialSetRetired) == [CredentialSetRetired(1, "wrong-a", 2)]
    assert [r.unvisited_reason for r in records] == [
        UnvisitedReason.AUTHENTICATION_FAILED,
        UnvisitedReason.AUTHENTICATION_FAILED,
        UnvisitedReason.SETS_RETIRED,
    ]
    assert visits.network.dialled == [_ip(10), _ip(11)]  # nothing dialled once all are retired


def test_a_device_whose_only_eligible_sets_are_retired_gets_no_password(tmp_path: Path) -> None:
    visits = Visits(
        tmp_path,
        _set("wrong-a", WRONG_A),
        _set("netops-ro", DEVICE_CANARY, Platform.NX_OS),
        budget=1,
    )
    visits.add(10)
    later = visits.add(11)

    first = visits(10)
    second = visits(11)

    assert first.unvisited_reason is UnvisitedReason.AUTHENTICATION_FAILED
    assert second.unvisited_reason is UnvisitedReason.SETS_RETIRED
    assert later.passwords_received == []
    assert not visits.sets.all_retired()


def test_a_connection_lost_during_the_login_spends_the_budget(tmp_path: Path) -> None:
    visits = Visits(tmp_path, _set("netops-ro", DEVICE_CANARY), budget=1)
    visits.add(10, login_lost=True)

    record = visits(10)

    assert record.unvisited_reason is UnvisitedReason.UNREACHABLE
    assert visits.sets.failures(1) == 1
    assert visits.sets.all_retired()
    assert visits.of(LoginAttempted) == [LoginAttempted(_ip(10), 1, "netops-ro", LoginResult.LOST)]
    assert visits.of(CredentialSetRetired) == [CredentialSetRetired(1, "netops-ro", 1)]


# -- Probation across the pool (story 35) --------------------------------------------------


def test_a_set_on_probation_has_one_login_in_flight_and_no_link_open_while_waiting(
    tmp_path: Path,
) -> None:
    visits = Visits(tmp_path)
    first, second = visits.add(10), visits.add(11)
    go = _held_open(first)

    one, found_one = visits.in_thread(10)
    _until(lambda: first.passwords_received == [DEVICE_CANARY])
    two, found_two = visits.in_thread(11)
    _until(lambda: visits.network.dialled.count(_ip(11)) >= 1 and second.open_links == 0)
    time.sleep(0.05)

    assert second.passwords_received == []  # the first login is still in flight
    assert second.open_links == 0  # it waits for its turn with no SSH link open
    go.set()
    one.join(timeout=5)
    two.join(timeout=5)
    assert second.passwords_received == [DEVICE_CANARY]
    assert [r.outcome for r in (*found_one, *found_two)] == [DeviceOutcome.VISITED] * 2


def test_once_a_set_has_worked_its_logins_run_in_parallel(tmp_path: Path) -> None:
    visits = Visits(tmp_path)
    visits.add(9)
    first, second = visits.add(10), visits.add(11)
    visits(9)  # the set works once: probation is over
    go = _held_open(first)

    one, _ = visits.in_thread(10)
    _until(lambda: first.passwords_received == [DEVICE_CANARY])
    two, _ = visits.in_thread(11)
    two.join(timeout=5)

    assert second.passwords_received == [DEVICE_CANARY]  # while the first is still in flight
    go.set()
    one.join(timeout=5)


# -- The lease is always given back --------------------------------------------------------


class _LoginBrokeError(RuntimeError):
    """A bug inside the login: the visit raises, and must still give the lease back."""


def test_the_lease_is_given_back_when_the_login_raises(tmp_path: Path) -> None:
    visits = Visits(tmp_path)

    def broken() -> None:
        raise _LoginBrokeError

    visits.add(10, on_login=broken)

    with pytest.raises(_LoginBrokeError):
        visits(10)

    lease = visits.sets.try_lease(1, failure_budget=3)  # on probation: free only if given back
    assert lease is not None
    lease.release()
    assert visits.sets.failures(1) == 0


def test_a_lease_taken_before_a_connection_that_fails_is_given_back(tmp_path: Path) -> None:
    visits = Visits(tmp_path, _set("wrong-a", WRONG_A), _set("netops-ro", DEVICE_CANARY))
    device = visits.add(10)

    def refuse_from_now_on() -> None:
        device.connection = ConnectionResult.REFUSED

    device.on_login = refuse_from_now_on

    record = visits(10)

    assert record.unvisited_reason is UnvisitedReason.UNREACHABLE
    lease = visits.sets.try_lease(2, failure_budget=3)
    assert lease is not None
    lease.release()
    assert visits.sets.failures(2) == 0
