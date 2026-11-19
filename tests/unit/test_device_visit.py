"""Logging into one Seed and identifying its Platform (ticket #49; stories 38-48, 53-59).

Driven through `device_gateway.visit` with fake devices at the gateway seam
(tests/support/fake_device): no SSH server, no network. Each test checks what came back
(the device record), what was recorded (`audit.log` events) and what reached the device.
"""

from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import device_gateway, scope, trust_store
from network_analyser.credentials import CredentialSet, CredentialSets, Secret
from network_analyser.records import (
    CredentialSetView,
    HostKeyVerdict,
    Placement,
    Platform,
    ScopeRecord,
)
from network_analyser.records.backup import BackupCapture
from network_analyser.records.device import (
    DeviceRecord,
    LandingPrivilege,
    UnvisitedReason,
    VersionFacts,
)
from network_analyser.records.events import (
    AuditEvent,
    CommandResult,
    CommandSent,
    ConnectionAttempted,
    ConnectionResult,
    CredentialSetRetired,
    DeviceFinished,
    DeviceIdentified,
    DeviceOutcome,
    HostKeyChecked,
    LoginAttempted,
    LoginResult,
    OutOfScopeRefused,
)
from network_analyser.trust_store import TrustStore
from tests.support import device_text
from tests.support.fake_device import (
    DEVICE_CANARY,
    NXOS_REPLIES,
    FakeDevice,
    FakeNetwork,
    synthetic_key,
)

SEED = IPv4Address("192.0.2.10")
WRONG = "CANARY-pw-wrong-91d0"


def _scope() -> ScopeRecord:
    fence = scope.parse(["192.0.2.0/24"], ["192.0.2.128/25"])
    assert isinstance(fence, ScopeRecord)
    return fence


class Visit:
    """Visits one IP with fake devices and collects what was emitted."""

    def __init__(self, tmp_path: Path) -> None:
        self.network = FakeNetwork()
        self.events: list[AuditEvent] = []
        self.known_hosts = tmp_path / "trust" / "known_hosts"
        self.strict = False
        self.sets = CredentialSets([CredentialSet("netops-ro", Secret(DEVICE_CANARY), None)])
        self.backups: list[str] = []  # the configs handed to the Backup sink (#51)

    def backup_sink(self, _capture: BackupCapture, config: str) -> None:
        self.backups.append(config)

    def trust(self) -> TrustStore:
        return trust_store.load(self.known_hosts, strict=self.strict)

    def __call__(self, ip: IPv4Address = SEED, *, store: TrustStore | None = None) -> DeviceRecord:
        record = device_gateway.visit(
            ip,
            scope=_scope(),
            trust=store or self.trust(),
            sets=self.sets,
            emit=self.events.append,
            failure_budget=3,
            backup_sink=self.backup_sink,
            dial=self.network.dial,
            wait_before_retry=self.network.wait_before_retry,
        )
        assert isinstance(record, DeviceRecord)  # no identity register: never an alias
        return record

    def of(self, kind: type[AuditEvent]) -> list[AuditEvent]:
        return [e for e in self.events if isinstance(e, kind)]

    def commands(self) -> list[str]:
        return [e.command for e in self.events if isinstance(e, CommandSent)]


@pytest.fixture
def visit(tmp_path: Path) -> Visit:
    return Visit(tmp_path)


# -- A normal visit --------------------------------------------------------------------------


def test_a_seed_is_logged_into_identified_and_left(visit: Visit) -> None:
    device = visit.network.add(str(SEED))

    record = visit()

    assert record.outcome is DeviceOutcome.VISITED
    assert record.platform is Platform.IOS_XE
    assert record.ssh_id == "SSH-2.0-Cisco-1.25"
    assert record.credential_set == CredentialSetView(1, "netops-ro", None)
    assert record.landing_privilege == LandingPrivilege("level 15", too_low=False)
    assert record.version == VersionFacts(
        "sw-a", "C9300-48P", "17.9.4a", ("TEST0000A01", "TEST0000A02")
    )
    assert record.host_key is not None
    assert record.host_key.verdict is HostKeyVerdict.NEW
    assert device.lines == [
        "terminal length 0",
        "terminal width 511",
        "show version",
        "show privilege",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
        "show running-config view full",
    ]
    assert visit.backups == [device_text.IOS_XE_RUNNING_CONFIG]
    assert device.passwords_received == [DEVICE_CANARY]
    assert device.open_links == 0


def test_an_nxos_seed_reports_its_roles(visit: Visit) -> None:
    visit.network.add(
        str(SEED),
        FakeDevice(ssh_id="SSH-2.0-OpenSSH_8.8 FIPS", prompt="nx-a#", replies=dict(NXOS_REPLIES)),
    )

    record = visit()

    assert record.platform is Platform.NX_OS
    assert record.landing_privilege == LandingPrivilege("roles NA-READ", too_low=False)
    commands = visit.commands()
    start = commands.index("show user-account netops-ro")
    assert commands[start : start + 4] == [  # then the collection commands (#60)
        "show user-account netops-ro",
        "show cdp neighbors detail | json",
        "show lldp neighbors detail | json",
        "show running-config",
    ]


def test_every_step_is_audited_in_order_without_device_output(visit: Visit) -> None:
    visit.network.add(str(SEED))

    visit()

    kinds = [type(e) for e in visit.events]
    assert kinds == [
        ConnectionAttempted,
        HostKeyChecked,
        LoginAttempted,
        CommandSent,
        CommandSent,
        CommandSent,
        CommandSent,
        DeviceIdentified,
        CommandSent,
        CommandSent,
        CommandSent,
        DeviceFinished,
    ]
    assert visit.events[0] == ConnectionAttempted(SEED, 22, ConnectionResult.CONNECTED, retry=False)
    assert visit.events[2] == LoginAttempted(SEED, 1, "netops-ro", LoginResult.SUCCEEDED)
    assert visit.events[-5] == DeviceIdentified(SEED, Platform.IOS_XE, "level 15")
    assert visit.events[-1] == DeviceFinished(SEED, DeviceOutcome.VISITED, None)
    assert all(DEVICE_CANARY not in repr(e) for e in visit.events)
    assert all("uptime" not in repr(e) for e in visit.events)
    assert all("hostname sw-a" not in repr(e) for e in visit.events)


def test_a_new_key_is_trusted_once_a_password_was_sent_and_known_next_time(
    visit: Visit,
) -> None:
    visit.network.add(str(SEED))
    visit()

    record = visit()

    assert record.host_key is not None
    assert record.host_key.verdict is HostKeyVerdict.KNOWN


def test_a_known_device_is_asked_only_for_the_key_type_trusted_for_it(visit: Visit) -> None:
    device = visit.network.add(str(SEED))
    visit()

    visit()

    assert device.key_types_asked == [(), ("ssh-ed25519",)]


def test_too_low_a_landing_privilege_is_flagged(visit: Visit) -> None:
    device = visit.network.add(str(SEED))
    device.replies["show privilege"] = device_text.IOS_XE_PRIVILEGE_1

    record = visit()

    assert record.landing_privilege == LandingPrivilege("level 1", too_low=True)


# -- The Scope is checked before any socket (stories 39-41) ---------------------------------


@pytest.mark.parametrize(
    ("ip", "placement", "reason"),
    [
        ("198.51.100.1", Placement.OUTSIDE, UnvisitedReason.OUTSIDE_SCOPE),
        ("192.0.2.200", Placement.EXCLUDED, UnvisitedReason.EXCLUDED),
        ("127.0.0.1", Placement.NEVER_A_TARGET, UnvisitedReason.OUTSIDE_SCOPE),
        ("224.0.0.5", Placement.NEVER_A_TARGET, UnvisitedReason.OUTSIDE_SCOPE),
        ("192.0.2.0", Placement.NEVER_A_TARGET, UnvisitedReason.OUTSIDE_SCOPE),
    ],
)
def test_an_address_outside_the_scope_is_never_dialled(
    visit: Visit, ip: str, placement: Placement, reason: UnvisitedReason
) -> None:
    address = IPv4Address(ip)
    visit.network.add(ip)

    record = visit(address)

    assert visit.network.dialled == []
    assert record.outcome is DeviceOutcome.UNVISITED
    assert record.unvisited_reason is reason
    assert visit.events[0] == OutOfScopeRefused(address, 22, placement)


# -- The Trust Store before any password (ADR 0002; stories 42-46) --------------------------


def _trust_other_key(visit: Visit) -> None:
    store = visit.trust()
    store.password_sent(store.check(SEED, 22, synthetic_key(filler=9)))


def test_a_changed_key_is_a_hard_stop_and_no_password_is_sent(visit: Visit) -> None:
    _trust_other_key(visit)
    device = visit.network.add(str(SEED))

    record = visit()

    assert record.unvisited_reason is UnvisitedReason.HOST_KEY_CHANGED
    assert device.passwords_received == []
    assert visit.of(LoginAttempted) == []
    (checked,) = visit.of(HostKeyChecked)
    assert isinstance(checked, HostKeyChecked)
    assert checked.verdict is HostKeyVerdict.CHANGED
    assert checked.trusted_fingerprint is not None


def test_a_known_device_that_no_longer_offers_its_key_type_counts_as_changed(
    visit: Visit,
) -> None:
    store = visit.trust()
    store.password_sent(store.check(SEED, 22, synthetic_key("ecdsa-sha2-nistp256")))
    device = visit.network.add(str(SEED))

    record = visit()

    assert record.unvisited_reason is UnvisitedReason.HOST_KEY_CHANGED
    assert device.passwords_received == []
    assert device.key_types_asked == [("ecdsa-sha2-nistp256",), ()]


def test_strict_mode_never_logs_into_an_untrusted_device(visit: Visit) -> None:
    visit.strict = True
    device = visit.network.add(str(SEED))

    record = visit()

    assert record.unvisited_reason is UnvisitedReason.HOST_KEY_NOT_TRUSTED
    assert device.passwords_received == []
    assert not visit.known_hosts.exists()


def test_a_wireless_controller_is_rejected_before_login(visit: Visit) -> None:
    device = visit.network.add(str(SEED), FakeDevice(ssh_id="SSH-2.0-CISCO_WLC"))

    record = visit()

    assert record.unvisited_reason is UnvisitedReason.UNSUPPORTED_ADVERTISED
    assert device.passwords_received == []


# -- Logins (stories 33-38) ------------------------------------------------------------------


def test_each_set_gets_one_connection_with_one_password_attempt(visit: Visit) -> None:
    visit.sets = CredentialSets(
        [
            CredentialSet("wrong-a", Secret(WRONG), None),
            CredentialSet("netops-ro", Secret(DEVICE_CANARY), None),
        ]
    )
    device = visit.network.add(str(SEED))

    record = visit()

    assert record.outcome is DeviceOutcome.VISITED
    assert record.credential_set == CredentialSetView(2, "netops-ro", None)
    assert device.passwords_received == [WRONG, DEVICE_CANARY]
    assert visit.network.dialled == [SEED, SEED]
    assert [e.result for e in visit.of(LoginAttempted)] == [  # type: ignore[attr-defined]
        LoginResult.FAILED,
        LoginResult.SUCCEEDED,
    ]


def test_a_device_every_set_fails_on_is_recorded_and_the_key_still_trusted(
    visit: Visit,
) -> None:
    visit.sets = CredentialSets([CredentialSet("wrong-a", Secret(WRONG), None)])
    visit.network.add(str(SEED))

    record = visit()

    assert record.unvisited_reason is UnvisitedReason.AUTHENTICATION_FAILED
    assert visit.trust().check(SEED, 22, synthetic_key()).verdict is HostKeyVerdict.KNOWN


def test_a_set_that_spends_its_budget_is_retired_and_reported(visit: Visit, tmp_path: Path) -> None:
    visit.sets = CredentialSets([CredentialSet("wrong-a", Secret(WRONG), None)])
    store = trust_store.load(tmp_path / "other")
    records = []
    for last in range(2, 6):
        visit.network.add(f"192.0.2.{last}")
        records.append(visit(IPv4Address(f"192.0.2.{last}"), store=store))

    retired = visit.of(CredentialSetRetired)
    assert retired == [CredentialSetRetired(1, "wrong-a", 3)]
    assert len(visit.of(LoginAttempted)) == 3
    assert visit.network.dialled == [IPv4Address(f"192.0.2.{n}") for n in (2, 3, 4)]
    assert records[-1].unvisited_reason is UnvisitedReason.SETS_RETIRED


def test_a_platform_limited_set_is_tried_only_where_the_hint_matches(visit: Visit) -> None:
    visit.sets = CredentialSets([CredentialSet("nx-only", Secret(DEVICE_CANARY), Platform.NX_OS)])
    device = visit.network.add(str(SEED))

    record = visit()

    assert record.unvisited_reason is UnvisitedReason.AUTHENTICATION_FAILED
    assert device.passwords_received == []


# -- Identification (stories 57-58) ----------------------------------------------------------


@pytest.mark.parametrize(
    "show_version", [device_text.ASA_SHOW_VERSION, device_text.IOS_XR_SHOW_VERSION]
)
def test_an_unsupported_platform_is_left_at_once_after_show_version(
    visit: Visit, show_version: str
) -> None:
    device = visit.network.add(str(SEED))
    device.replies["show version"] = show_version

    record = visit()

    assert record.outcome is DeviceOutcome.UNVISITED
    assert record.unvisited_reason is UnvisitedReason.UNSUPPORTED_IDENTIFIED
    assert device.lines[-1] == "show version"
    assert device.open_links == 0


# -- Read-only enforcement (stories 53-55) ---------------------------------------------------


def test_a_configuration_mode_prompt_drops_the_session_at_once(visit: Visit) -> None:
    device = visit.network.add(str(SEED), FakeDevice(config_prompt_after="terminal length 0"))

    record = visit()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.partial_reason == device_gateway.CONFIG_MODE
    assert device.lines == ["terminal length 0"]
    assert device.open_links == 0


def test_a_configuration_mode_prompt_at_login_drops_the_session(visit: Visit) -> None:
    device = visit.network.add(str(SEED), FakeDevice(prompt="sw-a(config)#"))

    record = visit()

    assert record.partial_reason == device_gateway.CONFIG_MODE
    assert device.lines == []


def test_the_librarys_own_writes_pass_the_same_gate(visit: Visit) -> None:
    device = visit.network.add(str(SEED))

    visit()

    assert device.gate is not None
    assert device.gate("show privilege")  # identified as IOS/IOS-XE by then
    assert not device.gate("configure terminal")
    assert not device.gate("exit")


def test_a_command_that_times_out_leaves_the_device_partial(visit: Visit) -> None:
    visit.network.add(str(SEED), FakeDevice(hangs_on=frozenset({"show privilege"})))

    record = visit()

    assert record.outcome is DeviceOutcome.PARTIAL
    assert record.platform is Platform.IOS_XE
    assert visit.of(CommandSent)[-1].result is CommandResult.TIMEOUT  # type: ignore[attr-defined]


def test_unreachable_devices_are_recorded(visit: Visit) -> None:
    visit.network.add(str(SEED), FakeDevice(connection=ConnectionResult.REFUSED))

    record = visit()

    assert record.unvisited_reason is UnvisitedReason.UNREACHABLE
    assert visit.events[0] == ConnectionAttempted(SEED, 22, ConnectionResult.REFUSED, retry=False)


def test_a_device_offering_only_old_algorithms_is_recorded_as_such(visit: Visit) -> None:
    visit.network.add(str(SEED), FakeDevice(algorithms_too_old=True))

    record = visit()

    assert record.unvisited_reason is UnvisitedReason.ALGORITHMS_TOO_OLD


def test_the_ssh_identification_string_is_kept_printable(visit: Visit) -> None:
    visit.network.add(str(SEED), FakeDevice(ssh_id="SSH-2.0-Cisco-1.25\x1b[2J"))

    record = visit()

    assert record.ssh_id == "SSH-2.0-Cisco-1.25\\x1b[2J"
