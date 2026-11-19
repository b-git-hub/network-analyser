"""The crawl: from the Seeds through CDP and LLDP, inside the Scope (#50; stories 49, 60-75).

Driven through `discovery.crawl` with the real `device_gateway.visit` bound to fake devices
at the gateway seam (tests/support/fake_device), so the gating, queueing, address choice and
identity checks are seen end to end. All addresses are RFC 5737, all names synthetic.
"""

import threading
import time
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import device_gateway, discovery, scope, trust_store
from network_analyser.credentials import CredentialSet, CredentialSets, Secret
from network_analyser.device_gateway.identity import Identity
from network_analyser.records import Platform, ScopeRecord
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.events import (
    AuditEvent,
    DeviceOutcome,
    NeighbourNotVisited,
)
from network_analyser.records.identity import Alias
from network_analyser.records.run_request import Timeouts
from network_analyser.trust_store import TrustStore
from tests.support import device_text
from tests.support.fake_device import DEVICE_CANARY, FakeDevice, FakeNetwork, synthetic_key

SEED = IPv4Address("192.0.2.1")
WRONG = "CANARY-pw-other-3f81"
"""A password no Credential Set holds: a synthetic canary."""
IOS = "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a"


def cdp(*entries: str) -> str:
    """A `show cdp neighbors detail` table of the given entries."""
    return "".join(entries) + f"\nTotal cdp entries displayed : {len(entries)}\n"


def entry(  # noqa: PLR0913 (one keyword per CDP field a test varies)
    name: str,
    *,
    management: tuple[str, ...] = (),
    other: tuple[str, ...] = (),
    platform: str = "cisco C9300-48P",
    capabilities: str = "Router Switch IGMP",
    version: str = IOS,
    port: str = "GigabitEthernet1/0/1",
) -> str:
    """One CDP detail entry: synthetic, shaped like IOS-XE's."""
    lines = ["-------------------------", f"Device ID: {name}", "Entry address(es):"]
    lines += [f"  IP address: {a}" if ":" not in a else f"  IPv6 address: {a}" for a in other]
    lines += [
        f"Platform: {platform},  Capabilities: {capabilities}",
        f"Interface: {port},  Port ID (outgoing port): GigabitEthernet1/0/1",
        "Holdtime : 150 sec",
        "",
        "Version :",
        version,
        "",
        "Management address(es):",
    ]
    lines += [f"  IP address: {a}" if ":" not in a else f"  IPv6 address: {a}" for a in management]
    return "\n".join([*lines, "", ""])


class Backups:
    """Stands in for the locking worker: counts the configs it is handed."""

    def __init__(self) -> None:
        self.taken = 0

    def append_capture(self, _capture: object, _config: str, /) -> None:
        self.taken += 1


class Lab:
    """Fake devices, each with its own host key and serial, and the crawl over them."""

    def __init__(self, tmp_path: Path) -> None:
        self.network = FakeNetwork()
        self.events: list[AuditEvent] = []
        self.store: TrustStore = trust_store.load(tmp_path / "trust" / "known_hosts")
        self.sets = CredentialSets([CredentialSet("netops-ro", Secret(DEVICE_CANARY), None)])
        self.count = 0
        self.budget = 3
        self.backups = Backups()
        self.stop = device_gateway.RunStop()
        self.ticks: list[int] = []
        fence = scope.parse(["192.0.2.0/24"], ["192.0.2.200-192.0.2.210"])
        assert isinstance(fence, ScopeRecord)
        self.scope = fence

    def device(self, ip: str, *neighbours: str, **changes: object) -> FakeDevice:
        """Add a distinct IOS-XE device at `ip` whose CDP table shows `neighbours`."""
        self.count += 1
        name = f"sw-{self.count}"
        device = FakeDevice(host_key=synthetic_key(filler=self.count), prompt=f"{name}#")
        device.replies["show version"] = device_text.IOS_XE_SHOW_VERSION.replace(
            "sw-a", name
        ).replace("TEST0000A0", f"TEST{self.count:04d}B0")
        device.replies["show cdp neighbors detail"] = cdp(*neighbours) if neighbours else ""
        for key, value in changes.items():
            setattr(device, key, value)
        return self.network.add(ip, device)

    def visit(
        self,
        ip: IPv4Address,
        *,
        id_gate: bool,
        neighbour_hint: Platform | None,
        identity: Identity,
    ) -> DeviceRecord | Alias:
        return device_gateway.visit(
            ip,
            scope=self.scope,
            trust=self.store,
            sets=self.sets,
            emit=self.events.append,
            failure_budget=self.budget,
            timeouts=Timeouts(),
            backup_sink=self.backups.append_capture,
            dial=self.network.dial,
            id_gate=id_gate,
            neighbour_hint=neighbour_hint,
            identity=identity,
            wait_before_retry=self.network.wait_before_retry,
            stop=self.stop,
        )

    def crawl(self, *seeds: str, parallel: int = 10) -> CrawlResult:
        return discovery.crawl(
            [IPv4Address(s) for s in seeds or (str(SEED),)],
            self.visit,
            scope=self.scope,
            parallel=parallel,
            emit=self.events.append,
            stop=self.stop,
            tick=self.ticks.append,
            all_retired=self.sets.all_retired,
        )


@pytest.fixture
def lab(tmp_path: Path) -> Lab:
    return Lab(tmp_path)


def _ips(result: CrawlResult) -> list[str]:
    return sorted(str(d.ip) for d in result.devices)


def _unvisited(result: CrawlResult, reason: UnvisitedReason) -> list[DeviceRecord]:
    return [u for u in result.unvisited if u.unvisited_reason is reason]


# -- Spreading through the network (stories 60-61) -----------------------------------------


def test_the_crawl_spreads_from_one_seed_with_no_hop_limit(lab: Lab) -> None:
    lab.device(str(SEED), entry("sw-b", management=("192.0.2.2",)))
    lab.device("192.0.2.2", entry("sw-c", management=("192.0.2.3",)))
    lab.device("192.0.2.3", entry("sw-d", management=("192.0.2.4",)))
    lab.device("192.0.2.4", entry("sw-e", management=("192.0.2.5",)))
    lab.device("192.0.2.5")

    result = lab.crawl()

    assert _ips(result) == [f"192.0.2.{n}" for n in range(1, 6)]
    assert all(d.outcome is DeviceOutcome.VISITED for d in result.devices)
    assert result.stopped is None


def test_a_neighbour_advertised_by_many_devices_is_visited_once(lab: Lab) -> None:
    lab.device(
        str(SEED),
        entry("sw-b", management=("192.0.2.2",)),
        entry("sw-c", management=("192.0.2.3",)),
    )
    lab.device("192.0.2.2", entry("sw-d", management=("192.0.2.4",)))
    lab.device("192.0.2.3", entry("sw-d", management=("192.0.2.4",)))
    lab.device("192.0.2.4", entry("sw-a", management=(str(SEED),)))

    result = lab.crawl()

    assert lab.network.dialled.count(IPv4Address("192.0.2.4")) == 1
    assert lab.network.dialled.count(SEED) == 1
    assert len(result.devices) == 4


def test_lldp_neighbours_are_followed_too(lab: Lab) -> None:
    seed = lab.device(str(SEED))
    seed.replies["show lldp neighbors detail"] = device_text.IOS_XE_LLDP_DETAIL
    lab.device("192.0.2.12", ssh_id="SSH-2.0-OpenSSH_8.8 FIPS")

    result = lab.crawl()

    assert "192.0.2.12" in _ips(result)


# -- The Scope is the fence (stories 66-68) ------------------------------------------------


def test_neighbours_beyond_the_fence_are_recorded_and_never_dialled(lab: Lab) -> None:
    lab.device(
        str(SEED),
        entry("far", management=("198.51.100.7",)),
        entry("kept-out", management=("192.0.2.205",)),
        entry("v6-only", management=("2001:db8::7",)),
        entry("loop", management=("127.0.0.1",)),
    )

    result = lab.crawl()

    assert lab.network.dialled == [SEED]
    assert [u.ip for u in _unvisited(result, UnvisitedReason.OUTSIDE_SCOPE)] == [
        IPv4Address("198.51.100.7"),
        IPv4Address("127.0.0.1"),
    ]
    (excluded,) = _unvisited(result, UnvisitedReason.EXCLUDED)
    assert excluded == DeviceRecord(
        IPv4Address("192.0.2.205"),
        DeviceOutcome.UNVISITED,
        unvisited_reason=UnvisitedReason.EXCLUDED,
    )
    assert _unvisited(result, UnvisitedReason.IPV6_ONLY) == []  # no IPv4 address to record
    not_visited = [e for e in lab.events if isinstance(e, NeighbourNotVisited)]
    assert all(e.reported_by == SEED for e in not_visited)
    reasons = [e.reason for e in not_visited]
    assert sorted(reasons) == sorted(
        [
            "outside Scope",
            "outside Scope",
            "excluded by operator",
            "IPv6 only (not supported in v1)",
        ]
    )


def test_an_excluded_address_is_never_used_even_beside_an_allowed_one(lab: Lab) -> None:
    lab.device(str(SEED), entry("sw-b", management=("192.0.2.205", "192.0.2.6")))
    lab.device("192.0.2.6")

    result = lab.crawl()

    assert IPv4Address("192.0.2.205") not in lab.network.dialled
    assert "192.0.2.6" in _ips(result)


def test_the_same_unvisited_device_seen_twice_is_one_record(lab: Lab) -> None:
    lab.device(
        str(SEED),
        entry("far", management=("198.51.100.7",)),
        entry("sw-b", management=("192.0.2.2",)),
    )
    lab.device("192.0.2.2", entry("far", management=("198.51.100.7",)))

    result = lab.crawl()

    (far,) = _unvisited(result, UnvisitedReason.OUTSIDE_SCOPE)
    assert far.ip == IPv4Address("198.51.100.7")


# -- Platform hints (stories 62-64) --------------------------------------------------------


def test_a_neighbour_advertised_as_unsupported_gets_no_login(lab: Lab) -> None:
    lab.device(
        str(SEED),
        entry("SEP00AABBCCDDEE", other=("192.0.2.50",), platform="Cisco IP Phone 8865"),
        entry("fw-a", management=("192.0.2.51",), version="Palo Alto Networks PA-3220"),
    )
    phone = lab.device("192.0.2.50")

    result = lab.crawl()

    assert len(_unvisited(result, UnvisitedReason.UNSUPPORTED_ADVERTISED)) == 2
    assert lab.network.dialled == [SEED]
    assert phone.passwords_received == []


def test_a_neighbour_with_no_hint_needs_a_supported_identification_string(lab: Lab) -> None:
    lab.device(
        str(SEED),
        entry("box-a", management=("192.0.2.60",), platform="Generic", version="Something"),
        entry("box-b", management=("192.0.2.61",), platform="Generic", version="Something"),
    )
    linux = lab.device("192.0.2.60", ssh_id="SSH-2.0-OpenSSH_9.6")
    cisco = lab.device("192.0.2.61")

    result = lab.crawl()

    assert linux.passwords_received == []
    assert cisco.passwords_received == [DEVICE_CANARY]
    (unknown,) = [d for d in result.devices if str(d.ip) == "192.0.2.60"]
    assert unknown.unvisited_reason is UnvisitedReason.UNSUPPORTED_ADVERTISED


def test_a_seed_is_logged_into_whatever_its_identification_string_says(lab: Lab) -> None:
    seed = lab.device(str(SEED), ssh_id="SSH-2.0-OpenSSH_9.6")

    lab.crawl()

    assert seed.passwords_received == [DEVICE_CANARY]


# -- Address choice (story 65) -------------------------------------------------------------


def test_the_management_address_is_tried_first_then_others_after_a_connection_failure(
    lab: Lab,
) -> None:
    lab.device(
        str(SEED),
        entry(
            "sw-b",
            management=("192.0.2.20",),
            other=("192.0.2.21", "192.0.2.22", "192.0.2.23"),
        ),
    )
    lab.device("192.0.2.22")

    result = lab.crawl()

    tried = [str(ip) for ip in lab.network.dialled if ip != SEED]
    assert tried == ["192.0.2.20", "192.0.2.20", "192.0.2.21", "192.0.2.21", "192.0.2.22"]
    assert "192.0.2.22" in _ips(result)


def test_at_most_three_addresses_are_tried(lab: Lab) -> None:
    lab.device(
        str(SEED),
        entry("sw-b", other=("192.0.2.20", "192.0.2.21", "192.0.2.22", "192.0.2.23")),
    )
    lab.device("192.0.2.23")

    result = lab.crawl()

    assert IPv4Address("192.0.2.23") not in lab.network.dialled
    (failed,) = [d for d in result.devices if d.ip != SEED]
    assert failed.unvisited_reason is UnvisitedReason.UNREACHABLE


def test_no_other_address_is_tried_after_an_authentication_failure(lab: Lab) -> None:
    lab.device(str(SEED), entry("sw-b", management=("192.0.2.20", "192.0.2.21")))
    lab.device("192.0.2.20", password=WRONG)
    other = lab.device("192.0.2.21")

    result = lab.crawl()

    assert IPv4Address("192.0.2.21") not in lab.network.dialled
    assert other.passwords_received == []
    (failed,) = [d for d in result.devices if d.ip != SEED]
    assert failed.unvisited_reason is UnvisitedReason.AUTHENTICATION_FAILED


# -- One record per device (stories 73-75) -------------------------------------------------


def test_one_device_reached_at_two_ips_is_one_record_with_an_alias(lab: Lab) -> None:
    seed = lab.device(str(SEED), entry("sw-b", management=("192.0.2.2",)))
    lab.device("192.0.2.2", entry("sw-a", other=("192.0.2.30",)))
    lab.network.add("192.0.2.30", seed)  # the seed again, at another address

    result = lab.crawl()

    (record,) = [d for d in result.devices if d.ip == SEED]
    assert record.aliases == (IPv4Address("192.0.2.30"),)
    assert len(result.devices) == 2
    assert seed.passwords_received == [DEVICE_CANARY]


def test_two_devices_with_the_same_name_stay_two_devices(lab: Lab) -> None:
    first = lab.device(str(SEED), entry("Switch", management=("192.0.2.2",)))
    second = lab.device("192.0.2.2", entry("Switch", management=(str(SEED),)))
    for device, name in ((first, "sw-1"), (second, "sw-2")):
        device.replies["show version"] = device.replies["show version"].replace(name, "Switch")

    result = lab.crawl()

    assert len(result.devices) == 2
    assert all(not d.aliases for d in result.devices)
    assert all(d.outcome is DeviceOutcome.VISITED for d in result.devices)


def test_a_stack_is_one_device_and_vpc_peers_are_two(lab: Lab) -> None:
    lab.device(
        str(SEED),
        entry("nx-1", management=("192.0.2.41",)),
        entry("nx-2", management=("192.0.2.42",)),
    )
    for ip in ("192.0.2.41", "192.0.2.42"):
        lab.device(ip)

    result = lab.crawl()

    stack = next(d for d in result.devices if d.ip == SEED)
    assert stack.version is not None
    assert isinstance(stack.version.serials, tuple)
    assert len(stack.version.serials) == 2  # two members, one device
    assert len(result.devices) == 3


# -- The pool (story 49) -------------------------------------------------------------------


def test_no_more_than_the_parallel_limit_run_at_once(lab: Lab) -> None:
    lab.device(str(SEED), *(entry(f"sw-{n}", management=(f"192.0.2.{n}",)) for n in range(2, 9)))
    for n in range(2, 9):
        lab.device(f"192.0.2.{n}")
    lock = threading.Lock()
    running = [0]
    most = [0]
    real = lab.visit

    def counted(
        ip: IPv4Address, *, id_gate: bool, neighbour_hint: Platform | None, identity: Identity
    ) -> DeviceRecord | Alias:
        with lock:
            running[0] += 1
            most[0] = max(most[0], running[0])
        time.sleep(0.02)
        try:
            return real(ip, id_gate=id_gate, neighbour_hint=neighbour_hint, identity=identity)
        finally:
            with lock:
                running[0] -= 1

    result = discovery.crawl([SEED], counted, scope=lab.scope, parallel=3, emit=lab.events.append)

    assert len(result.devices) == 8
    assert most[0] == 3


# -- Stopping (#49 follow-up) --------------------------------------------------------------


def test_a_trust_store_that_cannot_be_written_stops_new_logins(lab: Lab, tmp_path: Path) -> None:
    lab.device(str(SEED))
    lab.device("192.0.2.2")
    (tmp_path / "trust").write_text("", encoding="utf-8")  # a file where its folder goes

    result = lab.crawl(str(SEED), "192.0.2.2", parallel=1)

    assert result.stopped == device_gateway.TRUST_STORE_UNWRITABLE
    assert lab.network.dialled == [SEED]
    assert result.devices[0].unvisited_reason is UnvisitedReason.RUN_STOPPED
    assert result.unvisited == (
        DeviceRecord(
            IPv4Address("192.0.2.2"),
            DeviceOutcome.UNVISITED,
            unvisited_reason=UnvisitedReason.RUN_STOPPED,
        ),
    )


# -- Ctrl+C (#56; stories 82-83) -----------------------------------------------------------


def test_the_first_ctrl_c_starts_no_new_visit_and_records_the_queue_as_stopped(
    lab: Lab,
) -> None:
    seed = lab.device(
        str(SEED),
        entry("sw-b", management=("192.0.2.2",)),
        entry("sw-c", management=("192.0.2.3",)),
    )
    seed.when_sent["show running-config view full"] = lab.stop.stop_gracefully
    lab.device("192.0.2.2")
    lab.device("192.0.2.3")

    result = lab.crawl()

    assert result.stopped == discovery.STOPPED_BY_CTRL_C
    assert lab.network.dialled == [SEED]
    assert result.devices[0].outcome is DeviceOutcome.VISITED  # its session finished
    stopped = _unvisited(result, UnvisitedReason.RUN_STOPPED)
    assert sorted(str(u.ip) for u in stopped) == ["192.0.2.2", "192.0.2.3"]
    reasons = [e.reason for e in lab.events if isinstance(e, NeighbourNotVisited)]
    assert reasons == ["not attempted (Run stopped)"] * 2


def test_seeds_still_queued_at_the_first_ctrl_c_are_recorded_as_stopped(lab: Lab) -> None:
    lab.device(str(SEED)).when_sent["show version"] = lab.stop.stop_gracefully
    lab.device("192.0.2.2")

    result = lab.crawl(str(SEED), "192.0.2.2", parallel=1)

    assert lab.network.dialled == [SEED]
    assert [str(u.ip) for u in _unvisited(result, UnvisitedReason.RUN_STOPPED)] == ["192.0.2.2"]


def test_the_crawl_ticks_with_how_many_devices_are_queued(lab: Lab) -> None:
    lab.device(str(SEED))
    lab.device("192.0.2.2")

    lab.crawl(str(SEED), "192.0.2.2", parallel=1)

    assert lab.ticks
    assert lab.ticks[0] == 1  # one Seed waits while the first is visited
    assert lab.ticks[-1] == 0


def test_a_trust_store_that_cannot_be_written_also_stops_visits_under_way(
    lab: Lab, tmp_path: Path
) -> None:
    lab.device(str(SEED))
    (tmp_path / "trust").write_text("", encoding="utf-8")

    lab.crawl(str(SEED), parallel=1)

    assert lab.stop.requested


# -- Credential Sets (#54; stories 32, 37) -------------------------------------------------


def test_once_every_set_is_retired_the_crawl_stops_and_records_the_queue(lab: Lab) -> None:
    neighbours = [f"192.0.2.{n}" for n in range(2, 7)]
    lab.device(str(SEED), *(entry(f"sw-{ip}", management=(ip,)) for ip in neighbours))
    for ip in neighbours:
        lab.device(ip, password=WRONG)

    result = lab.crawl(parallel=1)

    assert result.stopped == discovery.ALL_SETS_RETIRED
    assert lab.network.dialled == [SEED, *(IPv4Address(ip) for ip in neighbours[:3])]
    tried = [d.unvisited_reason for d in result.devices if d.ip != SEED]
    assert tried == [UnvisitedReason.AUTHENTICATION_FAILED] * 3
    assert result.unvisited == tuple(
        DeviceRecord(
            IPv4Address(ip), DeviceOutcome.UNVISITED, unvisited_reason=UnvisitedReason.SETS_RETIRED
        )
        for ip in neighbours[3:]
    )


def test_a_neighbours_platform_hint_is_handed_to_its_visit(lab: Lab) -> None:
    nexus = entry(
        "nx-b",
        management=("192.0.2.2",),
        platform="N9K-C93180YC-EX",
        version="Cisco Nexus Operating System (NX-OS) Software, Version 9.3(8)",
    )
    unknown = entry("sw-c", management=("192.0.2.3",), platform="unknown box", version="")
    lab.device(str(SEED), nexus, unknown)
    lab.device("192.0.2.2")
    lab.device("192.0.2.3")
    hints: dict[IPv4Address, Platform | None] = {}
    real = lab.visit

    def noted(
        ip: IPv4Address, *, id_gate: bool, neighbour_hint: Platform | None, identity: Identity
    ) -> DeviceRecord | Alias:
        hints[ip] = neighbour_hint
        return real(ip, id_gate=id_gate, neighbour_hint=neighbour_hint, identity=identity)

    discovery.crawl([SEED], noted, scope=lab.scope, parallel=1, emit=lab.events.append)

    assert hints == {
        SEED: None,
        IPv4Address("192.0.2.2"): Platform.NX_OS,
        IPv4Address("192.0.2.3"): None,
    }
