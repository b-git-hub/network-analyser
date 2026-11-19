"""A confirmed Run crawls from its Seed and ends with every device found (ticket #50).

Driven through `main(["run", ...])` with what the operator types; the devices are fakes at
the `device_gateway` seam (tests/support/run_driver).
"""

import errno
import json
from ipaddress import IPv4Address

import pytest

from network_analyser.cli import ExitCode
from network_analyser.trust_store import TrustStore
from tests.support import device_text, fake_age
from tests.support.fake_device import DEVICE_CANARY, FakeDevice, synthetic_key
from tests.support.run_driver import FLAGS, Runner, data_folder, first_run

WRONG = "CANARY-pw-wrong-c4a7"
"""A password the Credential Set does not hold: a synthetic canary."""

NEIGHBOURS = """\
-------------------------
Device ID: sw-b
Entry address(es):
  IP address: 192.0.2.2
Platform: cisco C9300-48P,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/2
Holdtime : 150 sec

Version :
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a

Management address(es):
  IP address: 192.0.2.2

-------------------------
Device ID: rtr-far
Entry address(es):
  IP address: 198.51.100.9
Platform: cisco C8300,  Capabilities: Router
Interface: GigabitEthernet1/0/2,  Port ID (outgoing port): GigabitEthernet0/0/0
Holdtime : 150 sec

Version :
Cisco IOS Software [Cupertino], c8000be Software, Version 17.9.4a

"""


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    runner = Runner(monkeypatch, capsys)
    runner.seed.replies["show cdp neighbors detail"] = NEIGHBOURS
    neighbour = runner.network.add(
        "192.0.2.2", FakeDevice(prompt="sw-b#", host_key=synthetic_key(filler=8))
    )
    neighbour.replies["show version"] = device_text.IOL_SHOW_VERSION
    return runner


def _audit() -> list[dict[str, object]]:
    (folder,) = sorted(data_folder().runs.iterdir())
    text = (folder / "audit.log").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def _topology() -> dict[str, list[dict[str, object]]]:
    (folder,) = sorted(data_folder().runs.iterdir())
    document = json.loads((folder / "topology.json").read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_the_run_crawls_to_a_neighbour_and_lists_what_lies_beyond_the_scope(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.CLEAN
    assert "Visited: 2 (Backups locked: 2, partial: 0, Backup not taken: 0)" in got.out
    assert "Unvisited: 1\n  outside Scope: 1" in got.out
    lines = _audit()
    (not_visited,) = [line for line in lines if line["event"] == "neighbour_not_visited"]
    assert not_visited["addresses"] == ["198.51.100.9"]
    assert not_visited["reason"] == "outside Scope"
    assert lines[-1]["event"] == "run_ended"
    assert lines[-1]["devices_unvisited"] == 1
    topology = _topology()
    (far,) = topology["unvisited"]
    assert far["reason"] == "outside Scope"
    assert far["advertised_ips"] == ["198.51.100.9"]
    assert sorted(str(d["management_ip"]) for d in topology["devices"]) == [
        "192.0.2.1",
        "192.0.2.2",
    ]


def test_one_device_at_two_addresses_is_listed_once_with_its_alias(run: Runner) -> None:
    run.network.devices.pop(next(ip for ip in run.network.devices if str(ip) == "192.0.2.2"))
    run.network.add("192.0.2.2", run.seed)  # the Seed again, at its other address

    got = run(*FLAGS, typed=first_run())

    assert "Visited: 1 (" in got.out
    assert [line["event"] for line in _audit()].count("alias_found") == 1
    (device,) = _topology()["devices"]
    assert device["alias_ips"] == ["192.0.2.2"]


def test_a_trust_store_that_cannot_be_written_stops_the_run(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def full_disk(_store: TrustStore, _check: object) -> None:
        raise OSError(errno.ENOSPC, "no space left")

    monkeypatch.setattr(TrustStore, "password_sent", full_disk)

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.STOPPED
    assert "The Run stopped early: the Trust Store could not be written." in got.out
    assert len(run.network.dialled) == 1  # the Seed only: no further login started
    assert _audit()[-1]["ended"] == "stopped"


def test_a_retired_set_is_announced_at_once_and_the_run_stops_with_each_sets_results(
    run: Runner,
) -> None:
    run.network.devices[IPv4Address("192.0.2.2")].password = WRONG

    got = run(*FLAGS, "--failure-budget", "1", typed=first_run())

    assert got.code == ExitCode.STOPPED
    notice = (
        "Credential Set 1 (netops-ro) is retired after 1 failed login and will not be tried "
        "again this Run. A mistyped password is the usual cause."
    )
    assert notice in got.out
    assert got.out.index(notice) < got.out.index("Run stopped early")
    assert "  !! authentication failed (every eligible set tried): 1" in got.out
    assert "Credential Sets:\n  Set 1 (netops-ro): 1 worked, 1 failed, retired" in got.out
    assert "The Run stopped early: every Credential Set is retired." in got.out
    assert "check the password and each device's AAA lockout counter" in got.out
    (retired,) = [line for line in _audit() if line["event"] == "credential_set_retired"]
    assert retired["username"] == "netops-ro"
    assert retired["credential_set"] == 1
    assert DEVICE_CANARY not in got.out
    assert WRONG not in got.out
