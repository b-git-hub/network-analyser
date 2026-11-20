"""Ctrl+C during a confirmed Run (ticket #56; stories 82-85, 90).

Driven through `main(["run", ...])`; a fake device calls the SIGINT handler the Run has
installed, exactly as the interpreter would when the operator presses Ctrl+C, so no real
signal is raised in the test process.
"""

import json
import signal
import time
from ipaddress import IPv4Address

import pytest

from network_analyser import discovery
from network_analyser.cli import ExitCode
from tests.support import device_text, fake_age
from tests.support.fake_device import FakeDevice, synthetic_key
from tests.support.run_driver import FLAGS, Runner, data_folder, first_run

NEIGHBOUR = """\
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

"""


def _press_ctrl_c() -> None:
    handler = signal.getsignal(signal.SIGINT)
    assert callable(handler)
    handler(signal.SIGINT, None)


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    runner = Runner(monkeypatch, capsys)
    runner.seed.replies["show cdp neighbors detail"] = NEIGHBOUR
    neighbour = runner.network.add(
        "192.0.2.2", FakeDevice(prompt="sw-b#", host_key=synthetic_key(filler=8))
    )
    neighbour.replies["show version"] = device_text.IOL_SHOW_VERSION
    return runner


def _run_folder_files() -> set[str]:
    (folder,) = sorted(data_folder().runs.iterdir())
    return {p.name for p in folder.iterdir()}


def _run_folder_text(name: str) -> str:
    (folder,) = sorted(data_folder().runs.iterdir())
    return (folder / name).read_text(encoding="utf-8")


def _audit() -> list[dict[str, object]]:
    (folder,) = sorted(data_folder().runs.iterdir())
    text = (folder / "audit.log").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def test_the_first_ctrl_c_lets_the_session_finish_and_queues_nothing_new(run: Runner) -> None:
    def press_then_give_the_main_thread_a_tick() -> None:
        _press_ctrl_c()
        time.sleep(discovery.TICK_S * 3)

    run.seed.when_sent["show privilege"] = press_then_give_the_main_thread_a_tick

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.STOPPED
    assert run.network.dialled == [IPv4Address("192.0.2.1")]
    assert "Stopping: no new logins will start. Waiting for 1 session" in got.out
    assert "Run STOPPED by Ctrl+C after" in got.out
    assert "        1  not attempted (Run stopped)" in got.out
    assert "Visited      1   Backups locked 1" in got.out
    lines = _audit()
    (pressed,) = [line for line in lines if line["event"] == "ctrl_c_pressed"]
    assert pressed["press"] == 1
    assert pressed["sessions_running"] == 1
    assert lines[-1]["event"] == "run_ended"
    assert lines[-1]["ended"] == "stopped"
    assert lines[-1]["backups_written"] == 1  # not 0 (#51 follow-up)
    assert {"topology.json", "diagram.html", "run-report.html"} <= _run_folder_files()
    report = _run_folder_text("run-report.html")
    assert "ended: stopped" in report
    assert "<script" not in report.lower()


def test_the_second_ctrl_c_closes_the_session_and_leaves_the_device_partial(
    run: Runner,
) -> None:
    def second_press_then_wait_for_the_close() -> None:
        _press_ctrl_c()
        deadline = time.monotonic() + 5
        while run.seed.open_links and time.monotonic() < deadline:
            time.sleep(0.01)  # the main thread closes the session at its next tick

    run.seed.when_sent["show privilege"] = _press_ctrl_c
    run.seed.when_sent["show cdp neighbors detail"] = second_press_then_wait_for_the_close

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.STOPPED
    assert "Closing 1 session now." in got.out
    assert "Visited      1   Backups locked 0, partial 1, Backup not taken 1" in got.out
    presses = [line["press"] for line in _audit() if line["event"] == "ctrl_c_pressed"]
    assert presses == [1, 2]
    assert run.seed.open_links == 0
    assert "topology.json" in _run_folder_files()


def test_the_full_paths_are_printed_last(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run())

    (folder,) = sorted(data_folder().runs.iterdir())
    tail = got.out.rstrip("\n").splitlines()[-3:]
    assert tail == [
        f"Run folder  {folder}",
        f"Diagram     {folder / 'diagram.html'}",
        f"Run report  {folder / 'run-report.html'}",
    ]
