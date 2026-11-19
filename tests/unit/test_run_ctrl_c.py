"""Ctrl+C during a Run, end to end (ticket #56; stories 79-90).

Driven through `main(["run", ...])` with what the operator types; the devices are fakes at
the `device_gateway` seam. No real signal is sent: the Ctrl+C handler `cli.signals` sets
is caught by a stand-in for `signal.signal`, and a fake device calls it mid-command, the
way Python would call it on the main thread.
"""

import json
import re
import signal

import pytest

from network_analyser.cli import ExitCode, signals
from tests.support import device_text, fake_age
from tests.support.fake_device import DEVICE_CANARY, FakeDevice, synthetic_key
from tests.support.run_driver import BACKUP_CANARY, FLAGS, Runner, data_folder, first_run

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


class Signals:
    """Stands in for `signal.signal` inside `cli.signals`; `press` calls the handler set."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.handler: signals.Handler = signal.default_int_handler
        monkeypatch.setattr(signals, "_install", self.install)

    def install(self, _signum: int, handler: signals.Handler) -> signals.Handler:
        previous, self.handler = self.handler, handler
        return previous

    def press(self) -> None:
        handler = self.handler
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


@pytest.fixture
def ctrl_c(monkeypatch: pytest.MonkeyPatch) -> Signals:
    return Signals(monkeypatch)


def _folder_files() -> tuple[list[dict[str, object]], set[str]]:
    (folder,) = sorted(data_folder().runs.iterdir())
    text = (folder / "audit.log").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()], {p.name for p in folder.iterdir()}


def test_the_first_ctrl_c_finishes_the_open_session_and_writes_every_output(
    run: Runner, ctrl_c: Signals
) -> None:
    run.seed.when_sent["show running-config view full"] = ctrl_c.press

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.STOPPED
    assert run.network.dialled == [run.network.dialled[0]]  # the neighbour is never dialled
    assert "Stopping: no new logins or probes. Waiting on 1 session to finish." in got.out
    assert "Run stopped by the operator (Ctrl+C)." in got.out
    assert "Visited: 1 (Backups locked: 1, partial: 0, Backup not taken: 0)" in got.out
    assert "not attempted (Run stopped): 1" in got.out
    lines, files = _folder_files()
    pressed = [line for line in lines if line["event"] == "ctrl_c_pressed"]
    assert [(p["press"], p["sessions_running"]) for p in pressed] == [(1, 1)]
    ended = lines[-1]
    assert ended["event"] == "run_ended"
    assert ended["ended"] == "stopped"
    assert ended["devices_visited"] == 1
    assert ended["backups_written"] == 1  # #51 follow-up: counted on Ctrl+C too
    assert {"topology.json", "diagram.html", "audit.log"} <= files
    assert DEVICE_CANARY not in got.out
    assert BACKUP_CANARY not in got.out


def test_the_second_ctrl_c_closes_the_session_and_keeps_the_device_partial(
    run: Runner, ctrl_c: Signals
) -> None:
    def twice() -> None:
        ctrl_c.press()
        ctrl_c.press()

    run.seed.when_sent["show cdp neighbors detail"] = twice

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.STOPPED
    assert "Visited: 1 (Backups locked: 0, partial: 1, Backup not taken: 0)" in got.out
    lines, files = _folder_files()
    pressed = [(p["press"], p["sessions_running"]) for p in lines if p["event"] == "ctrl_c_pressed"]
    assert [press for press, _running in pressed] == [1, 2]
    assert "topology.json" in files
    assert run.seed.open_links == 0


def test_the_full_paths_come_last(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.CLEAN
    (folder,) = sorted(data_folder().runs.iterdir())
    tail = got.out.rstrip("\n").splitlines()[-3:]
    assert tail[0] == f"Run folder:      {folder}"
    assert tail[1] == f"diagram.html:    {folder / 'diagram.html'}"
    assert tail[2] == "run-report.html: not written"


def test_redirected_output_gets_the_log_with_a_locking_line(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run())

    assert re.search(
        r"^\d\d:\d\d:\d\dZ connection_attempted ip=192\.0\.2\.1 ", got.out, re.MULTILINE
    )
    assert re.search(r"^\d\d:\d\d:\d\dZ Locking the Backup of 192\.0\.2\.1", got.out, re.MULTILINE)
    assert "\x1b[" not in got.out  # no cursor codes in a redirected file
