"""Progress during the crawl: live panel, log lines and quiet (ticket #56; stories 77-81).

Driven with Audit log events, as the crawl emits them, a fake clock and a list for the
console, so nothing waits and nothing is printed.
"""

from ipaddress import IPv4Address

import pytest

from network_analyser.cli import progress
from network_analyser.cli.progress import Mode, Progress
from network_analyser.records import CredentialSetView, HostKeyVerdict, Platform
from network_analyser.records.events import (
    BackupWritten,
    ConnectionAttempted,
    ConnectionResult,
    CredentialSetRetired,
    DeviceFinished,
    DeviceIdentified,
    DeviceOutcome,
    HostKeyChecked,
    LoginAttempted,
    LoginResult,
    NeighbourNotVisited,
)

SEED = IPv4Address("192.0.2.1")
OTHER = IPv4Address("192.0.2.2")
SETS = (CredentialSetView(1, "netops-ro", None), CredentialSetView(2, "svc\x1b[2J", None))


class Console:
    def __init__(self) -> None:
        self.chunks: list[str] = []
        self.now = 0.0

    def write(self, text: str) -> None:
        self.chunks.append(text)

    def clock(self) -> float:
        return self.now

    @property
    def text(self) -> str:
        return "".join(self.chunks)

    def take(self) -> str:
        shown, self.chunks = self.text, []
        return shown


@pytest.fixture
def console() -> Console:
    return Console()


def _progress(console: Console, mode: Mode, *, in_place: bool = True) -> Progress:
    return Progress(
        mode,
        sets=SETS,
        parallel=10,
        write=console.write,
        clock=console.clock,
        width=120,
        in_place=in_place,
    )


def _connected(ip: IPv4Address) -> ConnectionAttempted:
    return ConnectionAttempted(ip, 22, ConnectionResult.CONNECTED, retry=False)


@pytest.mark.parametrize(
    ("requested", "live_ok", "chosen"),
    [
        (None, True, Mode.LIVE),
        ("live", True, Mode.LIVE),
        (None, False, Mode.LOG),
        ("live", False, Mode.LOG),  # redirected output never gets escape codes
        ("log", True, Mode.LOG),
        ("quiet", True, Mode.QUIET),
        ("quiet", False, Mode.QUIET),
    ],
)
def test_the_mode_is_log_whenever_output_is_redirected(
    requested: str | None,
    live_ok: bool,  # noqa: FBT001 (a parametrized case)
    chosen: Mode,
) -> None:
    assert progress.choose_mode(requested, live_ok=live_ok) is chosen


def test_the_live_panel_shows_counts_and_each_device_in_progress(console: Console) -> None:
    shown = _progress(console, Mode.LIVE)
    shown.event(_connected(SEED))
    shown.event(HostKeyChecked(SEED, 22, "ssh-ed25519", "SHA256:x", HostKeyVerdict.KNOWN, None))
    shown.event(DeviceFinished(OTHER, DeviceOutcome.VISITED, None))
    console.now = 75

    shown.tick(3)

    panel = console.text
    assert "Elapsed 0:01:15" in panel
    assert "Visited 1" in panel
    assert "In progress 1/10" in panel
    assert "Queued 3" in panel
    assert "192.0.2.1" in panel
    assert "logging in" in panel
    assert "%" not in panel


def test_the_live_panel_is_redrawn_in_place(console: Console) -> None:
    shown = _progress(console, Mode.LIVE)
    shown.tick(0)
    first = console.take()
    console.now = 1

    shown.tick(0)

    lines = first.count("\n")
    assert console.text.startswith(f"\x1b[{lines}F")


def test_the_live_panel_shows_each_sets_state_with_its_username_escaped(
    console: Console,
) -> None:
    shown = _progress(console, Mode.LIVE)
    shown.event(LoginAttempted(SEED, 1, "netops-ro", LoginResult.SUCCEEDED))
    shown.event(CredentialSetRetired(2, "svc\x1b[2J", 3))

    shown.tick(0)

    assert "1 netops-ro: 1 ok" in console.text
    assert "2 svc\\x1b[2J: retired" in console.text
    assert "\x1b[2J" not in console.text


def test_the_live_panel_keeps_the_latest_four_attention_items(console: Console) -> None:
    shown = _progress(console, Mode.LIVE)
    for last in range(10, 16):
        shown.event(
            DeviceFinished(IPv4Address(f"192.0.2.{last}"), DeviceOutcome.UNVISITED, "unreachable")
        )

    shown.tick(0)

    assert "192.0.2.11" not in console.text
    assert all(f"192.0.2.{last}" in console.text for last in range(12, 16))
    assert "Unvisited 6 (6 need attention)" in console.text


def test_backups_waiting_to_be_locked_are_shown(console: Console) -> None:
    shown = _progress(console, Mode.LIVE)
    shown.event(_connected(SEED))
    shown.backup_taken(SEED)
    shown.tick(0)
    assert "Backups locked 0, waiting 1" in console.take()

    shown.event(BackupWritten(SEED, "C:\\runs\\r\\backups\\sw-a.cfg.age", "ab", 18))
    console.now = 1
    shown.tick(0)

    assert "Backups locked 1, waiting 0" in console.text


def test_the_device_handing_over_its_backup_shows_it_is_locking(console: Console) -> None:
    shown = _progress(console, Mode.LIVE)
    shown.event(_connected(SEED))
    shown.event(DeviceIdentified(SEED, Platform.IOS_XE, "level 15"))

    shown.backup_taken(SEED)
    shown.tick(0)

    assert "locking" in console.text


def test_a_locking_line_is_shown_while_backups_still_wait_at_the_end(console: Console) -> None:
    shown = _progress(console, Mode.LOG)
    shown.backup_taken(SEED)
    shown.backup_taken(OTHER)

    shown.finish()

    assert "Locking 2 Backups still waiting" in console.text


def test_no_locking_line_when_nothing_waits(console: Console) -> None:
    shown = _progress(console, Mode.LOG)

    shown.finish()

    assert "Locking" not in console.text


def test_log_mode_prints_one_timestamped_line_per_device_event(console: Console) -> None:
    shown = _progress(console, Mode.LOG, in_place=False)
    console.now = 5

    shown.event(DeviceFinished(SEED, DeviceOutcome.VISITED, None))
    shown.event(NeighbourNotVisited(SEED, (IPv4Address("198.51.100.9"),), "outside Scope"))

    assert console.text.splitlines() == [
        "[0:00:05] OK 192.0.2.1       visited",
        "[0:00:05] -- 198.51.100.9    not visited: outside Scope",
    ]


def test_log_mode_prints_a_status_line_every_minute(console: Console) -> None:
    shown = _progress(console, Mode.LOG, in_place=False)
    console.now = 59
    shown.tick(2)
    assert console.text == ""

    console.now = 60
    shown.tick(2)

    assert console.text == (
        "[0:01:00] .. status: 0 Visited, 0 in progress, 2 queued, 0 Unvisited "
        "(0 need attention), 0 Backups locked, 0 waiting\n"
    )


def test_log_mode_announces_a_retired_set(console: Console) -> None:
    shown = _progress(console, Mode.LOG, in_place=False)

    shown.event(CredentialSetRetired(2, "svc\x1b[2J", 3))

    assert "!! Credential Set 2 (svc\\x1b[2J) is retired after 3 failed logins" in console.text


def test_quiet_mode_prints_only_attention_items(console: Console) -> None:
    shown = _progress(console, Mode.QUIET, in_place=False)

    shown.event(DeviceFinished(SEED, DeviceOutcome.VISITED, None))
    shown.event(DeviceFinished(OTHER, DeviceOutcome.UNVISITED, "host key changed"))
    shown.tick(0)

    assert console.text == "!! 192.0.2.2       unvisited: host key changed\n"


def test_quiet_mode_keeps_one_status_line_in_place_on_a_console(console: Console) -> None:
    shown = _progress(console, Mode.QUIET, in_place=True)

    shown.tick(4)

    assert console.text.startswith("\r")
    assert "Queued 4" in console.text
    assert "\n" not in console.text


def test_the_first_ctrl_c_says_how_many_sessions_it_waits_on(console: Console) -> None:
    shown = _progress(console, Mode.LOG, in_place=False)

    shown.ctrl_c(1, sessions=2)

    assert (
        "** Stopping: no new logins will start. Waiting for 2 sessions in progress to finish"
    ) in console.text
    assert "Press Ctrl+C again to close them now." in console.text


def test_the_second_ctrl_c_says_the_sessions_are_closing(console: Console) -> None:
    shown = _progress(console, Mode.LIVE)

    shown.ctrl_c(2, sessions=1)
    shown.tick(0)

    assert "Closing 1 session now." in console.text


def test_a_partial_reason_is_escaped(console: Console) -> None:
    shown = _progress(console, Mode.LOG, in_place=False)

    shown.event(DeviceFinished(SEED, DeviceOutcome.PARTIAL, "odd\x1b]0;title\x07"))

    assert "\x1b" not in console.text
    assert "\x07" not in console.text
