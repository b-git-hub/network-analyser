r"""Live progress during the crawl: panel, log and quiet modes (ticket #56; stories 77-81).

Driven with Audit log events, as the crawl's visits emit them, into a `Progress` writing to
a string, with a fake clock. Device and operator text is escaped (`\x1b`); counts are shown,
never a percentage.
"""

import io
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from network_analyser.cli import progress
from network_analyser.cli.progress import Mode, Progress
from network_analyser.records import CredentialSetView, Platform
from network_analyser.records.events import (
    BackupWritten,
    CommandResult,
    CommandSent,
    ConnectionAttempted,
    ConnectionResult,
    CredentialSetRetired,
    CtrlCPressed,
    DeviceFinished,
    DeviceIdentified,
    DeviceOutcome,
    LoginAttempted,
    LoginResult,
    NeighbourNotVisited,
)

A = IPv4Address("192.0.2.10")
B = IPv4Address("192.0.2.11")
C = IPv4Address("192.0.2.12")
ESC = "\x1b"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.wall = datetime(2026, 11, 19, 10, 0, 0, tzinfo=UTC)

    def __call__(self) -> float:
        return self.now

    def utc(self) -> datetime:
        return self.wall

    def advance(self, seconds: float) -> None:
        self.now += seconds
        self.wall += timedelta(seconds=seconds)


def _views() -> tuple[CredentialSetView, ...]:
    return (
        CredentialSetView(1, "netops-ro", None),
        CredentialSetView(2, "nx-ro", Platform.NX_OS),
    )


def _progress(mode: Mode) -> tuple[Progress, io.StringIO, Clock]:
    out = io.StringIO()
    clock = Clock()
    shown = Progress(out, mode, sets=_views(), clock=clock, utc=clock.utc)
    return shown, out, clock


def _busy_run(shown: Progress) -> None:
    shown.event(ConnectionAttempted(A, 22, ConnectionResult.CONNECTED, retry=False))
    shown.event(LoginAttempted(A, 1, "netops-ro", LoginResult.SUCCEEDED))
    shown.event(DeviceIdentified(A, Platform.IOS_XE, "level 15"))
    shown.event(CommandSent(A, "show cdp neighbors detail", 120, 900, CommandResult.OK))
    shown.event(ConnectionAttempted(B, 22, ConnectionResult.CONNECTED, retry=False))
    shown.event(LoginAttempted(B, 1, "netops-ro", LoginResult.SUCCEEDED))
    shown.event(DeviceFinished(B, DeviceOutcome.VISITED, None))
    shown.event(BackupWritten(B, "C:/runs/r1/backups/sw-b.cfg.age", "ab" * 32, 18))
    shown.event(DeviceFinished(C, DeviceOutcome.UNVISITED, "host key changed"))
    shown.event(NeighbourNotVisited(B, (IPv4Address("198.51.100.9"),), "outside Scope"))


# -- Choosing the mode (story 79) ----------------------------------------------------------


def test_the_panel_is_the_default_on_a_console() -> None:
    assert progress.choose_mode(None, is_console=True) is Mode.LIVE
    assert progress.choose_mode("log", is_console=True) is Mode.LOG
    assert progress.choose_mode("quiet", is_console=True) is Mode.QUIET


def test_log_mode_is_used_when_output_is_redirected() -> None:
    assert progress.choose_mode(None, is_console=False) is Mode.LOG
    assert progress.choose_mode("live", is_console=False) is Mode.LOG
    assert progress.choose_mode("quiet", is_console=False) is Mode.QUIET


# -- The live panel (stories 77-78) --------------------------------------------------------


def test_the_panel_shows_counts_devices_in_progress_and_sets() -> None:
    shown, out, clock = _progress(Mode.LIVE)
    _busy_run(shown)
    clock.advance(65)

    shown.tick(3)

    panel = out.getvalue()
    assert "0:01:05 elapsed" in panel
    assert "Visited 1 | In progress 1 | Queued 3 | Unvisited 2" in panel
    assert "Backups: 1 locked, 0 waiting" in panel
    assert "Set 1 (netops-ro): 2 worked, 0 failed" in panel
    assert "Set 2 (nx-ro, NX-OS only): 0 worked, 0 failed" in panel
    assert "192.0.2.10" in panel
    assert "show cdp neighbors detail" in panel
    assert "!! 192.0.2.12: host key changed" in panel
    assert "%" not in panel  # counts, never a percentage


def test_the_panel_is_redrawn_in_place() -> None:
    shown, out, clock = _progress(Mode.LIVE)
    shown.tick(0)
    drawn = out.getvalue().count("\n")
    clock.advance(1.5)

    shown.tick(0)

    assert f"{ESC}[{drawn}F{ESC}[J" in out.getvalue()


def test_the_panel_keeps_the_latest_four_attention_items() -> None:
    shown, out, _clock = _progress(Mode.LIVE)
    for last in range(20, 26):
        ip = IPv4Address(f"192.0.2.{last}")
        shown.event(DeviceFinished(ip, DeviceOutcome.UNVISITED, "unreachable"))

    shown.tick(0)

    panel = out.getvalue()
    assert "192.0.2.21" not in panel
    assert all(f"192.0.2.{last}" in panel for last in range(22, 26))


def test_the_first_ctrl_c_shows_a_banner_with_the_sessions_waited_on() -> None:
    shown, out, _clock = _progress(Mode.LIVE)

    shown.event(CtrlCPressed(press=1, sessions_running=2))
    shown.tick(0)

    text = out.getvalue()
    assert "Stopping: no new logins or probes. Waiting on 2 sessions to finish" in text
    assert "Press Ctrl+C again to close them at once." in text


def test_a_static_line_is_printed_before_each_lock() -> None:
    shown, out, _clock = _progress(Mode.LIVE)
    shown.tick(0)

    shown.locking(A)

    assert "Locking the Backup of 192.0.2.10" in out.getvalue()
    assert "Backups: 0 locked, 1 waiting" in out.getvalue()


# -- Log and quiet modes (story 79) --------------------------------------------------------


def test_log_mode_prints_one_timestamped_line_per_event_and_a_status_each_minute() -> None:
    shown, out, clock = _progress(Mode.LOG)
    shown.event(ConnectionAttempted(A, 22, ConnectionResult.CONNECTED, retry=False))
    shown.event(DeviceFinished(A, DeviceOutcome.VISITED, None))
    shown.tick(0)
    lines = out.getvalue().splitlines()
    assert len(lines) == 2
    assert all(line.startswith("10:00:00Z ") for line in lines)
    assert "192.0.2.10" in lines[0]

    clock.advance(61)
    shown.tick(4)

    status = out.getvalue().splitlines()[-1]
    assert status.startswith("10:01:01Z Status: ")
    assert "Visited 1 | In progress 0 | Queued 4 | Unvisited 0" in status
    assert ESC not in out.getvalue()


def test_quiet_mode_prints_attention_items_and_one_status_line() -> None:
    shown, out, clock = _progress(Mode.QUIET)
    _busy_run(shown)
    clock.advance(120)
    shown.tick(0)

    shown.finish()

    lines = out.getvalue().splitlines()
    assert lines[0] == "!! 192.0.2.12: host key changed"
    assert len(lines) == 2
    assert lines[1].startswith("Status: ")


# -- Escaping (story 81) -------------------------------------------------------------------


def test_device_and_operator_text_is_escaped_in_every_mode() -> None:
    for mode in Mode:
        shown, out, _clock = _progress(mode)
        shown.event(CredentialSetRetired(1, f"ops{ESC}[2J", 3))
        shown.event(DeviceFinished(A, DeviceOutcome.PARTIAL, f"cut{ESC}]0;evil"))
        shown.tick(0)
        shown.finish()

        text = out.getvalue()
        assert "ops\\x1b[2J" in text
        assert f"{ESC}[2J" not in text
        assert f"{ESC}]0;" not in text
