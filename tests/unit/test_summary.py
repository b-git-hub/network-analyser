"""The final summary at the end of a Run (ticket #56; stories 87-90; #54 for the sets).

Built from plain records: the `CrawlResult`, the `BackupResults` and the Run folder. It
never holds device output, and every username or device text is escaped (story 81).
"""

from ipaddress import IPv4Address
from pathlib import Path

from network_analyser import device_gateway, discovery
from network_analyser.cli import summary
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.records import (
    CredentialSetResult,
    CredentialSetView,
    HostKeyCheck,
    HostKeyVerdict,
    Platform,
)
from network_analyser.records.backup import BackupRecord, BackupResults
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.events import CredentialSetRetired, DeviceOutcome
from network_analyser.run_output import RunFolder
from tests.support.fake_device import synthetic_key

SET_1 = CredentialSetView(1, "netops-ro", None)
NO_BACKUPS = BackupResults(backups=(), lock_seconds=0.0, manifest_path=None, manifest_problem=None)


def _ip(last: int) -> IPv4Address:
    return IPv4Address(f"192.0.2.{last}")


def _visited(last: int, platform: Platform = Platform.IOS_XE, **kw: object) -> DeviceRecord:
    outcome = DeviceOutcome.PARTIAL if "partial_reason" in kw else DeviceOutcome.VISITED
    return DeviceRecord(
        _ip(last),
        outcome,
        credential_set=SET_1,
        platform=platform,
        partial_reason=kw.get("partial_reason"),  # type: ignore[arg-type]  # test helper
    )


def _unvisited(last: int, reason: UnvisitedReason) -> DeviceRecord:
    return DeviceRecord(_ip(last), DeviceOutcome.UNVISITED, unvisited_reason=reason)


def _backups(*lasts: int) -> BackupResults:
    return BackupResults(
        backups=tuple(
            BackupRecord(_ip(n), f"sw-{n}", f"C:\\runs\\r\\backups\\sw-{n}.cfg.age", "ab", 18, 0.5)
            for n in lasts
        ),
        lock_seconds=0.5 * len(lasts),
        manifest_path="C:\\runs\\r\\backups\\manifest.age",
        manifest_problem=None,
    )


def test_a_clean_run_says_nothing_needs_attention_and_exits_0() -> None:
    result = CrawlResult(devices=(_visited(1), _visited(2)))
    backups = _backups(1, 2)

    shown = summary.final_summary(result, backups, elapsed_s=65)

    assert shown.splitlines()[0] == "Run finished in 0:01:05. Nothing needs your attention."
    assert "Visited      2   Backups locked 2" in shown
    assert "Needs your attention" not in shown
    assert summary.exit_code(result, backups, scan_hits=0) is ExitCode.CLEAN


def test_counts_never_a_percentage() -> None:
    result = CrawlResult(devices=(_visited(1), _unvisited(2, UnvisitedReason.UNREACHABLE)))

    assert "%" not in summary.final_summary(result, _backups(1), elapsed_s=1)


def test_visited_counts_show_partial_and_backups_not_taken() -> None:
    result = CrawlResult(
        devices=(
            _visited(1),
            _visited(2, partial_reason=device_gateway.CLOSED_BY_OPERATOR),
            _visited(3, Platform.NX_OS),
        )
    )

    shown = summary.final_summary(result, _backups(1), elapsed_s=1)

    assert "Visited      3   Backups locked 1, partial 1, Backup not taken 2" in shown


def test_unvisited_reasons_that_need_attention_are_marked_and_listed_first() -> None:
    result = CrawlResult(
        devices=(
            _visited(1),
            _unvisited(2, UnvisitedReason.UNSUPPORTED_IDENTIFIED),
            _unvisited(3, UnvisitedReason.UNREACHABLE),
        ),
        unvisited=(
            _unvisited(20, UnvisitedReason.OUTSIDE_SCOPE),
            _unvisited(21, UnvisitedReason.OUTSIDE_SCOPE),
        ),
    )

    lines = summary.final_summary(result, _backups(1), elapsed_s=1).splitlines()

    start = lines.index("Unvisited    4")
    assert lines[start + 1 : start + 4] == [
        "   !!   1  unreachable",
        "        2  outside Scope",
        "        1  unsupported Platform (identified after login)",
    ]


def test_a_changed_host_key_gives_the_exact_trust_key_line_and_exits_1() -> None:
    key = synthetic_key()
    check = HostKeyCheck(_ip(5), 22, HostKeyVerdict.CHANGED, key, ("SHA256:old",))
    record = DeviceRecord(
        _ip(5),
        DeviceOutcome.UNVISITED,
        unvisited_reason=UnvisitedReason.HOST_KEY_CHANGED,
        host_key=check,
    )
    result = CrawlResult(devices=(record,))

    shown = summary.final_summary(result, NO_BACKUPS, elapsed_s=1)

    assert f"network-analyser trust-key 192.0.2.5 --fingerprint {key.fingerprint}" in shown
    assert shown.index("Needs your attention") < shown.index("trust-key")
    assert summary.exit_code(result, NO_BACKUPS, scan_hits=0) is ExitCode.NEEDS_ATTENTION


def test_a_backup_not_taken_points_at_the_platforms_role_snippet() -> None:
    result = CrawlResult(
        devices=(
            _visited(1, partial_reason="the account cannot read the full running config"),
            _visited(2, Platform.NX_OS, partial_reason="a command timed out"),
        )
    )

    shown = summary.final_summary(result, NO_BACKUPS, elapsed_s=1)

    assert '"network-analyser role-snippet ios-xe"' in shown
    assert '"network-analyser role-snippet nx-os"' in shown


def test_a_device_left_by_the_second_ctrl_c_is_not_an_attention_item() -> None:
    stopped = _visited(1, partial_reason=device_gateway.CLOSED_BY_OPERATOR)
    result = CrawlResult(devices=(stopped,), stopped=discovery.STOPPED_BY_CTRL_C)

    assert not summary.needs_attention(result, NO_BACKUPS)


def test_a_run_stopped_by_ctrl_c_says_so_and_exits_3() -> None:
    result = CrawlResult(
        devices=(_visited(1), _unvisited(2, UnvisitedReason.RUN_STOPPED)),
        stopped=discovery.STOPPED_BY_CTRL_C,
    )

    shown = summary.final_summary(result, _backups(1), elapsed_s=3725)

    assert shown.splitlines()[0] == (
        "Run STOPPED by Ctrl+C after 1:02:05. Outputs cover what was found before the stop."
    )
    assert "        1  not attempted (Run stopped)" in shown
    assert summary.exit_code(result, _backups(1), scan_hits=0) is ExitCode.STOPPED


def test_a_run_stopped_by_the_tool_says_why_and_what_to_do() -> None:
    result = CrawlResult(devices=(_visited(1),), stopped=device_gateway.TRUST_STORE_UNWRITABLE)

    shown = summary.final_summary(result, _backups(1), elapsed_s=1)

    assert shown.splitlines()[0] == (
        "Run STOPPED after 0:00:01: the Trust Store could not be written."
    )
    assert "Check the disk holding the per-user data folder" in shown
    assert summary.exit_code(result, _backups(1), scan_hits=0) is ExitCode.STOPPED


def test_a_secret_scan_hit_alone_exits_1() -> None:
    result = CrawlResult(devices=(_visited(1),))

    assert summary.exit_code(result, _backups(1), scan_hits=2) is ExitCode.NEEDS_ATTENTION


def test_new_host_keys_are_counted() -> None:
    check = HostKeyCheck(_ip(1), 22, HostKeyVerdict.NEW, synthetic_key(), ())
    record = DeviceRecord(
        _ip(1),
        DeviceOutcome.VISITED,
        credential_set=SET_1,
        platform=Platform.IOS_XE,
        host_key=check,
    )

    shown = summary.final_summary(CrawlResult(devices=(record,)), _backups(1), elapsed_s=1)

    assert "Host keys trusted for the first time: 1." in shown


def test_each_sets_results_are_listed_in_order() -> None:
    result = CrawlResult(
        devices=(),
        credential_sets=(
            CredentialSetResult(SET_1, 4, 0, retired=False),
            CredentialSetResult(CredentialSetView(2, "svc-nx", Platform.NX_OS), 0, 3, retired=True),
        ),
    )

    shown = summary.final_summary(result, NO_BACKUPS, elapsed_s=1)

    assert (
        "Credential Sets\n"
        "   Set 1 (netops-ro): 4 worked, 0 failed\n"
        "   Set 2 (svc-nx, NX-OS only): 0 worked, 3 failed, retired"
    ) in shown


def test_a_retired_set_needs_attention_with_its_next_step() -> None:
    result = CrawlResult(
        devices=(),
        credential_sets=(
            CredentialSetResult(CredentialSetView(2, "svc-nx", None), 0, 3, retired=True),
        ),
    )

    shown = summary.final_summary(result, NO_BACKUPS, elapsed_s=1)

    assert summary.needs_attention(result, NO_BACKUPS)
    assert (
        "Credential Set 2 (svc-nx) was retired after 3 failed logins. A mistyped password is "
        "the usual cause: check the password and each device's AAA lockout counter, then run "
        "again."
    ) in shown


def test_usernames_are_escaped() -> None:
    result = CrawlResult(
        devices=(),
        credential_sets=(
            CredentialSetResult(CredentialSetView(1, "ops\x1b[2J", None), 1, 0, retired=False),
        ),
    )

    shown = summary.final_summary(result, NO_BACKUPS, elapsed_s=1)

    assert "\x1b" not in shown
    assert "ops\\x1b[2J" in shown


def test_the_retirement_notice_names_the_set_and_escapes_its_username() -> None:
    notice = summary.retirement_notice(CredentialSetRetired(3, "ops\x1b[2J", 2))

    assert notice == (
        "Credential Set 3 (ops\\x1b[2J) is retired after 2 failed logins and will not be "
        "tried again this Run. A mistyped password is the usual cause."
    )


def test_backup_problems_are_attention_items() -> None:
    backups = BackupResults(
        backups=(BackupRecord(_ip(1), "sw-1", None, None, None, 0.1, "not written"),),
        lock_seconds=0.1,
        manifest_path=None,
        manifest_problem="manifest.age could not be written",
    )
    result = CrawlResult(devices=(_visited(1),))

    shown = summary.final_summary(result, backups, elapsed_s=1)

    assert "192.0.2.1: not written. Check the disk the Run folder is on." in shown
    assert summary.exit_code(result, backups, scan_hits=0) is ExitCode.NEEDS_ATTENTION


def test_where_to_look_gives_full_paths_of_what_was_written(tmp_path: Path) -> None:
    folder = RunFolder(path=tmp_path, io_path=tmp_path)
    (tmp_path / "diagram.html").write_text("", encoding="utf-8")

    shown = summary.where_to_look(folder)

    assert f"Run folder  {tmp_path}" in shown
    assert f"Diagram     {tmp_path / 'diagram.html'}" in shown
    assert "run-report.html" not in shown  # not written by this Run


def test_where_to_look_lists_the_run_report_once_it_exists(tmp_path: Path) -> None:
    folder = RunFolder(path=tmp_path, io_path=tmp_path)
    (tmp_path / "run-report.html").write_text("", encoding="utf-8")

    shown = summary.where_to_look(folder)

    assert f"Run report  {tmp_path / 'run-report.html'}" in shown
    assert "Diagram" not in shown
