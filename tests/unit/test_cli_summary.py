"""The final summary and the exit code (ticket #56; stories 87-90).

Built from a `CrawlResult` and `BackupResults` like those the crawl and the locking worker
hand back. All addresses are RFC 5737 and all names synthetic.
"""

from ipaddress import IPv4Address
from pathlib import Path

from network_analyser import device_gateway, discovery, run_output
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
from network_analyser.records.events import DeviceOutcome
from tests.support.fake_device import synthetic_key

SET = CredentialSetView(1, "netops-ro", None)


def _visited(
    last: int, outcome: DeviceOutcome = DeviceOutcome.VISITED, **more: object
) -> DeviceRecord:
    return DeviceRecord(
        IPv4Address(f"192.0.2.{last}"),
        outcome,
        credential_set=SET,
        platform=more.pop("platform", Platform.IOS_XE),  # type: ignore[arg-type]
        **more,  # type: ignore[arg-type]
    )


def _unvisited(last: int, reason: UnvisitedReason, **more: object) -> DeviceRecord:
    return DeviceRecord(
        IPv4Address(f"192.0.2.{last}"),
        DeviceOutcome.UNVISITED,
        unvisited_reason=reason,
        **more,  # type: ignore[arg-type]
    )


def _backups(*lasts: int) -> BackupResults:
    return BackupResults(
        backups=tuple(
            BackupRecord(
                IPv4Address(f"192.0.2.{last}"),
                f"sw-{last}",
                f"C:/runs/r1/backups/sw-{last}.cfg.age",
                "ab" * 32,
                18,
                0.5,
            )
            for last in lasts
        ),
        lock_seconds=1.0,
        manifest_path="C:/runs/r1/backups/manifest.age",
        manifest_problem=None,
    )


def _changed_key(last: int) -> DeviceRecord:
    check = HostKeyCheck(
        IPv4Address(f"192.0.2.{last}"),
        22,
        HostKeyVerdict.CHANGED,
        synthetic_key(filler=9),
        ("SHA256:old-fingerprint",),
    )
    return _unvisited(last, UnvisitedReason.HOST_KEY_CHANGED, host_key=check)


def test_a_clean_run_has_a_clean_outcome_and_exit_code_0() -> None:
    result = CrawlResult(
        devices=(_visited(1), _visited(2)),
        unvisited=(_unvisited(99, UnvisitedReason.OUTSIDE_SCOPE),),
        credential_sets=(CredentialSetResult(SET, 2, 0, retired=False),),
    )

    shown = summary.final_summary(result, _backups(1, 2))

    assert shown.splitlines()[0] == "Run finished: nothing needs your attention."
    assert "Visited: 2 (Backups locked: 2, partial: 0, Backup not taken: 0)" in shown
    assert "Unvisited: 1\n  outside Scope: 1" in shown
    assert "Set 1 (netops-ro): 2 worked, 0 failed" in shown
    assert "Needs your attention" not in shown
    assert "%" not in shown
    assert summary.exit_code(result, _backups(1, 2), scan_hits=0) is ExitCode.CLEAN


def test_reasons_needing_attention_are_marked_and_listed_first() -> None:
    result = CrawlResult(
        devices=(_visited(1), _changed_key(7), _unvisited(8, UnvisitedReason.UNREACHABLE)),
        unvisited=(
            _unvisited(98, UnvisitedReason.OUTSIDE_SCOPE),
            _unvisited(99, UnvisitedReason.OUTSIDE_SCOPE),
        ),
    )

    shown = summary.final_summary(result, _backups(1))

    assert shown.splitlines()[0] == "Run finished: some things need your attention (below)."
    assert (
        "Unvisited: 4\n  !! unreachable: 1\n  !! host key changed: 1\n  outside Scope: 2" in shown
    )
    assert summary.exit_code(result, _backups(1), scan_hits=0) is ExitCode.NEEDS_ATTENTION


def test_each_attention_item_has_its_next_step() -> None:
    retired = CredentialSetResult(CredentialSetView(2, "nx-ro", Platform.NX_OS), 0, 3, retired=True)
    nexus = _visited(3, platform=Platform.NX_OS)
    result = CrawlResult(
        devices=(_visited(1), _changed_key(7), _visited(2), nexus),
        credential_sets=(CredentialSetResult(SET, 3, 0, retired=False), retired),
    )

    shown = summary.final_summary(result, _backups(1))

    attention = shown[shown.index("Needs your attention:") :]
    assert "network-analyser trust-key 192.0.2.7 --fingerprint SHA256:" in attention
    assert "!! 192.0.2.2: Backup not taken" in attention
    assert "network-analyser role-snippet ios-xe" in attention
    assert "network-analyser role-snippet nx-os" in attention
    assert "check the password and each device's AAA lockout counter" in attention
    assert all(line.startswith(("  !! ", "      ")) for line in attention.splitlines()[1:])


def test_new_host_keys_are_counted() -> None:
    check = HostKeyCheck(IPv4Address("192.0.2.1"), 22, HostKeyVerdict.NEW, synthetic_key(), ())
    result = CrawlResult(devices=(_visited(1, host_key=check),))

    shown = summary.final_summary(result, _backups(1))

    assert "New host keys trusted on first use: 1." in shown


def test_a_run_stopped_with_ctrl_c_says_so_and_exits_3() -> None:
    stopped = _visited(2, DeviceOutcome.PARTIAL, partial_reason=device_gateway.CLOSED_BY_OPERATOR)
    result = CrawlResult(
        devices=(_visited(1), stopped),
        unvisited=(_unvisited(5, UnvisitedReason.RUN_STOPPED),),
        stopped=discovery.STOPPED_BY_CTRL_C,
    )

    shown = summary.final_summary(result, _backups(1))

    assert shown.splitlines()[0] == "Run stopped by the operator (Ctrl+C)."
    assert "not attempted (Run stopped): 1" in shown
    assert "Check the disk" not in shown  # not a Trust Store failure
    assert "192.0.2.2: Backup not taken" not in shown  # closed by the operator, not denied
    assert summary.exit_code(result, _backups(1), scan_hits=0) is ExitCode.STOPPED


def test_a_trust_store_stop_keeps_its_own_next_step() -> None:
    result = CrawlResult(devices=(_visited(1),), stopped=device_gateway.TRUST_STORE_UNWRITABLE)

    shown = summary.final_summary(result, _backups(1))

    assert shown.splitlines()[0] == "Run stopped early: the Trust Store could not be written."
    assert "Check the disk" in shown
    assert summary.exit_code(result, _backups(1), scan_hits=0) is ExitCode.STOPPED


def test_secret_scan_hits_need_attention() -> None:
    result = CrawlResult(devices=(_visited(1),))

    assert summary.exit_code(result, _backups(1), scan_hits=1) is ExitCode.NEEDS_ATTENTION


def test_device_text_is_escaped() -> None:
    odd = _visited(4, DeviceOutcome.PARTIAL, partial_reason="cut\x1b[2J")
    result = CrawlResult(devices=(odd,))

    shown = summary.final_summary(result, _backups(4))

    assert "\x1b" not in shown
    assert "cut\\x1b[2J" in shown


def test_the_full_paths_are_printed_at_the_end(tmp_path: Path) -> None:
    folder = run_output.RunFolder(path=tmp_path, io_path=tmp_path)
    (tmp_path / "diagram.html").write_text("<html></html>", encoding="utf-8")

    shown = summary.output_paths(folder)

    assert f"Run folder:      {tmp_path}" in shown
    assert f"diagram.html:    {tmp_path / 'diagram.html'}" in shown
    assert "run-report.html: not written" in shown
