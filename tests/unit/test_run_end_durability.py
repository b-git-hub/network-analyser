"""The Run end: a stopped Run never goes online, and no outage costs it its outputs (#143).

Driven through `main(["run", ...])` with the fake device and the fake Cisco at the
`advisories` transport seam. The secrets, PIDs and replies are synthetic.
"""

import json
import signal
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from network_analyser import backup_store, discovery, run_output
from network_analyser.cli import ExitCode, run_analysis
from network_analyser.credentials import Secret
from network_analyser.records.analysis import CiscoAnswers
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import AnalysisResults, Topology
from tests.support import fake_age
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco
from tests.support.run_driver import (
    BACKUP_CANARY,
    FLAGS,
    Runner,
    data_folder,
    first_run,
    later_run,
)

PASS = BACKUP_CANARY
SET_AT = datetime(2026, 11, 21, 9, 0, 0, tzinfo=UTC)
NO_KEY = "No Cisco API key is stored"


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    return Runner(monkeypatch, capsys)


def _store_key() -> None:
    """Store a synthetic key as `cisco-key set` would, under the passphrase tests type."""
    data = data_folder()
    passphrase = backup_store.create_check_file(data.check_file, Secret(PASS))
    backup_store.lock_key_file(
        data.cisco_key_file,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        passphrase,
        set_at=SET_AT,
    )


def _serve(monkeypatch: pytest.MonkeyPatch, fake: FakeCisco) -> FakeCisco:
    monkeypatch.setattr(
        "network_analyser.advisories.session.HttpsTransport", lambda **_kwargs: fake
    )
    return fake


def _run_folder() -> Path:
    (folder,) = sorted(data_folder().runs.iterdir())
    return folder


def _audit(folder: Path) -> list[dict[str, Any]]:
    text = (folder / "audit.log").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def _topology(folder: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((folder / "topology.json").read_text(encoding="utf-8"))
    return loaded


def _synthetic_advisory() -> dict[str, Any]:
    return {
        "advisoryId": "cisco-sa-test-143",
        "advisoryTitle": "Synthetic advisory",
        "sir": "High",
        "cvssBaseScore": "8.6",
        "cves": ["CVE-2026-0143"],
        "firstPublished": "2026-01-01T00:00:00",
        "lastUpdated": "2026-02-01T00:00:00",
        "firstFixed": ["17.9.5"],
    }


def _synthetic_eox() -> dict[str, Any]:
    return {
        "EOLProductID": "C9300-48P",
        "ProductIDDescription": "Synthetic switch",
        "ProductBulletinNumber": "EOL-SYNTHETIC-143",
        "LinkToProductBulletinURL": "https://cisco.example/bulletin",
        "EndOfSaleDate": {"value": "2025-01-01"},
        "EndOfSWMaintenanceReleases": {"value": "2025-06-01"},
        "EndOfSecurityVulSupportDate": {"value": "2026-01-01"},
        "LastDateOfSupport": {"value": "2027-01-01"},
        "EOXMigrationDetails": {
            "MigrationProductId": "C9300-48P",
            "MigrationProductInfoURL": "https://cisco.example/upgrade",
        },
        "EOXInputType": "PID",
        "EOXInputValue": "C9300-48P",
    }


def _synthetic_suggestion() -> dict[str, Any]:
    return {
        "relDispName": "17.9.5",
        "isSuggested": "Y",
        "releaseDate": "2026-03-01",
        "trainDispName": "17.9",
    }


def _fake() -> FakeCisco:
    return FakeCisco(
        advisories={("iosxe", "17.9.4a", None): [_synthetic_advisory()]},
        eox_pid={"C9300-48P": _synthetic_eox()},
        suggestions={"C9300-48P": [_synthetic_suggestion()]},
    )


def _press_ctrl_c() -> None:
    handler = signal.getsignal(signal.SIGINT)
    assert callable(handler)
    handler(signal.SIGINT, None)


def _stop_during_the_crawl(run: Runner) -> None:
    def press_then_give_the_main_thread_a_tick() -> None:
        _press_ctrl_c()
        time.sleep(discovery.TICK_S * 3)

    run.seed.when_sent["show privilege"] = press_then_give_the_main_thread_a_tick


def test_a_stopped_run_never_unlocks_the_key_and_still_records_analysis(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_key()
    fake = _serve(monkeypatch, _fake())

    def refuse(*_args: object, **_kwargs: object) -> None:
        pytest.fail("a stopped Run must not unlock the key file")

    monkeypatch.setattr(backup_store, "open_key_file", refuse)
    _stop_during_the_crawl(run)

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.STOPPED, got.err
    assert fake.requests == []  # no outbound connection, not even the token
    folder = _run_folder()
    lines = _audit(folder)
    analysis = next(line for line in lines if line["event"] == "analysis")
    assert analysis["cisco_lookups_ran"] is False
    end = lines[-1]
    assert end["event"] == "run_ended"
    assert end["ended"] == "stopped"
    assert end["devices_visited"] == 1
    assert end["backups_written"] == 1
    assert _topology(folder)["cisco_lookups"] == {"ran": False, "when": None}


def test_a_second_ctrl_c_during_the_online_step_keeps_the_outputs_and_the_counts(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_key()
    fake = _serve(monkeypatch, _fake())

    def interrupt(_request: object) -> None:
        raise KeyboardInterrupt

    fake.on_request = interrupt

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.STOPPED, got.err
    assert "Cisco lookups did not finish" in got.err
    assert "Run STOPPED by Ctrl+C" in got.out
    folder = _run_folder()
    names = {path.name for path in folder.iterdir()}
    assert {"topology.json", "diagram.html", "findings.html"} <= names
    lines = _audit(folder)
    assert any(line["event"] == "analysis" for line in lines)
    end = lines[-1]
    assert end["event"] == "run_ended"
    assert end["ended"] == "stopped"
    assert end["devices_visited"] == 1
    assert end["backups_written"] == 1


def test_a_check_that_raises_on_ciscos_answers_still_writes_every_output(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_key()
    _serve(monkeypatch, _fake())
    real = run_analysis.analysed
    calls: list[CiscoAnswers | None] = []

    def flaky(
        built: Topology,
        answers: CiscoAnswers | None = None,
        *,
        records: tuple[DeviceRecord, ...] = (),
        as_of: datetime | None = None,
    ) -> AnalysisResults:
        calls.append(answers)
        if len(calls) == 1:
            msg = "synthetic Check failure"
            raise TypeError(msg)
        return real(built, answers, records=records, as_of=as_of)

    monkeypatch.setattr(run_analysis, "analysed", flaky)

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.NEEDS_ATTENTION, got.err
    assert len(calls) == 2
    assert "could not use Cisco's answers" in got.err
    folder = _run_folder()
    names = {path.name for path in folder.iterdir()}
    assert {"topology.json", "diagram.html", "findings.html"} <= names
    assert _topology(folder)["cisco_lookups"]["ran"] is True
    assert any(line["event"] == "analysis" for line in _audit(folder))


def test_the_key_is_unlocked_only_after_the_backup_locker_has_finished(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_key()
    fake = _serve(monkeypatch, _fake())
    finished: list[bool] = []
    real_finish = backup_store.BackupLocker.finish

    def finish(self: backup_store.BackupLocker) -> object:
        result = real_finish(self)
        finished.append(True)
        return result

    monkeypatch.setattr(backup_store.BackupLocker, "finish", finish)
    real_unlock = backup_store.open_key_file

    def unlock(path: Path, passphrase: backup_store.BackupPassphrase) -> backup_store.KeyUnlock:
        assert finished, "the key was unlocked before the Backups were locked"
        return real_unlock(path, passphrase)

    monkeypatch.setattr(backup_store, "open_key_file", unlock)

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err
    assert finished
    assert fake.token_calls() == 1


def test_lookups_off_never_opens_the_key_file(run: Runner, monkeypatch: pytest.MonkeyPatch) -> None:
    _store_key()
    key_file = data_folder().cisco_key_file
    _serve(monkeypatch, _fake())
    opened: list[Path] = []
    real_open = Path.open

    def spy(self: Path, *args: object, **kwargs: object) -> object:
        opened.append(self)
        opener: Callable[..., object] = real_open
        return opener(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", spy)

    off = run(*FLAGS, typed=later_run())

    assert off.code == ExitCode.CLEAN, off.err
    assert key_file not in opened  # not even at the filesystem seam

    opened.clear()
    on = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert on.code == ExitCode.CLEAN, on.err
    assert key_file in opened  # the spy would have seen it


def test_starting_over_says_the_key_is_gone_before_the_first_device_prompt(
    run: Runner,
) -> None:
    _store_key()
    data_folder().check_file.unlink()  # the operator starts over by hand

    got = run(*FLAGS, "--cisco-lookups", "on", typed=first_run(start="n"))

    assert got.code == ExitCode.STOPPED
    assert not data_folder().cisco_key_file.is_file()
    assert NO_KEY in got.out
    assert got.out.index(NO_KEY) < got.out.index("Ready to start")


def test_a_run_that_never_reaches_its_end_still_wipes_the_typed_secrets(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    wipes: list[Secret] = []
    real_wipe = Secret.wipe

    def spy(self: Secret) -> None:
        wipes.append(self)
        real_wipe(self)

    monkeypatch.setattr(Secret, "wipe", spy)

    def cannot(*_args: object, **_kwargs: object) -> run_output.AuditLog:
        msg = "audit.log could not be created"
        raise run_output.AuditLogError(msg)

    monkeypatch.setattr(run_output, "open_audit_log", cannot)

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.STOPPED
    assert len(wipes) >= 2  # the Backup Passphrase and the one Credential Set password
