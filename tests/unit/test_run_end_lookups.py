"""The Run's end goes online once, after secrets are wiped, and outages stay one line (#104).

Driven through `main(argv)` with fake devices and the fake Cisco at the `advisories` transport
seam. The fake asserts on the state it observes, so no test can pass while an outbound
connection opened with a device session or a typed secret still held. It also walks the Run's
`SecretScan` at that moment, proving the scan holds no typed password and no passphrase, only
fingerprints, yet still redacts them (#145).
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

import pytest

from network_analyser import backup_store, device_gateway
from network_analyser.advisories import HttpResponse
from network_analyser.cli import ExitCode, run_end
from network_analyser.credentials import CredentialSets, Secret, SecretScan
from network_analyser.records.device import DeviceRecord
from network_analyser.records.identity import Alias
from tests.support import fake_age
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, TOKEN, FakeCisco
from tests.support.run_driver import (
    BACKUP_CANARY,
    DEVICE_CANARY,
    FLAGS,
    Runner,
    data_folder,
    first_run,
    later_run,
)
from tests.support.scan_state import reachable_text

PASS = BACKUP_CANARY
SET_AT = datetime(2026, 11, 21, 9, 0, 0, tzinfo=UTC)
NO_KEY = "No Cisco API key is stored"
REJECTED = "Cisco rejected the API key"


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


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


def _run_folders() -> list[Path]:
    runs = data_folder().runs
    return sorted(runs.iterdir()) if runs.is_dir() else []


def _run_folder() -> Path:
    (folder,) = _run_folders()
    return folder


def _audit(folder: Path) -> list[dict[str, Any]]:
    text = (folder / "audit.log").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def _topology(folder: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((folder / "topology.json").read_text(encoding="utf-8"))
    return loaded


def _advisory() -> dict[str, Any]:
    return {
        "advisoryId": "cisco-sa-test-104",
        "advisoryTitle": "Synthetic advisory",
        "sir": "High",
        "cvssBaseScore": "8.6",
        "cves": ["CVE-2026-0001"],
        "firstPublished": "2026-01-01T00:00:00",
        "lastUpdated": "2026-02-01T00:00:00",
        "firstFixed": ["17.9.5"],
    }


def _eox() -> dict[str, Any]:
    return {
        "EOLProductID": "C9300-48P",
        "ProductIDDescription": "Synthetic switch",
        "ProductBulletinNumber": "EOL-SYNTHETIC-1",
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


def _suggestion() -> dict[str, Any]:
    return {
        "relDispName": "17.9.5",
        "isSuggested": "Y",
        "releaseDate": "2026-03-01",
        "trainDispName": "17.9",
    }


def _status(status: int) -> HttpResponse:
    return HttpResponse(status=status, body=b"")


def _fake() -> FakeCisco:
    return FakeCisco(
        advisories={("iosxe", "17.9.4a", None): [_advisory()]},
        eox_pid={"C9300-48P": _eox()},
        suggestions={"C9300-48P": [_suggestion()]},
    )


@dataclass
class _Observed:
    """What the test sees when the fake Cisco is reached, to prove the order held."""

    visits: int = 0
    sets_wiped: bool | None = None
    passphrase_wiped: bool | None = None
    scan: SecretScan | None = None

    def check(self, *_args: object) -> None:
        assert self.visits == 0, "Cisco was asked while a device session was open"
        assert self.sets_wiped, "Cisco was asked while a Credential Set password was held"
        assert self.passphrase_wiped, "Cisco was asked while the Backup Passphrase was held"
        assert self.scan is not None
        held = reachable_text(self.scan)
        for canary in (DEVICE_CANARY, BACKUP_CANARY):
            assert canary not in held, "the secret scan still held a typed secret while online"
            assert self.scan.holds_secret(canary), "the secret scan stopped watching a secret"


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    return Runner(monkeypatch, capsys)


def test_a_stored_key_asks_cisco_after_the_sessions_close_and_every_secret_is_wiped(
    run: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_key()
    fake = _serve(monkeypatch, _fake())
    observed = _Observed()
    fake.on_request = observed.check

    real_visit = device_gateway.visit

    def counted_visit(ip: IPv4Address, **kwargs: object) -> DeviceRecord | Alias:
        observed.visits += 1
        try:
            return real_visit(ip, **kwargs)  # type: ignore[arg-type]
        finally:
            observed.visits -= 1

    monkeypatch.setattr(device_gateway, "visit", counted_visit)
    real_wipe = run_end.wipe

    def observed_wipe(sets: CredentialSets, passphrase: backup_store.BackupPassphrase) -> None:
        real_wipe(sets, passphrase)
        observed.sets_wiped = sets.wiped
        observed.passphrase_wiped = passphrase.wiped

    monkeypatch.setattr(run_end, "wipe", observed_wipe)

    def record_scan() -> SecretScan:
        scan = SecretScan()
        observed.scan = scan
        return scan

    monkeypatch.setattr("network_analyser.cli.cmd_run.SecretScan", record_scan)

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err
    assert fake.token_calls() == 1
    assert fake.api_requests()
    folder = _run_folder()
    document = _topology(folder)
    assert document["cisco_lookups"]["ran"] is True
    assert isinstance(document["cisco_lookups"]["when"], str)
    assert "sw-a" not in json.dumps(fake.paths())
    assert (folder / "backups").is_dir()
    assert "Needs your attention" not in got.out


def test_lookups_off_opens_nothing_and_leaves_the_key_file_untouched(
    run: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_key()
    key_file = data_folder().cisco_key_file
    before = (key_file.read_bytes(), key_file.stat().st_mtime_ns)
    fake = _serve(monkeypatch, _fake())

    got = run(*FLAGS, typed=later_run())  # FLAGS carry --cisco-lookups off

    assert got.code == ExitCode.CLEAN, got.err
    assert fake.requests == []
    assert (key_file.read_bytes(), key_file.stat().st_mtime_ns) == before
    assert _topology(_run_folder())["cisco_lookups"] == {"ran": False, "when": None}


def test_a_run_with_no_key_gives_one_notice_and_one_attention_line(run: Runner) -> None:
    got = run(*FLAGS, "--cisco-lookups", "on", typed=first_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert got.out.count(NO_KEY) == 2  # one notice before the prompts, one Needs-attention line
    assert got.out.index(NO_KEY) < got.out.index("Scope (")
    assert "Backup Passphrase" in got.err  # the first prompt comes after the notice
    assert "  No Cisco API key is stored, so Cisco lookups did not run." in got.out
    assert (Path(_run_folder()) / "backups").is_dir()  # Backups are kept


def test_a_rejected_key_gives_exactly_one_attention_line_and_exit_1(
    run: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_key()
    fake = _serve(monkeypatch, _fake())
    fake.token_status = 401
    fake.token_error = "invalid_client"

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert fake.token_calls() == 1  # a rejected key is never retried
    lines = [line for line in got.out.splitlines() if REJECTED in line]
    assert len(lines) == 1, got.out
    assert "cisco-key set" in lines[0]
    assert len([line for line in got.out.splitlines() if "did not run:" in line]) == 1
    assert (Path(_run_folder()) / "backups").is_dir()


def test_two_software_suggestion_failures_give_one_attention_line(
    run: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_key()
    fake = _serve(monkeypatch, _fake())
    fake.scripted.append(("/software/suggestion/v2/suggestions/releases", _status(400)))
    fake.scripted.append(("/software/suggestion/v2/suggestions/compatible", _status(404)))

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    lines = [line for line in got.out.splitlines() if "Cisco Software Suggestion" in line]
    assert lines == ["  Cisco Software Suggestion did not run: Cisco returned HTTP 400."]
    assert "cisco-key set" not in got.out


def test_a_400_on_a_release_is_that_devices_could_not_check_and_no_key_advice(
    run: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_key()
    fake = _serve(monkeypatch, _fake())
    fake.advisories = {}
    fake.advisory_errors = {("iosxe", "17.9.4a", None): (400, "INVALID_IOS_VERSION")}

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert "cisco-key set" not in got.out
    assert REJECTED not in got.out
    assert "Cisco advisories (openVuln) did not run" not in got.out
    outcome = _topology(_run_folder())["devices"][0]["advice"]["outcome"]
    assert outcome.startswith("could not check: Cisco openVuln does not know release 17.9.4a")
    assert fake.api_requests()[-1].path.startswith("/software")  # the later calls still went out


def test_an_unreachable_cisco_gives_one_attention_line_per_source(
    run: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_key()
    fake = _serve(monkeypatch, _fake())
    fake.outage = True

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    lines = [line for line in got.out.splitlines() if "did not run:" in line]
    assert len(lines) == 3, got.out
    assert all("cisco-key set" not in line for line in lines)
    document = _topology(_run_folder())
    assert document["cisco_lookups"]["ran"] is True
    assert not [
        finding
        for finding in document["findings"]
        if finding["check"]["type"] in {"Advisory", "Lifecycle"}
    ]


def test_the_analysis_audit_event_is_counts_only(
    run: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_key()
    _serve(monkeypatch, _fake())

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err
    folder = _run_folder()
    lines = _audit(folder)
    analysis = next(line for line in lines if line["event"] == "analysis")
    assert lines[-1]["event"] == "run_ended"
    assert analysis["cisco_lookups_ran"] is True
    assert isinstance(analysis["cisco_lookups_when"], str)
    assert analysis["checks"]
    assert all(len(check) == 3 for check in analysis["checks"])
    assert [level[0] for level in analysis["findings_by_level"]] == [
        "Critical",
        "High",
        "Medium",
        "Low",
    ]
    assert analysis["findings_by_check"]
    assert analysis["token_outcome"] == "ok"
    assert len(analysis["endpoints"]) == 5
    compatible = next(
        endpoint
        for endpoint in analysis["endpoints"]
        if endpoint[0] == "Software Suggestion (compatible)"
    )
    assert len(compatible) == 5  # endpoint, calls, values, retries, pages
    written = (folder / "audit.log").read_text(encoding="utf-8")
    for secret in (CLIENT_ID, CLIENT_SECRET, TOKEN, PASS):
        assert secret not in written
    assert "sw-a" not in json.dumps(analysis)
    assert "192.0.2.1" not in json.dumps(analysis)


def test_the_recap_says_lookups_are_on_and_that_a_key_is_stored(
    run: Runner,
) -> None:
    _store_key()

    got = run(*FLAGS, "--cisco-lookups", "on", typed=first_run(start="n"))

    assert got.code == ExitCode.STOPPED
    assert "  Cisco lookups   on (command line); Cisco API key stored\n" in got.out


def test_a_run_file_key_turns_lookups_off(run: Runner, tmp_path: Path) -> None:
    run_file = tmp_path / "site-a.toml"
    run_file.write_text("cisco_lookups = false\n", encoding="utf-8")

    got = run(
        "--from",
        str(run_file),
        "--scope",
        "192.0.2.0/24",
        "--seed",
        "192.0.2.1",
        typed=first_run(start="n"),
    )

    assert got.code == ExitCode.STOPPED
    assert "  Cisco lookups   off (run file); no Cisco API key stored\n" in got.out


def test_lookups_off_never_calls_the_online_step(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_questions: object, _key: object, **_kwargs: object) -> None:
        pytest.fail("lookups off must never ask Cisco")

    monkeypatch.setattr("network_analyser.cli.run_analysis.answers_for", fail)

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.CLEAN, got.err


def test_a_key_locked_with_another_passphrase_is_reported_once(
    run: Runner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    data = data_folder()
    backup_store.create_check_file(data.check_file, Secret(PASS))
    other = backup_store.create_check_file(
        tmp_path / "other" / "check.age", Secret("CANARY-pp-104-0ther")
    )
    backup_store.lock_key_file(
        data.cisco_key_file,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        other,
        set_at=SET_AT,
    )
    fake = _serve(monkeypatch, _fake())

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert fake.requests == []
    assert got.out.count(backup_store.KEY_LOCKED_ELSEWHERE) == 1


def test_the_run_report_carries_the_run_end_attention(
    run: Runner,
) -> None:
    got = run(*FLAGS, "--cisco-lookups", "on", typed=first_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    report = (_run_folder() / "run-report.html").read_text(encoding="utf-8")
    assert "No Cisco API key is stored, so Cisco lookups did not run." in report


def test_a_recorded_run_time_is_utc(
    run: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_key()
    _serve(monkeypatch, _fake())

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err
    when = _topology(_run_folder())["cisco_lookups"]["when"]
    assert when.endswith("+00:00")
    assert datetime.fromisoformat(when).tzinfo is not None


def test_the_proxy_flag_reaches_the_online_transport(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_key()
    fake = _fake()
    opened: dict[str, Any] = {}

    def transport(**kwargs: object) -> FakeCisco:
        opened.update(kwargs)
        return fake

    monkeypatch.setattr("network_analyser.advisories.session.HttpsTransport", transport)

    got = run(
        *FLAGS,
        "--cisco-lookups",
        "on",
        "--proxy",
        "proxy.example:8080",
        typed=later_run(),
    )

    assert got.code == ExitCode.CLEAN, got.err
    proxy = opened["proxy"]
    assert proxy.address == "proxy.example:8080"
    assert fake.token_calls() == 1


def test_the_key_file_is_not_read_when_lookups_are_off(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_key()

    def fail(*_args: object, **_kwargs: object) -> None:
        pytest.fail("the key file must not be opened with lookups off")

    monkeypatch.setattr(backup_store, "unlock_key_file", fail)

    got = run(*FLAGS, typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err


def test_a_compatible_page_cap_is_not_available_and_adds_no_attention_line(
    run: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_key()
    fake = _serve(monkeypatch, _fake())
    fake.compatible = {"C9300-48P": []}
    fake.compatible_last_page = {"C9300-48P": 25}

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err
    assert "did not run:" not in got.out
    document = _topology(_run_folder())
    advice = document["devices"][0]["advice"]
    assert advice["latest_release"] == "not available"
    assert advice["latest_in_train"] == "not available"
    analysis = next(line for line in _audit(_run_folder()) if line["event"] == "analysis")
    compatible = next(
        endpoint
        for endpoint in analysis["endpoints"]
        if endpoint[0] == "Software Suggestion (compatible)"
    )
    assert compatible[4] == 20
    assert "C9300-48P" not in json.dumps(analysis)


def test_a_token_that_expires_mid_run_keeps_the_answers_and_does_not_blame_the_key(
    run: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_key()
    fake = _serve(monkeypatch, _fake())
    fake.scripted.append(("/supporttools", _status(401)))

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    lines = [line for line in got.out.splitlines() if "stopped early" in line]
    assert len(lines) == 1, got.out
    assert "Cisco's token expired" in lines[0]
    assert "cisco-key set" not in got.out
    assert REJECTED not in got.out
    assert "did not run:" not in got.out
    assert fake.token_calls() == 1  # the one-token rule held: no second token was asked for
    assert (Path(_run_folder()) / "backups").is_dir()
    document = _topology(_run_folder())
    assert any(finding["check"]["type"] == "Advisory" for finding in document["findings"])
    analysis = next(line for line in _audit(_run_folder()) if line["event"] == "analysis")
    assert analysis["token_outcome"] == "ok"
    openvuln = next(item for item in analysis["endpoints"] if item[0] == "openVuln")
    assert openvuln[1] >= 1  # the calls that went out are still counted


def test_a_failure_nobody_expected_still_records_what_was_sent(
    run: Runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_key()
    fake = _serve(monkeypatch, _fake())

    def explode(request: object) -> None:
        if getattr(request, "path", "").startswith("/supporttools"):
            raise RuntimeError

    fake.on_request = explode

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert "Cisco lookups did not finish" in got.err
    assert (Path(_run_folder()) / "backups").is_dir()
    analysis = next(line for line in _audit(_run_folder()) if line["event"] == "analysis")
    assert analysis["token_outcome"] == "ok"
    by_name = {item[0]: item for item in analysis["endpoints"]}
    assert by_name["openVuln"][1] >= 1
    assert by_name["EoX"][1] == 1
    written = (_run_folder() / "audit.log").read_text(encoding="utf-8")
    for secret in (CLIENT_ID, CLIENT_SECRET, TOKEN, PASS):
        assert secret not in written
