"""Run-driver realism: the real bridge sees the releases and modes a device really prints.

The unit tests around `run_analysis` hand-build the records Analysis consumes; these drive
`main(argv)` with fake devices and the fake Cisco at the transport seam, so the show output a
real Run parses reaches `run_analysis.analysed` and the advice the operator sees (#149). All
data is synthetic, and the release strings are public Cisco numbering.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from network_analyser import backup_store
from network_analyser.cli import ExitCode
from network_analyser.credentials import Secret
from tests.support import device_text, fake_age
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco
from tests.support.run_driver import (
    BACKUP_CANARY,
    FLAGS,
    Runner,
    data_folder,
    later_run,
)

SET_AT = datetime(2026, 11, 21, 9, 0, 0, tzinfo=UTC)
PID = "C9300-48P"
COULD_NOT_CHECK = "advisory-could-not-check"


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    return Runner(monkeypatch, capsys)


def _store_key() -> None:
    data = data_folder()
    passphrase = backup_store.create_check_file(data.check_file, Secret(BACKUP_CANARY))
    backup_store.lock_key_file(
        data.cisco_key_file,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        passphrase,
        set_at=SET_AT,
    )


def _serve(monkeypatch: pytest.MonkeyPatch, fake: FakeCisco) -> FakeCisco:
    monkeypatch.setattr("network_analyser.advisories.session.HttpsTransport", lambda **_: fake)
    return fake


def _advisory(ident: str, *fixes: str) -> dict[str, Any]:
    return {
        "advisoryId": ident,
        "advisoryTitle": "Synthetic advisory",
        "sir": "High",
        "cvssBaseScore": "8.6",
        "cves": ["CVE-2026-0149"],
        "firstPublished": "2026-01-01T00:00:00",
        "lastUpdated": "2026-02-01T00:00:00",
        "firstFixed": list(fixes),
    }


def _run_folder() -> Path:
    (folder,) = data_folder().runs.iterdir()
    return folder


def _document() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(
        (_run_folder() / "topology.json").read_text(encoding="utf-8")
    )
    return loaded


def test_a_lettered_running_release_is_asked_for_and_the_later_fix_is_the_target(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`show version` prints `17.09.04a`; Cisco is asked for `17.9.4a`, the #123 criterion."""
    _store_key()
    fake = _serve(
        monkeypatch,
        FakeCisco(
            advisories={
                ("iosxe", "17.9.4a", None): [
                    _advisory("cisco-sa-test-149a", "17.9.7a"),
                    _advisory("cisco-sa-test-149b", "17.9.8"),
                ]
            }
        ),
    )

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err
    (advisory_path,) = [path for path in fake.paths() if "/OSType/iosxe" in path]
    assert "version=17.9.4a" in advisory_path
    document = _document()
    advice = document["devices"][0]["advice"]
    assert (advice["upgrade_target"], advice["not_cleared"]) == ("17.9.8", 0)
    findings = {item["check"]["id"]: item for item in document["findings"]}
    assert (
        "First fixed in Train 17.9: 17.9.7a."
        in findings["advisory-cisco-sa-test-149a"]["what_was_found"]
    )
    assert (
        "First fixed in Train 17.9: 17.9.8."
        in findings["advisory-cisco-sa-test-149b"]["what_was_found"]
    )


def test_a_controller_managed_ios_xe_device_is_never_asked_about_or_matched(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real `Router operating mode:` line keeps SD-WAN out of the release lookup (#147)."""
    _store_key()
    run.seed.replies["show version"] = device_text.IOS_XE_SDWAN_SHOW_VERSION
    fake = _serve(monkeypatch, FakeCisco())

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err
    assert [path for path in fake.paths() if "/OSType/" in path] == []
    document = _document()
    (unchecked,) = [item for item in document["findings"] if item["check"]["id"] == COULD_NOT_CHECK]
    assert "IOS XE SD-WAN is not matched" in unchecked["what_was_found"]
    advice = document["devices"][0]["advice"]
    assert "IOS XE SD-WAN is not matched" in advice["outcome"]
    assert not [
        item
        for item in document["findings"]
        if item["check"]["type"] == "Advisory" and item["check"]["id"] != COULD_NOT_CHECK
    ]
