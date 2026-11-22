"""A Run over an NX-OS device asks openVuln for its Nexus series, end to end (#134).

Driven through `main(argv)` with a fake Nexus at the `device_gateway` seam, answering the
replies the real readers consume (`show version`, `show inventory | json`), and the fake Cisco
at the `advisories` transport seam. The series is not in `show version`'s model (`C9300v`); it
is the chassis PID in `show inventory | json` (`N9K-C9300v`), so a Run that never read the
inventory cannot name the series and must say so rather than say Cisco gave no answer.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from network_analyser import backup_store
from network_analyser.cli import ExitCode
from network_analyser.credentials import Secret
from tests.support import fake_age, nxos_show
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco
from tests.support.fake_device import NXOS_REPLIES
from tests.support.nxos_json import NXOS_JSON_REPLIES
from tests.support.run_driver import (
    BACKUP_CANARY,
    FLAGS,
    Runner,
    data_folder,
    later_run,
)

SET_AT = datetime(2026, 11, 21, 9, 0, 0, tzinfo=UTC)
RELEASE = "9.3(8)"
CHASSIS = "N9K-C93180YC-EX"
SERIES_NAME = "Cisco Nexus 9000 Series Switches"
NO_ANSWER = "Cisco openVuln gave no answer"
NOT_CONFIRMED = "hardware family not confirmed"
COULD_NOT_CHECK = "advisory-could-not-check"


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    runner = Runner(monkeypatch, capsys)
    runner.seed.ssh_id = "SSH-2.0-OpenSSH_8.8 FIPS"
    runner.seed.prompt = "nx-a#"
    runner.seed.replies = {
        **NXOS_JSON_REPLIES,
        **NXOS_REPLIES,
        "show cdp neighbors detail | json": "",
        "show lldp neighbors detail | json": "",
        "show inventory | json": nxos_show.INVENTORY.replace("N9K-C9300v", CHASSIS),
    }
    return runner


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


def _serve(monkeypatch: pytest.MonkeyPatch) -> FakeCisco:
    fake = FakeCisco(
        advisories={("nxos", RELEASE, "NEXUS9000"): [_advisory()]},
        compatible={
            CHASSIS: [
                {
                    "releaseFormat1": "9.3(10)",
                    "isSuggested": "N",
                    "releaseTrain": "9.3",
                    "releaseLifeCycle": "MD",
                }
            ]
        },
    )
    monkeypatch.setattr(
        "network_analyser.advisories.session.HttpsTransport", lambda **_kwargs: fake
    )
    return fake


def _advisory() -> dict[str, Any]:
    return {
        "advisoryId": "cisco-sa-nxos-0134",
        "advisoryTitle": "Synthetic NX-OS advisory",
        "sir": "High",
        "cvssBaseScore": "8.6",
        "cves": ["CVE-2026-0134"],
        "firstPublished": "2026-01-01T00:00:00",
        "lastUpdated": "2026-02-01T00:00:00",
        "firstFixed": [],
        "platforms": [
            {
                "id": "1",
                "name": SERIES_NAME,
                "vulnerabilityState": "vulnerable",
                "firstFixes": [{"id": "2", "name": "9.3(10)"}],
            }
        ],
    }


def _findings() -> list[dict[str, Any]]:
    (folder,) = sorted(data_folder().runs.iterdir())
    document = json.loads(Path(folder / "topology.json").read_text(encoding="utf-8"))
    findings: list[dict[str, Any]] = document["findings"]
    return findings


def test_a_realistic_nexus_run_asks_openvuln_with_the_series_from_its_chassis_pid(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_key()
    fake = _serve(monkeypatch)

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.out
    advisory_paths = [path for path in fake.paths() if "/OSType/nxos" in path]
    assert len(advisory_paths) == 1, fake.paths()
    assert "platformAlias=NEXUS9000" in advisory_paths[0]
    assert all("currentRelease" not in path for path in fake.paths())
    assert any(path.endswith(f"/productId/{CHASSIS}?pageIndex=1") for path in fake.paths())
    findings = _findings()
    advisory = [f for f in findings if f["check"]["id"] == "advisory-cisco-sa-nxos-0134"]
    assert len(advisory) == 1
    assert "First fixed in Train 9.3: 9.3(10)." in advisory[0]["what_was_found"]
    assert not [f for f in findings if f["check"]["id"] == COULD_NOT_CHECK]


def test_a_nexus_whose_inventory_was_not_read_says_the_series_could_not_be_worked_out(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_key()
    run.seed.replies["show inventory | json"] = "% Permission denied for the role\n"
    fake = _serve(monkeypatch)

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code in {ExitCode.CLEAN, ExitCode.NEEDS_ATTENTION}, got.err
    assert not [path for path in fake.paths() if "/OSType/nxos" in path]
    (unchecked,) = [f for f in _findings() if f["check"]["id"] == COULD_NOT_CHECK]
    assert NOT_CONFIRMED in unchecked["what_was_found"]
    assert NO_ANSWER not in unchecked["what_was_found"]
