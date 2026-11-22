"""The inventory a Run collected reaches Analysis, so hardware EoX runs for real (#135).

Driven through `main(argv)` with a fake device whose `show inventory` lists a chassis, stack
members, a supervisor and a line card (and a PSU, a fan and an optic that must never leave),
and the fake Cisco at the `advisories` transport seam. The unit tests hand-built the inventory
the real Run never supplied; these do not.
"""

import json
from typing import Any

import pytest

from network_analyser import analysis, backup_store, topology
from network_analyser.analysis.core import SKIPPED_EVERYWHERE
from network_analyser.cli import ExitCode, run_analysis
from network_analyser.credentials import Secret
from network_analyser.records.analysis import (
    AnalysisInput,
    DeviceInventory,
    HardwareItem,
    HardwareKind,
)
from network_analyser.records.collected import InventoryItem, InventoryKind
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import AnalysisResults
from network_analyser.records.unknown import Unknown
from tests.support import device_text, fake_age, ios_xe_text
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco
from tests.support.run_driver import (
    BACKUP_CANARY,
    FLAGS,
    Runner,
    data_folder,
    later_run,
)
from tests.support.topology_records import visited
from tests.unit.test_run_end_lookups import (
    SET_AT,
    _eox,
    _fake,
    _run_folder,
    _serve,
    _topology,
)

HARDWARE_EOX = "lifecycle-hardware-eox"
SUPERVISOR = "C9400-SUP-1XL"
LINE_CARD = "C9400-LC-48U"
NEVER_ASKED = ("PWR-C1-715WAC", "C9300-FAN", "SFP-10G-SR")


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


def _past_eox(pid: str, **dates: str) -> dict[str, Any]:
    record = _eox()
    record["EOLProductID"] = pid
    record["EOXInputValue"] = pid
    record["EOXMigrationDetails"] = {
        "MigrationProductId": f"{pid}-NEW",
        "MigrationProductInfoURL": "https://cisco.example/upgrade",
    }
    for key in (
        "EndOfSaleDate",
        "EndOfSWMaintenanceReleases",
        "EndOfSecurityVulSupportDate",
        "LastDateOfSupport",
    ):
        record[key] = {"value": dates.get(key, "2099-01-01")}
    return record


def _eox_fake() -> FakeCisco:
    fake = _fake()
    fake.eox_pid = {
        "C9300-48P": _past_eox("C9300-48P"),
        SUPERVISOR: _past_eox(SUPERVISOR, LastDateOfSupport="2020-01-01"),
        LINE_CARD: _past_eox(LINE_CARD, EndOfSaleDate="2020-01-01"),
    }
    return fake


def _with_replies(run: Runner, **replies: str) -> None:
    run.seed.replies.update(ios_xe_text.REPLIES)
    run.seed.replies.update(replies)


def _finding(document: dict[str, Any], check: str) -> dict[str, Any]:
    (found,) = [item for item in document["findings"] if item["check"]["id"] == check]
    assert isinstance(found, dict)
    return found


def _check_run(document: dict[str, Any], check: str) -> dict[str, Any]:
    (found,) = [item for item in document["analysis"]["checks"] if item["check"]["id"] == check]
    assert isinstance(found, dict)
    return found


def test_a_stack_with_a_supervisor_and_a_line_card_raises_hardware_eox_at_the_worst_level(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_key()
    _with_replies(run)
    fake = _serve(monkeypatch, _eox_fake())

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err
    document = _topology(_run_folder())
    finding = _finding(document, HARDWARE_EOX)
    assert finding["level"] == "High"
    items = {item["name"]: item for item in finding["cisco_detail"]["items"]}
    assert set(items) == {SUPERVISOR, LINE_CARD}
    assert items[SUPERVISOR]["replacement"] == f"{SUPERVISOR}-NEW"
    assert items[LINE_CARD]["replacement"] == f"{LINE_CARD}-NEW"
    assert _check_run(document, HARDWARE_EOX)["ran"] is True
    assert _check_run(document, HARDWARE_EOX)["skipped"] == []
    asked = " ".join(fake.paths())
    assert SUPERVISOR in asked
    assert LINE_CARD in asked


def test_optics_psus_and_fans_never_reach_cisco(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_key()
    _with_replies(run)
    fake = _serve(monkeypatch, _eox_fake())

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err
    asked = " ".join(fake.paths())
    for pid in NEVER_ASKED:
        assert pid not in asked


def test_software_suggestion_is_asked_about_the_chassis_pid_only(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store_key()
    _with_replies(run)
    fake = _serve(monkeypatch, _eox_fake())

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err
    suggestion_paths = [path for path in fake.paths() if path.startswith("/software/suggestion")]
    assert suggestion_paths
    for path in suggestion_paths:
        assert SUPERVISOR not in path
        assert LINE_CARD not in path
    assert any(SUPERVISOR in path for path in fake.paths() if "/eox/" in path)


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        (device_text.COMMAND_AUTHORISATION_FAILED, "show inventory"),
        (ios_xe_text.NOT_UNDERSTOOD, "show inventory"),
    ],
)
def test_a_refused_or_unreadable_show_inventory_skips_hardware_eox_with_the_reason(
    run: Runner, monkeypatch: pytest.MonkeyPatch, reply: str, reason: str
) -> None:
    _store_key()
    _with_replies(run, **{"show inventory": reply})
    _serve(monkeypatch, _eox_fake())

    got = run(*FLAGS, "--cisco-lookups", "on", typed=later_run())

    assert got.code == ExitCode.CLEAN, got.err
    check = _check_run(_topology(_run_folder()), HARDWARE_EOX)
    assert check["ran"] is False
    assert check["reason"] == SKIPPED_EVERYWHERE
    (skip,) = check["skipped"]
    assert reason in skip["reason"]
    assert json.dumps(check)  # plain data, nothing secret


def _input_analysed(monkeypatch: pytest.MonkeyPatch, record: DeviceRecord) -> AnalysisInput:
    """The `AnalysisInput` `analysed` hands Analysis for one device record."""
    seen: list[AnalysisInput] = []
    real = analysis.analyse

    def spy(data: AnalysisInput) -> AnalysisResults:
        seen.append(data)
        return real(data)

    monkeypatch.setattr(analysis, "analyse", spy)
    run_analysis.analysed(topology.build([record]), records=(record,))
    (data,) = seen
    return data


def test_analysed_builds_the_inventory_under_the_device_id_with_the_four_kinds_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = visited(
        "192.0.2.1",
        "S1",
        inventory=[
            InventoryItem("Chassis", InventoryKind.CHASSIS, "C9400-X", "S1"),
            InventoryItem("Slot 1", InventoryKind.SUPERVISOR, SUPERVISOR, "S2"),
            InventoryItem("Slot 2", InventoryKind.LINE_CARD, LINE_CARD, "S3"),
            InventoryItem("Switch 2", InventoryKind.STACK_MEMBER, "C9300-24P", "S4"),
            InventoryItem("Slot 3", InventoryKind.LINE_CARD, Unknown("no PID"), "S5"),
        ],
    )

    data = _input_analysed(monkeypatch, record)

    (inventory,) = data.inventory
    assert inventory.device == data.topology.devices[0].id
    assert inventory.items == (
        HardwareItem("C9400-X", HardwareKind.CHASSIS),
        HardwareItem(SUPERVISOR, HardwareKind.SUPERVISOR),
        HardwareItem(LINE_CARD, HardwareKind.LINE_CARD),
        HardwareItem("C9300-24P", HardwareKind.STACK_MEMBER),
    )


@pytest.mark.parametrize("unread", [Unknown("show inventory: denied"), None])
def test_an_unread_inventory_falls_back_to_the_model(
    monkeypatch: pytest.MonkeyPatch, unread: Unknown | None
) -> None:
    record = visited("192.0.2.1", "S1", inventory=unread)

    data = _input_analysed(monkeypatch, record)

    assert data.inventory == (
        DeviceInventory(
            data.topology.devices[0].id, (HardwareItem("C9300-48P", HardwareKind.CHASSIS),)
        ),
    )
