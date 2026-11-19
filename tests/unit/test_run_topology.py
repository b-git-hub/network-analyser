"""A Run writes `topology.json` at its end, including after Ctrl+C (#52).

Driven through `main(argv)` with what the operator types; the Seeds are fake devices.
"""

import json
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import device_gateway, run_output
from network_analyser.cli import ExitCode
from network_analyser.records.device import DeviceRecord
from tests.support import fake_age
from tests.support.run_driver import FLAGS, Runner, data_folder, first_run


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    return Runner(monkeypatch, capsys)


def _topology() -> dict[str, object]:
    (folder,) = data_folder().runs.iterdir()
    loaded: dict[str, object] = json.loads((folder / "topology.json").read_text(encoding="utf-8"))
    return loaded


def test_a_run_writes_topology_json_at_its_end(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.CLEAN
    document = _topology()
    assert document["format_version"] == 1
    devices = document["devices"]
    assert isinstance(devices, list)
    assert [d["management_ip"] for d in devices] == ["192.0.2.1"]
    assert "netops-ro" not in json.dumps(document)
    assert "topology.json" in got.out


def test_a_run_stopped_by_ctrl_c_still_writes_topology_json(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    run.network.add("192.0.2.2")
    real_visit = device_gateway.visit

    def stop_at_the_second(ip: IPv4Address, **kwargs: object) -> DeviceRecord:
        if ip == IPv4Address("192.0.2.2"):
            raise KeyboardInterrupt
        return real_visit(ip, **kwargs)  # type: ignore[arg-type]  # the cli's own arguments

    monkeypatch.setattr(device_gateway, "visit", stop_at_the_second)

    got = run(*FLAGS, "--seed", "192.0.2.2", typed=first_run())

    assert got.code == ExitCode.STOPPED
    devices = _topology()["devices"]
    assert isinstance(devices, list)
    assert [d["management_ip"] for d in devices] == ["192.0.2.1"]


def test_a_topology_that_cannot_be_written_needs_attention(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def disk_full(*_args: object) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(run_output, "write_scanned_json", disk_full)

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert "topology.json could not be written" in got.err
    (folder,) = data_folder().runs.iterdir()
    assert not (Path(folder) / "topology.json").exists()
