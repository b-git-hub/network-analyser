"""A Run writes `topology.json` at its end, including after Ctrl+C (#52), and draws
`diagram.html` (#63), `diagram.drawio` (#65) and `findings.html` (#107) from it.

Driven through `main(argv)` with what the operator types; the Seeds are fake devices.
"""

import json
import xml.etree.ElementTree as ET
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import device_gateway, run_output
from network_analyser.cli import ExitCode, main
from network_analyser.records.device import DeviceRecord
from network_analyser.records.identity import Alias
from tests.support import device_text, fake_age, fake_device, ios_xe_text
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
    assert document["format_version"] == 2
    devices = document["devices"]
    assert isinstance(devices, list)
    assert [d["management_ip"] for d in devices] == ["192.0.2.1"]
    assert "netops-ro" not in json.dumps(document)
    assert "topology.json" in got.out


def test_a_run_draws_diagram_html_from_its_topology(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.CLEAN
    (folder,) = data_folder().runs.iterdir()
    page = (Path(folder) / "diagram.html").read_text(encoding="utf-8")
    assert _topology()["devices"][0]["id"] in page  # type: ignore[index]  # JSON data
    assert "netops-ro" not in page
    assert "diagram.html" in got.out


def test_a_run_draws_diagram_drawio_beside_diagram_html(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.CLEAN
    (folder,) = data_folder().runs.iterdir()
    root = ET.fromstring((Path(folder) / "diagram.drawio").read_bytes())  # noqa: S314 (our own)
    assert [d.get("name") for d in root.findall("diagram")] == ["Physical", "Routing"]
    ident = _topology()["devices"][0]["id"]  # type: ignore[index]  # JSON data
    assert f'id="n-{ident}"' in (Path(folder) / "diagram.drawio").read_text(encoding="utf-8")
    assert "netops-ro" not in (Path(folder) / "diagram.drawio").read_text(encoding="utf-8")
    assert "diagram.drawio" in got.out


def test_analysis_runs_at_the_run_s_end_and_its_finding_reaches_every_output(
    run: Runner,
) -> None:
    second = run.network.add(
        "192.0.2.2",
        fake_device.FakeDevice(prompt="sw-b#", host_key=fake_device.synthetic_key(filler=8)),
    )
    second.replies["show version"] = _second_show_version()

    got = run(*FLAGS, "--seed", "192.0.2.2", typed=first_run())

    assert got.code == ExitCode.CLEAN
    document = _topology()
    findings = document["findings"]
    assert isinstance(findings, list)
    drift = [item for item in findings if item["check"]["id"] == "consistency-model-drift"]
    assert len(drift) == 1
    assert len(drift[0]["devices"]) == 2
    advice = document["analysis"]["advice"]  # type: ignore[index]  # JSON data
    assert len(advice) == 2  # one per Visited Device, none for an Unvisited Device
    assert len(run.network.dialled) == 2  # Analysis added no login
    (folder,) = data_folder().runs.iterdir()
    page = (Path(folder) / "diagram.html").read_text(encoding="utf-8")
    assert drift[0]["id"] in page
    assert "Same model on different releases" in (Path(folder) / "run-report.html").read_text(
        encoding="utf-8"
    )

    assert main(["render", str(folder)], elevated=lambda: False) == ExitCode.CLEAN
    redrawn = (Path(folder) / "diagram.html").read_text(encoding="utf-8")
    assert drift[0]["id"] in redrawn


def test_config_facts_from_the_visit_reach_analysis_at_the_run_s_end(
    run: Runner,
) -> None:
    run.seed.replies["show running-config view full"] = device_text.IOS_XE_HARDENING_CONFIG

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.CLEAN
    document = _topology()
    findings = document["findings"]
    assert isinstance(findings, list)
    checks = {item["check"]["id"] for item in findings}
    assert "hardening-telnet" in checks
    assert "hardening-snmp-v1-v2c" in checks
    assert "hardening-legacy-services" in checks
    assert "CANARY-cfg-96-a1b2" not in json.dumps(document)


def _second_show_version() -> str:
    """Another serial, hostname and release on the same model."""
    return (
        device_text.IOS_XE_SHOW_VERSION.replace("TEST0000A01", "TEST0000A09")
        .replace("TEST0000A02", "TEST0000A0A")
        .replace("17.09.04a", "17.09.05")
        .replace("17.9.4a", "17.9.5")
        .replace("sw-a", "sw-b")
    )


def test_a_show_output_check_runs_at_the_run_s_end_and_reaches_topology_json(
    run: Runner,
) -> None:
    run.seed.replies.update(ios_xe_text.REPLIES)  # sw-a answers every 0.2.0 command

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.CLEAN
    document = _topology()
    findings = document["findings"]
    assert isinstance(findings, list)
    snmp = [item for item in findings if item["check"]["id"] == "config-snmpv3-user-crypto"]
    assert len(snmp) == 1
    assert snmp[0]["level"] == "High"
    assert snmp[0]["check"]["name"] == "SNMPv3 users on MD5/DES/3DES"
    checks = document["analysis"]["checks"]  # type: ignore[index]  # JSON data
    assert isinstance(checks, list)
    ran = next(item for item in checks if item["check"]["id"] == "config-snmpv3-user-crypto")
    assert ran["ran"] is True
    assert ran["skipped"] == []
    assert not [
        item for item in findings if item["check"]["id"] == "config-device-role-out-of-date"
    ]


def test_a_run_whose_role_refuses_the_new_commands_gets_one_role_finding(
    run: Runner,
) -> None:
    got = run(*FLAGS, typed=first_run())  # the fake's role knows no 0.2.0 command

    assert got.code == ExitCode.CLEAN
    findings = _topology()["findings"]
    assert isinstance(findings, list)
    roles = [item for item in findings if item["check"]["id"] == "config-device-role-out-of-date"]
    assert len(roles) == 1
    assert roles[0]["level"] == "Medium"
    assert "Device Role is out of date" in roles[0]["what_was_found"]
    assert "role-snippet" in roles[0]["what_was_found"]
    checks = _topology()["analysis"]["checks"]  # type: ignore[index]  # JSON data
    assert isinstance(checks, list)
    ntp = next(item for item in checks if item["check"]["id"] == "config-ntp-synchronised")
    assert ntp["ran"] is False
    assert ntp["skipped"][0]["reason"] == "show ntp associations: denied"


def test_a_run_stopped_by_ctrl_c_still_writes_topology_json(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    run.network.add("192.0.2.2")
    real_visit = device_gateway.visit

    def stop_at_the_second(ip: IPv4Address, **kwargs: object) -> DeviceRecord | Alias:
        if ip == IPv4Address("192.0.2.2"):
            raise KeyboardInterrupt
        return real_visit(ip, **kwargs)  # type: ignore[arg-type]  # the cli's own arguments

    monkeypatch.setattr(device_gateway, "visit", stop_at_the_second)

    got = run(*FLAGS, "--seed", "192.0.2.2", typed=first_run())

    assert got.code == ExitCode.STOPPED
    devices = _topology()["devices"]
    assert isinstance(devices, list)
    assert [d["management_ip"] for d in devices] == ["192.0.2.1"]
    (folder,) = data_folder().runs.iterdir()
    assert (Path(folder) / "diagram.html").is_file()
    assert (Path(folder) / "diagram.drawio").is_file()
    assert (Path(folder) / "findings.html").is_file()


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


def test_a_diagram_that_cannot_be_drawn_needs_attention(
    run: Runner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def disk_full(*_args: object) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(run_output, "write_scanned_text", disk_full)

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert "diagram.html or diagram.drawio could not be drawn" in got.err
    assert _topology()["format_version"] == 2  # topology.json was still written
