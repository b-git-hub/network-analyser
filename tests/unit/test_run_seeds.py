"""A confirmed Run logs into each Seed, identifies it and ends with a summary (ticket #49).

Driven through `main(["run", ...])` with what the operator types; the Seeds are fake devices
at the `device_gateway` seam (tests/support/run_driver).
"""

import json
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import trust_store
from network_analyser.cli import ExitCode
from tests.support import fake_age
from tests.support.fake_device import FakeDevice, synthetic_key
from tests.support.run_driver import (
    BACKUP_CANARY,
    DEVICE_CANARY,
    FLAGS,
    Runner,
    data_folder,
    first_run,
)

SEED = IPv4Address(FLAGS[3])


@pytest.fixture(autouse=True)
def _fast_age(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_age.use_fake_age(monkeypatch)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Runner:
    return Runner(monkeypatch, capsys)


def _audit() -> list[dict[str, object]]:
    (folder,) = sorted(data_folder().runs.iterdir())
    text = (folder / "audit.log").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def test_a_run_visits_its_seed_audits_every_step_and_ends_clean(run: Runner) -> None:
    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.CLEAN
    assert "Run summary: 1 device tried: 1 visited, 0 partial, 0 unvisited." in got.out
    assert "192.0.2.1        visited    IOS/IOS-XE  sw-a  privilege level 15  as netops-ro" in (
        got.out
    )
    assert "New host keys trusted on first use: 1." in got.out
    events = [line["event"] for line in _audit()]
    # The locking worker writes its event as soon as the Backup is on disk, so it may come
    # before or after the device's last line; always before the Run's end.
    assert events.index("backup_written") > events.index("device_identified")
    steps = [e for e in events if e != "backup_written"]
    assert steps[:10] == [
        "run_started",
        "connection_attempted",
        "host_key_checked",
        "login_attempted",
        "command_sent",
        "command_sent",
        "command_sent",
        "command_sent",
        "device_identified",
        "command_sent",
    ]
    assert set(steps[10:-2]) == {"command_sent"}  # the collection commands (#59)
    assert steps[-2:] == ["device_finished", "run_ended"]
    commands = [line["command"] for line in _audit() if line["event"] == "command_sent"]
    assert commands[:5] == [
        "terminal length 0",
        "terminal width 511",
        "show version",
        "show privilege",
        "show running-config view full",
    ]
    text = json.dumps(_audit())
    assert DEVICE_CANARY not in text
    assert BACKUP_CANARY not in text
    assert "uptime" not in text  # no device output


def test_a_changed_key_needs_attention_with_the_exact_trust_key_line(run: Runner) -> None:
    store = trust_store.load(data_folder().trust_store)
    store.password_sent(store.check(SEED, 22, synthetic_key(filler=9)))

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert "192.0.2.1        unvisited  host key changed" in got.out
    line = f"network-analyser trust-key 192.0.2.1 --fingerprint {run.seed.host_key.fingerprint}"
    assert line in got.out
    assert run.seed.passwords_received == []


def test_strict_mode_logs_into_nothing_untrusted(run: Runner) -> None:
    got = run(*FLAGS, "--strict-host-keys", typed=first_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert "host key not yet trusted (strict mode)" in got.out
    assert run.seed.passwords_received == []
    assert not data_folder().trust_store.exists()


def test_a_known_hosts_file_trusts_its_keys_and_is_never_written(
    run: Runner, tmp_path: Path
) -> None:
    preload = tmp_path / "site_known_hosts"
    key = run.seed.host_key
    preload.write_text(f"192.0.2.1 {key.key_type} {key.base64}\n", encoding="utf-8")
    before = preload.read_bytes()

    got = run(*FLAGS, "--strict-host-keys", "--known-hosts", str(preload), typed=first_run())

    assert got.code == ExitCode.CLEAN
    assert preload.read_bytes() == before


def test_a_missing_known_hosts_file_refuses_before_any_secret_prompt(run: Runner) -> None:
    got = run(*FLAGS, "--known-hosts", "missing_known_hosts", typed=first_run())

    assert got.code == ExitCode.REFUSED
    assert "--known-hosts file" in got.err
    assert "Backup Passphrase" not in got.err
    assert run.network.dialled == []


def test_a_seed_on_an_unsupported_platform_is_left_and_reported(run: Runner) -> None:
    run.seed.replies["show version"] = "Cisco IOS XR Software, Version 7.5.2\n"

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert "unsupported Platform (identified after login)" in got.out


def test_a_landing_privilege_too_low_needs_attention(run: Runner) -> None:
    run.seed.replies["show privilege"] = "Current privilege level is 1\n"

    got = run(*FLAGS, typed=first_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert "landed at privilege level 1, too low" in got.out


def test_a_second_seed_is_visited_too_and_one_out_of_reach_is_unreachable(run: Runner) -> None:
    run.network.add("192.0.2.2", FakeDevice(prompt="sw-b#"))

    got = run(*FLAGS, "--seed", "192.0.2.2", "--seed", "192.0.2.3", typed=first_run())

    assert got.code == ExitCode.NEEDS_ATTENTION
    assert "3 devices tried: 2 visited, 0 partial, 1 unvisited." in got.out
    assert "192.0.2.3        unvisited  unreachable" in got.out
