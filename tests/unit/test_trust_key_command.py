"""`network-analyser trust-key IP --fingerprint SHA256:...` (story 45; #46 and #69 follow-ups).

Driven through `main`, with a fake device at the `device_gateway` seam.
"""

import pytest

from network_analyser import run_output
from network_analyser.cli import ExitCode, main
from tests.support.fake_device import FakeDevice, FakeNetwork, synthetic_key
from tests.support.run_driver import data_folder


@pytest.fixture
def device(monkeypatch: pytest.MonkeyPatch) -> FakeDevice:
    network = FakeNetwork()
    network.install(monkeypatch)
    return network.add("192.0.2.10")


def test_a_matching_key_is_saved_and_no_password_is_sent(
    device: FakeDevice, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["trust-key", "192.0.2.10", "--fingerprint", device.host_key.fingerprint])

    assert code == ExitCode.CLEAN
    assert "Saved" in capsys.readouterr().out
    assert device.host_key.base64 in data_folder().trust_store.read_text(encoding="utf-8")
    assert device.passwords_received == []


def test_a_key_that_does_not_match_is_not_saved_and_needs_attention(
    device: FakeDevice, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["trust-key", "192.0.2.10", "--fingerprint", synthetic_key(filler=9).fingerprint])

    out = capsys.readouterr().out
    assert code == ExitCode.NEEDS_ATTENTION
    assert f"The device presents {device.host_key.fingerprint}" in out
    assert "Not saved" in out
    assert not data_folder().trust_store.exists()


@pytest.mark.parametrize("ip", ["sw-a", "192.0.2", "2001:db8::1"])
def test_anything_but_one_ipv4_address_is_refused(
    ip: str, device: FakeDevice, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["trust-key", ip, "--fingerprint", device.host_key.fingerprint])

    assert code == ExitCode.REFUSED
    assert "IPv4 address" in capsys.readouterr().err


def test_a_loopback_address_is_refused_before_any_connection(
    device: FakeDevice, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["trust-key", "127.0.0.1", "--fingerprint", device.host_key.fingerprint])

    assert code == ExitCode.REFUSED
    assert "Nothing was contacted" in capsys.readouterr().err
    assert device.key_types_asked == []


def test_trust_key_is_refused_while_a_run_holds_the_lock(
    device: FakeDevice, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = run_output.take_instance_lock(data_folder())
    assert lock is not None
    try:
        code = main(["trust-key", "192.0.2.10", "--fingerprint", device.host_key.fingerprint])
    finally:
        lock.release()

    assert code == ExitCode.REFUSED
    assert "another Run" in capsys.readouterr().err
    assert device.key_types_asked == []
