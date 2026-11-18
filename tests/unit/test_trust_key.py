"""`trust-key`: a device's key is saved only if it matches the typed fingerprint (story 45).

Driven through `device_gateway.trust_key` with fake devices at the gateway seam. No password
is ever sent.
"""

from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import device_gateway, trust_store
from network_analyser.records import HostKeyVerdict
from network_analyser.trust_store import AcceptOutcome, TrustStore
from tests.support.fake_device import FakeDevice, FakeNetwork, synthetic_key

DEVICE = IPv4Address("192.0.2.10")


@pytest.fixture
def store(tmp_path: Path) -> TrustStore:
    return trust_store.load(tmp_path / "trust" / "known_hosts")


def test_a_matching_key_is_saved_with_no_password_sent(store: TrustStore) -> None:
    network = FakeNetwork()
    device = network.add(str(DEVICE))

    result = device_gateway.trust_key(
        DEVICE, device.host_key.fingerprint, trust=store, dial=network.dial
    )

    assert result.outcome is AcceptOutcome.SAVED
    assert store.check(DEVICE, 22, device.host_key).verdict is HostKeyVerdict.KNOWN
    assert device.passwords_received == []
    assert device.open_links == 0


def test_each_key_type_is_asked_for_until_one_matches(store: TrustStore) -> None:
    network = FakeNetwork()
    device = network.add(str(DEVICE), FakeDevice(host_key=synthetic_key("ssh-rsa")))

    result = device_gateway.trust_key(
        DEVICE, device.host_key.fingerprint, trust=store, dial=network.dial
    )

    assert result.outcome is AcceptOutcome.SAVED
    assert device.key_types_asked[-1] == ("ssh-rsa",)
    assert all(len(asked) == 1 for asked in device.key_types_asked)


def test_a_key_that_does_not_match_is_never_saved(store: TrustStore, tmp_path: Path) -> None:
    network = FakeNetwork()
    device = network.add(str(DEVICE))
    other = synthetic_key(filler=9).fingerprint

    result = device_gateway.trust_key(DEVICE, other, trust=store, dial=network.dial)

    assert result.outcome is AcceptOutcome.FINGERPRINT_MISMATCH
    assert result.presented == (device.host_key.fingerprint,)
    assert not (tmp_path / "trust" / "known_hosts").exists()


@pytest.mark.parametrize("ip", ["127.0.0.1", "224.0.0.1", "0.0.0.1", "255.255.255.255"])
def test_an_address_that_is_never_a_target_is_never_dialled(ip: str, store: TrustStore) -> None:
    network = FakeNetwork()

    result = device_gateway.trust_key(
        IPv4Address(ip), synthetic_key().fingerprint, trust=store, dial=network.dial
    )

    assert result.outcome is None
    assert result.failure is not None
    assert network.dialled == []


def test_an_unreachable_device_is_reported(store: TrustStore) -> None:
    network = FakeNetwork()

    result = device_gateway.trust_key(
        DEVICE, synthetic_key().fingerprint, trust=store, dial=network.dial
    )

    assert result.outcome is None
    assert result.failure == "the device could not be reached over SSH"
