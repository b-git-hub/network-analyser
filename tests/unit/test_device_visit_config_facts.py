"""Config facts are extracted inside the visit and carried on the device record (#96).

Driven through `device_gateway.visit` with a fake device at the gateway seam: the running
config still goes only to the Backup sink, while its secret-free facts ride the record.
"""

from ipaddress import IPv4Address
from pathlib import Path

import pytest

from network_analyser import device_gateway, scope, trust_store
from network_analyser.credentials import CredentialSet, CredentialSets, Secret
from network_analyser.records import ScopeRecord
from network_analyser.records.config_facts import TELNET_LINES, ConfigFacts
from network_analyser.records.device import DeviceRecord
from network_analyser.records.unknown import Unknown
from tests.support import device_text
from tests.support.fake_device import DEVICE_CANARY, FakeDevice, FakeNetwork

SEED = "192.0.2.10"


def _scope() -> ScopeRecord:
    fence = scope.parse(["192.0.2.0/24"], ["192.0.2.128/25"])
    assert isinstance(fence, ScopeRecord)
    return fence


def _visit(tmp_path: Path, device: FakeDevice) -> tuple[DeviceRecord, list[str]]:
    network = FakeNetwork()
    network.add(SEED, device)
    backups: list[str] = []

    def sink(_capture: object, config: str) -> None:
        backups.append(config)

    record = device_gateway.visit(
        IPv4Address(SEED),
        scope=_scope(),
        trust=trust_store.load(tmp_path / "known_hosts", strict=False),
        sets=CredentialSets([CredentialSet("netops-ro", Secret(DEVICE_CANARY), None)]),
        emit=lambda _event: None,
        failure_budget=3,
        backup_sink=sink,
        dial=network.dial,
        wait_before_retry=network.wait_before_retry,
    )
    assert isinstance(record, DeviceRecord)
    return record, backups


def test_a_visited_device_carries_the_facts_of_the_config_it_captured(
    tmp_path: Path,
) -> None:
    device = FakeDevice()
    device.replies["show running-config view full"] = device_text.IOS_XE_HARDENING_CONFIG

    record, backups = _visit(tmp_path, device)

    facts = {fact.name: fact.value for fact in record.config_facts}
    assert facts[TELNET_LINES] == ("line vty 0 4",)
    assert backups == [device_text.IOS_XE_HARDENING_CONFIG]
    for canary in device_text.HARDENING_CANARIES:
        assert canary not in repr(record)


def test_a_device_whose_config_was_not_read_has_no_facts_and_they_read_as_unknown(
    tmp_path: Path,
) -> None:
    device = FakeDevice()
    device.replies["show running-config view full"] = "not a whole config\n"

    record, backups = _visit(tmp_path, device)

    assert record.config_facts == ()
    assert backups == []
    facts = ConfigFacts("dev-TEST0000A01", record.config_facts)
    value = facts.fact(TELNET_LINES)
    assert isinstance(value, Unknown)


def test_a_fact_that_was_not_collected_is_unknown_never_absent() -> None:
    facts = ConfigFacts("dev-S1", ())

    value = facts.fact("no-such-fact")

    assert isinstance(value, Unknown)


@pytest.mark.parametrize("platform", ["ios", "nxos"])
def test_both_platforms_carry_facts(platform: str, tmp_path: Path) -> None:
    device = FakeDevice()
    if platform == "nxos":
        device.replies = {
            "terminal length 0": "",
            "terminal width 511": "",
            "show version": device_text.NXOS_SHOW_VERSION,
            "show user-account netops-ro": device_text.NXOS_USER_ACCOUNT,
            "show cdp neighbors detail | json": "",
            "show lldp neighbors detail | json": "",
            "show running-config": device_text.NXOS_HARDENING_CONFIG,
        }

    record, _ = _visit(tmp_path, device)

    assert record.config_facts
