"""Interface names are shortened by one fixed table (story 127; decided on #11).

Both ends of a Link must name a port the same way, whichever Platform reported it, so the
long names, and the short forms LLDP often sends, all map to one canonical short form. There
is no general rule: `Tw` (TwoGigabitEthernet) is not `Twe` (TwentyFiveGigE).
"""

import pytest

from network_analyser.records.interface_names import InterfaceName, interface_name


@pytest.mark.parametrize(
    ("reported", "short"),
    [
        ("GigabitEthernet1/0/1", "Gi1/0/1"),
        ("Gi1/0/1", "Gi1/0/1"),
        ("gigabitethernet0/0", "Gi0/0"),
        ("GigabitEthernet 1/0/24", "Gi1/0/24"),
        ("TenGigabitEthernet1/1/1", "Te1/1/1"),
        ("TwoGigabitEthernet1/0/3", "Tw1/0/3"),
        ("TwentyFiveGigE1/0/1", "Twe1/0/1"),
        ("Twe1/0/1", "Twe1/0/1"),
        ("FortyGigabitEthernet1/1/2", "Fo1/1/2"),
        ("HundredGigE1/0/49", "Hu1/0/49"),
        ("FastEthernet0/1", "Fa0/1"),
        ("Ethernet1/1", "Eth1/1"),
        ("Eth1/1", "Eth1/1"),
        ("Ethernet1/49/2", "Eth1/49/2"),
        ("Ethernet0/0", "Eth0/0"),
        ("port-channel10", "Po10"),
        ("Port-channel10", "Po10"),
        ("Po10", "Po10"),
        ("Port-channel10.200", "Po10.200"),
        ("GigabitEthernet0/1.100", "Gi0/1.100"),
        ("Vlan20", "Vl20"),
        ("Loopback0", "Lo0"),
        ("loopback0", "Lo0"),
        ("mgmt0", "mgmt0"),
        ("Tunnel5", "Tu5"),
        ("AppGigabitEthernet1/0/1", "Ap1/0/1"),
    ],
)
def test_a_known_name_gets_its_one_short_form_and_keeps_the_reported_one(
    reported: str, short: str
) -> None:
    assert interface_name(reported) == InterfaceName(short=short, reported=reported, known=True)


@pytest.mark.parametrize(
    "reported",
    ["WeirdPort1/1", "Gi", "Gigabit1/0/1", "GigabitEthernet1/x", "", "Gi1/0/1 extra", "Te1/1\x1b"],
)
def test_a_name_the_table_does_not_know_is_kept_exactly_as_reported(reported: str) -> None:
    assert interface_name(reported) == InterfaceName(short=reported, reported=reported, known=False)


def test_two_and_twenty_five_gigabit_ports_never_collide() -> None:
    assert interface_name("Tw1/0/1").short != interface_name("Twe1/0/1").short
