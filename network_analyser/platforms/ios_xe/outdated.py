"""IOS/IOS-XE's out-of-date Device Role record (story 80; #97).

The Device Role is cut to the allow-list (ADR 0005), so a role generated before release
0.2.0 has no `commands exec include` line for the new show commands and refuses them. The
command's result is `Unknown`, never a pass. This module maps each new command to the Checks
that need it, so one record can say exactly what could not run and point at `role-snippet`.

The Check names are the ones spec #92 and ticket #102 use. Ticket #102 replaces them with its
own Check ids when it attaches the Checks; the list is the only place this module knows about
Analysis. Ticket #98 adds the NX-OS map, and #102 joins them at the `analysis` seam.
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from network_analyser.platforms.collection import (
    DEVICE_ROLE_CHECK,
    DEVICE_ROLE_LEVEL,
    DEVICE_ROLE_OUT_OF_DATE,
    DeviceRoleOutOfDate,
    outdated_role,
)
from network_analyser.platforms.ios_xe import commands as c
from network_analyser.records.collected import Collected

__all__ = [
    "CHECK_NAMES_BY_COMMAND",
    "DEVICE_ROLE_CHECK",
    "DEVICE_ROLE_LEVEL",
    "DEVICE_ROLE_OUT_OF_DATE",
    "DeviceRoleOutOfDate",
    "role_out_of_date",
]

CHECK_NAMES_BY_COMMAND: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        c.SHOW_INVENTORY: ("Hardware EoX",),
        c.SHOW_SNMP_USER: ("SNMPv3 users on MD5/DES/3DES",),
        c.SHOW_NTP_ASSOCIATIONS: ("NTP not synchronised",),
        c.SHOW_POLICY_MAP_CONTROL_PLANE: ("CoPP not applied",),
        c.SHOW_IP_SSH: ("SSH key under 2048 bits",),
        c.SHOW_SYSTEM_INSECURE_CONFIGURATION: ("Cisco insecure-list items",),
    }
)
"""Each 0.2.0 command and the Checks that cannot run without it (provisional: #102)."""


def role_out_of_date(collected: Collected) -> DeviceRoleOutOfDate | None:
    """Return the one record for a refused new command, or None when none was refused."""
    return outdated_role(collected, CHECK_NAMES_BY_COMMAND)
