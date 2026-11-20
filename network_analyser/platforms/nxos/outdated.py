"""NX-OS's out-of-date Device Role record (story 80; #97, #98).

The Device Role is cut to the allow-list (ADR 0005), so a role generated before release
0.2.0 has no `rule permit command` line for the new show commands and refuses them. The
command's result is `Unknown`, never a pass. This module maps each new command to the Checks
that need it, so one record can say exactly what could not run and point at `role-snippet`.

The Check names are the ones spec #92 and ticket #102 use. Ticket #102 replaces them with its
own Check ids when it attaches the Checks; the list is the only place this module knows about
Analysis. The shared reading of denied commands is `platforms.collection.outdated_role`
(#97), so both Platforms report the Finding the same way.

SNMPv3 users are absent on purpose: they come from the running config, not from a command
(story 78), so no command of ours can be refused for them. The Guest Shell's fallback command
maps to the same Check, so one refused fallback never becomes a second Finding.
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
from network_analyser.platforms.nxos import commands as c
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
        c.SHOW_NTP_PEER_STATUS: ("NTP not synchronised",),
        c.SHOW_COPP_STATUS: ("CoPP not applied",),
        c.SHOW_SSH_KEY: ("SSH key under 2048 bits",),
        c.SHOW_GUESTSHELL: ("Guest Shell present",),
        c.SHOW_VIRTUAL_SERVICE_LIST: ("Guest Shell present",),
    }
)
"""Each 0.2.0 command and the Checks that cannot run without it (provisional: #102)."""


def role_out_of_date(collected: Collected) -> DeviceRoleOutOfDate | None:
    """Return the one record for a refused new command, or None when none was refused."""
    return outdated_role(collected, CHECK_NAMES_BY_COMMAND)
