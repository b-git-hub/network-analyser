"""NX-OS's out-of-date Device Role record (story 80; #97, #98).

The Device Role is cut to the allow-list (ADR 0005), so a role generated before release
0.2.0 has no `rule permit command` line for the new show commands and refuses them. The
command's result is `Unknown`, never a pass. This module maps each new command to the Checks
that need it, so one record can say exactly what could not run and point at `role-snippet`.

The Check ids are the final ones ticket #102 attached (in `analysis.catalogue`); the list is
the only place this module knows about Analysis. The shared reading of denied commands is
`platforms.collection.outdated_role` (#97), so both Platforms report the Finding the same way.

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
    DeviceRoleOutOfDate,
    outdated_role,
)
from network_analyser.platforms.nxos import commands as c
from network_analyser.records.analysis import DEVICE_ROLE_CHECKS_BY_DATA
from network_analyser.records.collected import Collected

__all__ = [
    "CHECK_IDS_BY_COMMAND",
    "DEVICE_ROLE_CHECK",
    "DEVICE_ROLE_LEVEL",
    "DeviceRoleOutOfDate",
    "role_out_of_date",
]

CHECK_IDS_BY_COMMAND: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        c.SHOW_INVENTORY: DEVICE_ROLE_CHECKS_BY_DATA["inventory"],
        c.SHOW_NTP_PEER_STATUS: DEVICE_ROLE_CHECKS_BY_DATA["ntp_associations"],
        c.SHOW_COPP_STATUS: DEVICE_ROLE_CHECKS_BY_DATA["control_plane"],
        c.SHOW_SSH_KEY: DEVICE_ROLE_CHECKS_BY_DATA["ssh"],
        c.SHOW_GUESTSHELL: DEVICE_ROLE_CHECKS_BY_DATA["guest_shell"],
        c.SHOW_VIRTUAL_SERVICE_LIST: DEVICE_ROLE_CHECKS_BY_DATA["guest_shell"],
    }
)
"""Each 0.2.0 command and the stable Check ids that cannot run without it (#102).

The ids come from the shared Device Role contract in `records.analysis`, so this map and
Analysis cannot drift apart."""


def role_out_of_date(collected: Collected) -> DeviceRoleOutOfDate | None:
    """Return the one record for a refused new command, or None when none was refused."""
    return outdated_role(collected, CHECK_IDS_BY_COMMAND)
