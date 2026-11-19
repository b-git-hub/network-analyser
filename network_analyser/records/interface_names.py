"""The fixed interface short-name table (spec #37 story 127; decided on #11).

The short form is canonical: both ends of a Link must name a port the same way, whichever
Platform reported it and whether CDP sent the long name or LLDP a short one. So one table
covers IOS/IOS-XE and NX-OS, and maps each long name, and each abbreviation a device is known
to send, to one short form. There is no general rule, because one would collide (`Tw` is
TwoGigabitEthernet, `Twe` is TwentyFiveGigE).

`Ethernet` becomes `Eth` on every Platform (NX-OS `Eth1/1`, and IOS `Ethernet0/0` too), so
the two ends always agree. A name the table does not know is kept exactly as reported, matched
only exactly, and listed in the Topology so the report can show it. New types are added to
the table in later releases (a new entry changes no existing short name).

The platform parsers (#59, #60) build every `InterfaceName` with `interface_name`.
"""

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

_SHORT: Final = MappingProxyType(
    {
        long.lower(): short
        for short, names in {
            "Fa": ("FastEthernet", "Fa"),
            "Gi": ("GigabitEthernet", "Gig", "Gi"),
            "Tw": ("TwoGigabitEthernet", "Tw"),
            "Fi": ("FiveGigabitEthernet", "Fi"),
            "Te": ("TenGigabitEthernet", "TenGigE", "Te"),
            "Twe": ("TwentyFiveGigE", "TwentyFiveGigabitEthernet", "Twe"),
            "Fo": ("FortyGigabitEthernet", "FortyGigE", "Fo"),
            "Hu": ("HundredGigabitEthernet", "HundredGigE", "Hu"),
            "Ap": ("AppGigabitEthernet", "Ap"),
            "Eth": ("Ethernet", "Eth", "Et"),
            "Po": ("Port-channel", "Po"),
            "Vl": ("Vlan", "Vl"),
            "Lo": ("Loopback", "Lo"),
            "Tu": ("Tunnel", "Tu"),
            "mgmt": ("mgmt",),
            "nve": ("nve",),
        }.items()
        for long in names
    }
)
"""Every known type name or abbreviation, lowercased, to its canonical short form."""

# A type name, an optional space, then numbers: `1`, `1/0/1`, `1/49/2`, a `.100` sub-
# interface or a `:1` breakout.
_NAME: Final = re.compile(r"([A-Za-z][A-Za-z-]*) ?(\d+(?:/\d+)*(?:[.:]\d+)?)")


@dataclass(frozen=True, slots=True)
class InterfaceName:
    """An interface's name: the canonical short form and the name as the device reported it.

    Attributes:
        short: the canonical short form, such as `Gi1/0/1`, `Eth1/1` or `Po10`; for a name the
            table does not know, the name exactly as reported.
        reported: the name exactly as the device reported it.
        known: False when the table did not know the name, so it is matched only exactly and
            listed in the report (story 127).
    """

    short: str
    reported: str
    known: bool


def interface_name(reported: str) -> InterfaceName:
    """Return `reported` with its canonical short form from the fixed table."""
    match = _NAME.fullmatch(reported)
    short = _SHORT.get(match.group(1).lower()) if match else None
    if match is None or short is None:
        return InterfaceName(short=reported, reported=reported, known=False)
    return InterfaceName(short=f"{short}{match.group(2)}", reported=reported, known=True)
