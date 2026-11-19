"""A Neighbour's Platform hint, before any login (ticket #50; stories 62-63; decided on #10).

The hint comes from the CDP Platform and Version, or the LLDP System Description, matched
against the patterns compiled in here, and from the capabilities advertised:

- a supported Platform: the crawl logs in;
- a known unsupported one (Palo Alto, ASA/FTD, IOS-XR, Meraki, phones, lightweight access
  points, hosts): an Unvisited Device, never logged into;
- no hint, or one not recognised (None): logged into only if its SSH identification string
  looks like a supported Platform.

Unsupported patterns are checked first, so an access point or IOS-XR box whose text also
says "Cisco IOS Software" is never taken for a Catalyst. The patterns are provisional until
the lab confirms them (lab checklist).
"""

import re
from typing import Final

from network_analyser.platforms.identify import Unsupported
from network_analyser.records import Platform
from network_analyser.records.neighbour import NeighbourRecord

_UNSUPPORTED_TEXT: Final = (
    ("PAN-OS", re.compile(r"Palo Alto Networks|\bPAN-OS\b|\bPA-\d{3,4}\b")),
    ("ASA", re.compile(r"Cisco Adaptive Security Appliance|\bASA ?\d{4}")),
    ("FTD", re.compile(r"Firepower Threat Defense|Cisco Secure Firewall|\bFPR-?\d{4}")),
    ("IOS-XR", re.compile(r"\bIOS[ -]XR\b")),
    ("Meraki", re.compile(r"\bMeraki\b", re.IGNORECASE)),
    ("phone", re.compile(r"\bIP Phone\b|\bIP Conference Phone\b|\bCP-\d{4}\b")),
    (
        "access point",
        re.compile(r"Cisco AP Software|\bAIR-C?AP|\bAP\dG\d|K9W8|\bC91\d{2}AX", re.IGNORECASE),
    ),
    (
        "host",
        re.compile(
            r"\bVMware ESX|\bMicrosoft Windows\b|\bUbuntu\b|\bDebian\b|\bRed Hat\b|\bCentOS\b"
            r"|\bAlpine Linux\b"
        ),
    ),
)

_SUPPORTED_TEXT: Final = (
    (Platform.NX_OS, re.compile(r"Cisco Nexus Operating System|\bNX-OS\b|\bNexus\d*\b|\bN\dK-")),
    (Platform.IOS_XE, re.compile(r"Cisco IOS XE Software|IOS-XE Software|Cisco IOS Software")),
)

# Capabilities: CDP words and LLDP enabled-capability codes (IEEE 802.1AB).
_PHONE: Final = frozenset({"phone", "t"})
_ACCESS_POINT: Final = frozenset({"w"})
_HOST: Final = frozenset({"host", "s"})
_NETWORK: Final = frozenset({"router", "switch", "r", "b", "trans-bridge", "source-route-bridge"})


def neighbour_hint(neighbour: NeighbourRecord) -> Platform | Unsupported | None:
    """Return the Platform a Neighbour advertises, a known unsupported one, or None."""
    text = " ".join(t for t in (neighbour.platform, neighbour.description) if t)
    for name, pattern in _UNSUPPORTED_TEXT:
        if pattern.search(text):
            return Unsupported(name)
    capabilities = {c.lower() for c in neighbour.capabilities}
    if capabilities & _PHONE:
        return Unsupported("phone")
    if not capabilities & _NETWORK:
        if capabilities & _ACCESS_POINT:
            return Unsupported("access point")
        if capabilities & _HOST:
            return Unsupported("host")
    return next((p for p, pattern in _SUPPORTED_TEXT if pattern.search(text)), None)
