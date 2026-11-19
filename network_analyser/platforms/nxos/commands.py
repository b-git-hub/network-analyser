"""The NX-OS allow-list: every command the tool may ever send to a Nexus.

Compiled in, never read from a file (story 56). Adding a command is a breaking change
(decision #32): bump the minor version and list it in CHANGELOG.md. Ticket #49 holds only
what identification needs; later tickets add entries (#51 the Backup, #60 collection).
"""

from typing import Final

from network_analyser.platforms.allowlist import AllowList, Exact, Template

TERMINAL_LENGTH: Final = "terminal length 0"
TERMINAL_WIDTH: Final = "terminal width 511"
SHOW_VERSION: Final = "show version"

USERNAME_PATTERN: Final = r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}"
"""An NX-OS username: a letter or digit, then letters, digits, `.`, `_` or `-`, 32 at most."""

SHOW_USER_ACCOUNT: Final = Template("show user-account {username}", {"username": USERNAME_PATTERN})
"""Reports the login's own roles (provisional: lab checks A5 and C10)."""
SHOW_RUNNING_CONFIG: Final = "show running-config"
"""The Backup (#51): the running config as NX-OS shows it."""
SHOW_CDP_NEIGHBORS_DETAIL: Final = "show cdp neighbors detail | json"
SHOW_LLDP_NEIGHBORS_DETAIL: Final = "show lldp neighbors detail | json"
"""The CDP and LLDP Neighbours the crawl follows (#50; the `| json` forms are provisional)."""

# Collection (#60): the `| json` form of each command, every VRF at once (`vrf all`), so no
# entry is a per-VRF template. The exact strings, and how RBAC rules match them, are
# provisional until the lab confirms them (lab checklist section I).
SHOW_FEATURE: Final = "show feature | json"
"""Which features are on, so a command for one that is off is not sent and its data is
"none" rather than unknown."""
SHOW_INTERFACE: Final = "show interface | json"
SHOW_INTERFACE_SWITCHPORT: Final = "show interface switchport | json"
SHOW_IP_INTERFACE: Final = "show ip interface vrf all | json"
SHOW_PORT_CHANNEL_SUMMARY: Final = "show port-channel summary | json"
SHOW_VLAN_BRIEF: Final = "show vlan brief | json"
SHOW_VRF: Final = "show vrf | json"
SHOW_VPC_BRIEF: Final = "show vpc brief | json"
SHOW_VPC_PEER_KEEPALIVE: Final = "show vpc peer-keepalive | json"
SHOW_IP_ARP: Final = "show ip arp vrf all | json"
SHOW_MAC_ADDRESS_TABLE: Final = "show mac address-table | json"
SHOW_IP_OSPF_NEIGHBORS: Final = "show ip ospf neighbors vrf all | json"
SHOW_IP_EIGRP_NEIGHBORS: Final = "show ip eigrp neighbors vrf all | json"
SHOW_IP_BGP_SUMMARY: Final = "show ip bgp summary vrf all | json"
SHOW_IP_ROUTE_STATIC: Final = "show ip route static vrf all | json"
SHOW_HSRP_BRIEF: Final = "show hsrp brief | json"
SHOW_VRRP: Final = "show vrrp | json"

COLLECTION: Final = (
    SHOW_FEATURE,
    SHOW_INTERFACE,
    SHOW_INTERFACE_SWITCHPORT,
    SHOW_IP_INTERFACE,
    SHOW_PORT_CHANNEL_SUMMARY,
    SHOW_VLAN_BRIEF,
    SHOW_VRF,
    SHOW_VPC_BRIEF,
    SHOW_VPC_PEER_KEEPALIVE,
    SHOW_IP_ARP,
    SHOW_MAC_ADDRESS_TABLE,
    SHOW_IP_OSPF_NEIGHBORS,
    SHOW_IP_EIGRP_NEIGHBORS,
    SHOW_IP_BGP_SUMMARY,
    SHOW_IP_ROUTE_STATIC,
    SHOW_HSRP_BRIEF,
    SHOW_VRRP,
)
"""Every collection command, in the order they are sent after the Backup. The CDP and LLDP
tables are not among them: the crawl reads those before the Backup (#50)."""

ALLOW_LIST: Final = AllowList(
    (
        Exact(TERMINAL_LENGTH),
        Exact(TERMINAL_WIDTH),
        Exact(SHOW_VERSION),
        SHOW_USER_ACCOUNT,
        Exact(SHOW_RUNNING_CONFIG),
        Exact(SHOW_CDP_NEIGHBORS_DETAIL),
        Exact(SHOW_LLDP_NEIGHBORS_DETAIL),
        *(Exact(command) for command in COLLECTION),
    )
)
