"""The IOS/IOS-XE allow-list: every command the tool may ever send to a Catalyst.

Compiled in, never read from a file (story 56). Adding a command is a breaking change
(decision #32): bump the minor version and list it in CHANGELOG.md. Ticket #49 holds only
what identification needs; later tickets add entries.

The collection commands (#59; spec #37 "Data the allow-list must cover"; catalogue on #4)
are provisional until lab check B1 confirms each string. The per-VRF forms are templates
whose one parameter is a VRF name from `show vrf`, matched against `VRF_PATTERN`; a VRF whose
name does not fit is never queried, and its data is recorded as unknown.
"""

from typing import Final

from network_analyser.platforms.allowlist import AllowList, Exact, Template

TERMINAL_LENGTH: Final = "terminal length 0"
TERMINAL_WIDTH: Final = "terminal width 511"
SHOW_VERSION: Final = "show version"
SHOW_PRIVILEGE: Final = "show privilege"
"""Reports the landing privilege level (provisional: lab checks A5 and C6)."""
SHOW_RUNNING_CONFIG: Final = "show running-config view full"
"""The Backup (#51, story 96): always `view full`, so a CLI view user gets the whole config,
never the parts its view happens to cover. Plain `show running-config` is never sent."""
SHOW_CDP_NEIGHBORS_DETAIL: Final = "show cdp neighbors detail"
SHOW_LLDP_NEIGHBORS_DETAIL: Final = "show lldp neighbors detail"
"""The CDP and LLDP Neighbours the crawl follows (#50); the gateway reads them before the
Backup, so the collection (#59) never sends them again."""

# -- Collection (#59) ------------------------------------------------------------------------

SHOW_INTERFACES: Final = "show interfaces"
SHOW_INTERFACES_SWITCHPORT: Final = "show interfaces switchport"
SHOW_INTERFACES_TRUNK: Final = "show interfaces trunk"
SHOW_IP_INTERFACE: Final = "show ip interface"
"""Not `brief`: only the full form gives masks, secondaries, unnumbered and the VRF."""
SHOW_ETHERCHANNEL_SUMMARY: Final = "show etherchannel summary"
SHOW_VLAN_BRIEF: Final = "show vlan brief"
SHOW_VRF: Final = "show vrf"
SHOW_IP_ARP: Final = "show ip arp"
SHOW_MAC_ADDRESS_TABLE: Final = "show mac address-table"
SHOW_IP_OSPF_NEIGHBOR: Final = "show ip ospf neighbor"
"""Every OSPF process, VRFs included; a neighbour's VRF is its interface's."""
SHOW_IP_EIGRP_NEIGHBORS: Final = "show ip eigrp neighbors"
SHOW_IP_BGP_SUMMARY: Final = "show ip bgp summary"
SHOW_IP_ROUTE_STATIC: Final = "show ip route static"
SHOW_STANDBY_BRIEF: Final = "show standby brief"
SHOW_VRRP_BRIEF: Final = "show vrrp brief"
SHOW_GLBP_BRIEF: Final = "show glbp brief"

# -- The 0.2.0 Analysis commands (#97; spec #92) ---------------------------------------------

SHOW_INVENTORY: Final = "show inventory"
"""The chassis, stack-member, supervisor and line-card PIDs the EoX Check sends (story 14)."""
SHOW_SNMP_USER: Final = "show snmp user"
"""SNMPv3 users and their authentication and privacy protocols (story 60)."""
SHOW_NTP_ASSOCIATIONS: Final = "show ntp associations"
"""Which NTP peer, if any, the device is synchronised to (story 60)."""
SHOW_POLICY_MAP_CONTROL_PLANE: Final = "show policy-map control-plane"
"""The control-plane service policy, for the CoPP Check (story 60)."""
SHOW_IP_SSH: Final = "show ip ssh"
"""SSH's version and, on IOS-XE 17.11 and later, the RSA host key's modulus size.

Chosen over `show crypto key mypubkey rsa` because Cisco documents this command's `Modulus
Size` line for the SSH key-size Check (field notice FN-72511), and it also reports whether
SSH is enabled. Where a release does not print the modulus, the key size is `Unknown` and
the Check is "could not decide", never a pass; lab check K5 confirms whether the other
command is the better source on the fleet's releases."""
SHOW_SYSTEM_INSECURE_CONFIGURATION: Final = "show system insecure configuration"
"""Cisco's own list of configured insecure features. IOS-XE 17.18.2 and later only, so it is
sent only when the release allows it (story 68); never on classic IOS."""

VRF_PATTERN: Final = r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}"
"""A VRF name the tool will put in a command: one word of at most 32 characters."""

SHOW_IP_ARP_VRF: Final = Template("show ip arp vrf {vrf}", {"vrf": VRF_PATTERN})
SHOW_IP_EIGRP_VRF_NEIGHBORS: Final = Template(
    "show ip eigrp vrf {vrf} neighbors", {"vrf": VRF_PATTERN}
)
SHOW_IP_BGP_VPNV4_VRF_SUMMARY: Final = Template(
    "show ip bgp vpnv4 vrf {vrf} summary", {"vrf": VRF_PATTERN}
)
SHOW_IP_ROUTE_VRF_STATIC: Final = Template("show ip route vrf {vrf} static", {"vrf": VRF_PATTERN})

ALLOW_LIST: Final = AllowList(
    (
        Exact(TERMINAL_LENGTH),
        Exact(TERMINAL_WIDTH),
        Exact(SHOW_VERSION),
        Exact(SHOW_PRIVILEGE),
        Exact(SHOW_RUNNING_CONFIG),
        Exact(SHOW_CDP_NEIGHBORS_DETAIL),
        Exact(SHOW_LLDP_NEIGHBORS_DETAIL),
        Exact(SHOW_INTERFACES),
        Exact(SHOW_INTERFACES_SWITCHPORT),
        Exact(SHOW_INTERFACES_TRUNK),
        Exact(SHOW_IP_INTERFACE),
        Exact(SHOW_ETHERCHANNEL_SUMMARY),
        Exact(SHOW_VLAN_BRIEF),
        Exact(SHOW_VRF),
        Exact(SHOW_IP_ARP),
        SHOW_IP_ARP_VRF,
        Exact(SHOW_MAC_ADDRESS_TABLE),
        Exact(SHOW_IP_OSPF_NEIGHBOR),
        Exact(SHOW_IP_EIGRP_NEIGHBORS),
        SHOW_IP_EIGRP_VRF_NEIGHBORS,
        Exact(SHOW_IP_BGP_SUMMARY),
        SHOW_IP_BGP_VPNV4_VRF_SUMMARY,
        Exact(SHOW_IP_ROUTE_STATIC),
        SHOW_IP_ROUTE_VRF_STATIC,
        Exact(SHOW_STANDBY_BRIEF),
        Exact(SHOW_VRRP_BRIEF),
        Exact(SHOW_GLBP_BRIEF),
        Exact(SHOW_INVENTORY),
        Exact(SHOW_SNMP_USER),
        Exact(SHOW_NTP_ASSOCIATIONS),
        Exact(SHOW_POLICY_MAP_CONTROL_PLANE),
        Exact(SHOW_IP_SSH),
        Exact(SHOW_SYSTEM_INSECURE_CONFIGURATION),
    )
)
