"""Hand-written, synthetic IOS/IOS-XE command output for the collection tests (#59).

Shaped like Catalyst output so the parsers have something to read, never captured from a
device (CLAUDE.md): made-up hostnames (`sw-a`, `sw-b`, `rtr-c`), RFC 5737 IPv4 addresses,
RFC 3849 IPv6 addresses and RFC 7042 documentation MAC addresses (`0000.5e00.53xx`).

The device is `sw-a`, a two-switch stack (`device_text.IOS_XE_SHOW_VERSION`): Po10 bundles
Gi1/0/1 and Gi2/0/1 to `sw-b`; Gi1/0/2 is a shut access port in VLAN 10; Vlan10 has a
secondary address and HSRP; Vlan20 is in VRF `BLUE` with VRRP and GLBP; Te1/1/1 is
unnumbered; Gi0/0 is the management port in `Mgmt-intf`.
"""

SHOW_INTERFACES = """\
GigabitEthernet0/0 is up, line protocol is up
  Hardware is RP management port, address is 0000.5e00.5300 (bia 0000.5e00.5300)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full Duplex, 1000Mbps, link type is auto, media type is RJ45
GigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is 0000.5e00.5301 (bia 0000.5e00.5301)
  Description: to sw-b Gi1/0/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
GigabitEthernet1/0/2 is administratively down, line protocol is down (disabled)
  Hardware is Gigabit Ethernet, address is 0000.5e00.5302 (bia 0000.5e00.5302)
  Description: spare
  MTU 1500 bytes, BW 10000 Kbit/sec, DLY 1000 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Auto-duplex, Auto-speed, media type is 10/100/1000BaseTX
GigabitEthernet2/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is 0000.5e00.5303 (bia 0000.5e00.5303)
  Description: to sw-b Gi2/0/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX
TenGigabitEthernet1/1/1 is up, line protocol is up (connected)
  Hardware is Ten Gigabit Ethernet, address is 0000.5e00.5304 (bia 0000.5e00.5304)
  Description: to rtr-c
  MTU 1500 bytes, BW 10000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full-duplex, 10Gb/s, link type is auto, media type is SFP-10GBase-SR
Port-channel10 is up, line protocol is up (connected)
  Hardware is EtherChannel, address is 0000.5e00.5305 (bia 0000.5e00.5305)
  Description: to sw-b
  MTU 1500 bytes, BW 2000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full-duplex, 1000Mb/s, link type is auto, media type is N/A
  Members in this channel: Gi1/0/1 Gi2/0/1
Vlan10 is up, line protocol is up
  Hardware is Ethernet SVI, address is 0000.5e00.5306 (bia 0000.5e00.5306)
  Description: users
  Internet address is 192.0.2.1/25
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
Vlan20 is up, line protocol is up
  Hardware is Ethernet SVI, address is 0000.5e00.5307 (bia 0000.5e00.5307)
  Internet address is 198.51.100.1/24
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
Loopback0 is up, line protocol is up
  Hardware is Loopback
  Internet address is 192.0.2.250/32
  MTU 1514 bytes, BW 8000000 Kbit/sec, DLY 5000 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation LOOPBACK, loopback not set
"""

SHOW_INTERFACES_SWITCHPORT = """\
Name: Gi1/0/1
Switchport: Enabled
Administrative Mode: trunk
Operational Mode: trunk (member of bundle Po10)
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: dot1q
Negotiation of Trunking: On
Access Mode VLAN: 1 (default)
Trunking Native Mode VLAN: 99 (NATIVE)
Administrative Native VLAN tagging: enabled
Voice VLAN: none
Administrative private-vlan host-association: none
Administrative private-vlan mapping: none
Operational private-vlan: none
Trunking VLANs Enabled: 10,20,30-32
Pruning VLANs Enabled: 2-1001
Capture Mode Disabled
Capture VLANs Allowed: ALL

Name: Gi1/0/2
Switchport: Enabled
Administrative Mode: static access
Operational Mode: down
Administrative Trunking Encapsulation: dot1q
Negotiation of Trunking: Off
Access Mode VLAN: 10 (users)
Trunking Native Mode VLAN: 1 (default)
Administrative Native VLAN tagging: enabled
Voice VLAN: none
Trunking VLANs Enabled: ALL
Pruning VLANs Enabled: 2-1001

Name: Gi2/0/1
Switchport: Enabled
Administrative Mode: trunk
Operational Mode: trunk (member of bundle Po10)
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: dot1q
Negotiation of Trunking: On
Access Mode VLAN: 1 (default)
Trunking Native Mode VLAN: 99 (NATIVE)
Voice VLAN: none
Trunking VLANs Enabled: 10,20,30-32
Pruning VLANs Enabled: 2-1001

Name: Te1/1/1
Switchport: Disabled

Name: Po10
Switchport: Enabled
Administrative Mode: trunk
Operational Mode: trunk
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: dot1q
Negotiation of Trunking: On
Access Mode VLAN: 1 (default)
Trunking Native Mode VLAN: 99 (NATIVE)
Voice VLAN: none
Trunking VLANs Enabled: 10,20,30-32
Pruning VLANs Enabled: 2-1001
"""

SHOW_INTERFACES_TRUNK = """\

Port        Mode             Encapsulation  Status        Native vlan
Po10        on               802.1q         trunking      99

Port        Vlans allowed on trunk
Po10        10,20,30-32

Port        Vlans allowed and active in management domain
Po10        10,20

Port        Vlans in spanning tree forwarding state and not pruned
Po10        10,20
"""

SHOW_IP_INTERFACE = """\
GigabitEthernet0/0 is up, line protocol is up
  Internet address is 203.0.113.10/24
  Broadcast address is 255.255.255.255
  Address determined by non-volatile memory
  MTU is 1500 bytes
  Helper address is not set
  VPN Routing/Forwarding "Mgmt-intf"
GigabitEthernet1/0/1 is up, line protocol is up
  Internet protocol processing disabled
GigabitEthernet1/0/2 is administratively down, line protocol is down
  Internet protocol processing disabled
GigabitEthernet2/0/1 is up, line protocol is up
  Internet protocol processing disabled
TenGigabitEthernet1/1/1 is up, line protocol is up
  Interface is unnumbered. Using address of Loopback0 (192.0.2.250)
  MTU is 1500 bytes
Port-channel10 is up, line protocol is up
  Internet protocol processing disabled
Vlan10 is up, line protocol is up
  Internet address is 192.0.2.1/25
  Broadcast address is 255.255.255.255
  Address determined by non-volatile memory
  MTU is 1500 bytes
  Helper address is not set
  Directed broadcast forwarding is disabled
  Secondary address 203.0.113.129/25
  Outgoing Common access list is not set
Vlan20 is up, line protocol is up
  Internet address is 198.51.100.1/24
  Broadcast address is 255.255.255.255
  MTU is 1500 bytes
  VPN Routing/Forwarding "BLUE"
Loopback0 is up, line protocol is up
  Internet address is 192.0.2.250/32
  Broadcast address is 255.255.255.255
  MTU is 1514 bytes
"""

SHOW_ETHERCHANNEL_SUMMARY = """\
Flags:  D - down        P - bundled in port-channel
        I - stand-alone s - suspended
        H - Hot-standby (LACP only)
        R - Layer3      S - Layer2
        U - in use      f - failed to allocate aggregator

        M - not in use, minimum links not met
        u - unsuitable for bundling
        w - waiting to be aggregated
        d - default port

        A - formed by Auto LAG


Number of channel-groups in use: 1
Number of aggregators:           1

Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
10     Po10(SU)        LACP        Gi1/0/1(P)      Gi2/0/1(D)
"""

SHOW_VLAN_BRIEF = """\

VLAN Name                             Status    Ports
---- -------------------------------- --------- -------------------------------
1    default                          active    Gi1/0/3, Gi1/0/4
10   users                            active    Gi1/0/2
20   servers                          active
99   NATIVE                           active
1002 fddi-default                     act/unsup
"""

SHOW_VRF = """\
  Name                             Default RD            Protocols   Interfaces
  BLUE                             65000:1               ipv4        Vl20
  Mgmt-intf                        <not set>             ipv4,ipv6   Gi0/0
  V6ONLY                           65000:6               ipv6
"""

SHOW_IP_ARP = """\
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.0.2.1               -   0000.5e00.5306  ARPA   Vlan10
Internet  192.0.2.20             12   0000.5e00.5320  ARPA   Vlan10
Internet  192.0.2.30              3   Incomplete      ARPA
"""

SHOW_IP_ARP_VRF_BLUE = """\
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  198.51.100.20           5   0000.5e00.5321  ARPA   Vlan20
"""

SHOW_IP_ARP_VRF_MGMT = """\
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  203.0.113.1             1   0000.5e00.5322  ARPA   GigabitEthernet0/0
"""

SHOW_MAC_ADDRESS_TABLE = """\
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0000.5e00.53f0    STATIC      CPU
  10    0000.5e00.5320    DYNAMIC     Gi1/0/2
  10    0000.5e00.5330    DYNAMIC     Po10
  20    0000.5e00.5321    STATIC      Gi1/0/1
Total Mac Addresses for this criterion: 4
"""

SHOW_IP_OSPF_NEIGHBOR = """\

Neighbor ID     Pri   State           Dead Time   Address         Interface
192.0.2.251       1   FULL/DR         00:00:33    198.51.100.2    Vlan20
192.0.2.252       0   FULL/  -        00:00:37    192.0.2.254     TenGigabitEthernet1/1/1
"""

SHOW_IP_EIGRP_NEIGHBORS = """\
EIGRP-IPv4 Neighbors for AS(100)
H   Address                 Interface              Hold Uptime   SRTT   RTO  Q  Seq
                                                   (sec)         (ms)       Cnt Num
0   192.0.2.2               Vl10                     13 01:02:03    1   100  0  7
"""

SHOW_IP_EIGRP_VRF_BLUE_NEIGHBORS = """\
EIGRP-IPv4 VR(BLUE) Address-Family Neighbors for AS(200)
           VRF(BLUE)
H   Address                 Interface              Hold Uptime   SRTT   RTO  Q  Seq
                                                   (sec)         (ms)       Cnt Num
0   198.51.100.3            Vl20                     12 00:10:00    2   100  0  4
"""

SHOW_IP_BGP_SUMMARY = """\
BGP router identifier 192.0.2.250, local AS number 65000
BGP table version is 5, main routing table version 5
3 network entries using 744 bytes of memory

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.0.2.3       4        65001     100     101        5    0    0 01:00:00        3
192.0.2.4       4        65002       0       0        1    0    0 never    Idle
"""

SHOW_IP_BGP_VPNV4_VRF_BLUE_SUMMARY = """\
BGP router identifier 192.0.2.250, local AS number 65000
BGP table version is 9, main routing table version 9

Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
198.51.100.4    4        65003      50      52        9    0    0 00:30:00        2
"""

SHOW_IP_ROUTE_STATIC = """\
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
       * - candidate default, U - per-user static route, o - ODR
       P - periodic downloaded static route, H - NHRP, l - LISP
       + - replicated route, % - next hop override, p - overrides from PfR

Gateway of last resort is 192.0.2.126 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 192.0.2.126
      203.0.113.0/24 is variably subnetted, 2 subnets, 2 masks
S        203.0.113.64/26 [1/0] via 192.0.2.125
S        203.0.113.128/26 is directly connected, Vlan10
"""

SHOW_IP_ROUTE_VRF_BLUE_STATIC = """\

Routing Table: BLUE
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       * - candidate default, U - per-user static route, o - ODR

Gateway of last resort is not set

      198.51.100.0/24 is variably subnetted, 2 subnets, 2 masks
S        198.51.100.128/25 [1/0] via 198.51.100.254
"""

SHOW_STANDBY_BRIEF = """\
                     P indicates configured to preempt.
                     |
Interface   Grp  Pri P State   Active          Standby         Virtual IP
Vl10        10   110 P Active  local           192.0.2.2       192.0.2.126
"""

SHOW_VRRP_BRIEF = """\
Interface          Grp A-F Pri  Time Own Pre State   Master addr/Group addr
Vl20                20 IPv4 100     0  N   Y  MASTER  198.51.100.1(local) 198.51.100.254
"""

SHOW_GLBP_BRIEF = """\
Interface   Grp  Fwd Pri State    Address         Active router   Standby router
Vl20        30   -   100 Active   198.51.100.253  local           198.51.100.2
Vl20        30   1   -   Active   0007.b400.1e01  local           -
"""

SHOW_CDP_NEIGHBORS_DETAIL = """\
-------------------------
Device ID: sw-b.example.net
Entry address(es):
  IP address: 192.0.2.2
  IP address: 198.51.100.2
  IPv6 address: 2001:db8::2  (global unicast)
Platform: cisco C9300-48P,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/24
Holdtime : 150 sec

Version :
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a

advertisement version: 2
VTP Management Domain: ''
Native VLAN: 99
Duplex: full
Management address(es):
  IP address: 203.0.113.2

-------------------------
Device ID: rtr-c
Entry address(es):
  IP address: 192.0.2.254
Platform: cisco C8000V,  Capabilities: Router IGMP
Interface: TenGigabitEthernet1/1/1,  Port ID (outgoing port): GigabitEthernet2
Holdtime : 120 sec

Version :
Cisco IOS Software [Dublin], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M)

advertisement version: 2
Duplex: full
Management address(es):

Total cdp entries displayed : 2
"""

SHOW_LLDP_NEIGHBORS_DETAIL = """\
------------------------------------------------
Local Intf: Gi1/0/1
Chassis id: 0000.5e00.5340
Port id: Gi1/0/24
Port Description: to sw-a
System Name: sw-b.example.net

System Description:
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a
Technical Support: http://www.cisco.com/techsupport

Time remaining: 100 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Management Addresses:
    IP: 203.0.113.2
    IPV6: 2001:db8::2
Auto Negotiation - not supported
Physical media capabilities - not advertised
Media Attachment Unit type - not advertised
Vlan ID: - not advertised

------------------------------------------------
Local Intf: Gi1/0/2
Chassis id: 0000.5e00.5350
Port id: 0000.5e00.5351
Port Description: eth0
System Name: - not advertised

System Description - not advertised

Time remaining: 90 seconds
System Capabilities - not advertised
Enabled Capabilities - not advertised
Management Addresses - not advertised
Auto Negotiation - supported, enabled
Vlan ID: - not advertised


Total entries displayed: 2
"""

# -- The 0.2.0 read-only commands (#97) -------------------------------------------------------

SHOW_INVENTORY = """\
NAME: "Chassis", DESCR: "Cisco Catalyst 9300 48-port GbE switch"
PID: C9300-48P, VID: V02, SN: TEST0000A01

NAME: "Switch 1", DESCR: "Cisco Catalyst 9300 48-port GbE switch"
PID: C9300-48P, VID: V02, SN: TEST0000A01

NAME: "Switch 2", DESCR: "Cisco Catalyst 9300 48-port GbE switch"
PID: C9300-48P, VID: V02, SN: TEST0000A02

NAME: "Slot 1 - Supervisor Module", DESCR: "Supervisor Module"
PID: C9400-SUP-1XL, VID: V01, SN: TEST0000A03

NAME: "Slot 2 - Line Card 1", DESCR: "48-port GbE line card"
PID: C9400-LC-48U, VID: V01, SN: TEST0000A04

NAME: "Switch 1 - Power Supply A", DESCR: "Power supply"
PID: PWR-C1-715WAC, VID: V01, SN: TEST0000A05

NAME: "Switch 1 - Fan Tray 1", DESCR: "Fan tray"
PID: C9300-FAN, VID: V01, SN: TEST0000A06

NAME: "GigabitEthernet1/0/1", DESCR: "SFP transceiver"
PID: SFP-10G-SR, VID: V03, SN: TEST0000A07
"""
"""Chassis, stack members, a supervisor and a line card; PSU, fan and optic are left out."""

SHOW_SNMP_USER = """\
User name: netops-ro
Engine ID: 80000009030000005E005300
storage-type: nonvolatile        active
Authentication Protocol: SHA-256
Privacy Protocol: AES256
Group-name: NA-RO

User name: legacy-user
Engine ID: 80000009030000005E005300
storage-type: nonvolatile        active
Authentication Protocol: MD5
Privacy Protocol: DES
Group-name: NA-RO
"""

SHOW_NTP_ASSOCIATIONS = """\
      address         ref clock     st   when   poll reach  delay  offset   disp
 *~192.0.2.1        .GPS.            1     35     64   377   1.234   0.567   0.890
 +~198.51.100.1     .GPS.            2     41     64   377   2.345  -0.123   1.010
 * sys.peer, # selected, + candidate, - outlyer, x falseticker, ~ configured
"""

SHOW_POLICY_MAP_CONTROL_PLANE = """\
Control Plane
  Service-policy input: NA-COPP

  Class-map: NA-COPP-class (match-any)
    0 packets, 0 bytes
    30 second offered rate 0000 bps
"""

SHOW_IP_SSH = """\
SSH Enabled - version 2.0
Authentication methods:publickey,keyboard-interactive,password
Authentication Publickey Algorithms:x509v3-ssh-rsa,ssh-rsa
Hostkey Algorithms:x509v3-ssh-rsa,ssh-rsa
Encryption Algorithms:aes128-ctr,aes192-ctr,aes256-ctr
MAC Algorithms:hmac-sha2-256,hmac-sha2-512
Authentication timeout: 120 secs; Authentication retries: 3
Minimum expected Diffie Hellman key size : 2048 bits
IOS Keys in SECSH format(ssh-rsa, base64 encoded): NONE
Modulus Size : 2048 bits
"""

SHOW_IP_SSH_WITHOUT_MODULUS = """\
SSH Enabled - version 1.99
Authentication timeout: 120 secs; Authentication retries: 3
Minimum expected Diffie Hellman key size : 1024 bits
IOS Keys in SECSH format(ssh-rsa, base64 encoded): ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ
"""
"""Classic IOS: the host key's modulus is not printed at all (#97, lab check K5)."""

SHOW_SYSTEM_INSECURE_CONFIGURATION = """\
=============================================================
          ACTIVE INSECURE CONFIGURATION DATABASE
=============================================================
Generated: Active Configuration Analysis
Total Active Insecure Commands: 2
Database Type: Active (Current State)
Scan Status: Complete
Next Update: No pending updates
Database State: Stable
=============================================================
SECURE_CONFIG_ACTIVE_INSECURE_CONFIG_DB_WALK: Processing 2 active insecure CLI entries

+-------------------------------------------------------------
| ACTIVE INSECURE CONFIGURATION ENTRY [1/2]
+-------------------------------------------------------------
|               Module: FTP
|       Parent Command: NA
|          CLI Command: ip ftp source-interface GigabitEthernet0/0
|          Description: FTP service enabled - transmits credentials in plaintext
|               Reason: No encryption is configured
|          Remediation: Transition to secure file transfer methods
|          Config Mode: configure
|               Status: ACTIVE
|             Severity: HIGH
+-------------------------------------------------------------
SECURE_CONFIG_ACTIVE_INSECURE_CONFIG_DB_WALK: Processed entry 1: ip ftp source-interface Gi0/0

+-------------------------------------------------------------
| ACTIVE INSECURE CONFIGURATION ENTRY [2/2]
+-------------------------------------------------------------
|               Module: SNMP
|       Parent Command: NA
|          CLI Command: snmp-server community <STRING> RO
|               Reason: Legacy protocol poses data confidentiality risks
|             Severity: HIGH
+-------------------------------------------------------------
SECURE_CONFIG_ACTIVE_INSECURE_CONFIG_DB_WALK: Processed entry 2: snmp-server community CANARY-c97 RO

=============================================================
                    DATABASE SUMMARY
=============================================================
Total Active Entries Processed: 2
"""
"""17.18.2+ only (#97). The walk line echoes the real community string: it must be dropped."""

SHOW_SYSTEM_INSECURE_CONFIGURATION_EMPTY = """\
=============================================================
          ACTIVE INSECURE CONFIGURATION DATABASE
=============================================================
Generated: Active Configuration Analysis
Total Active Insecure Commands: 0
Database Type: Active (Current State)
Scan Status: Complete
Next Update: No pending updates
Database State: Stable
=============================================================
"""

BGP_NOT_ACTIVE = "% BGP not active\n"
NOT_UNDERSTOOD = "% Something unexpected happened\n"

NEIGHBOUR_REPLIES = {
    "show cdp neighbors detail": SHOW_CDP_NEIGHBORS_DETAIL,
    "show lldp neighbors detail": SHOW_LLDP_NEIGHBORS_DETAIL,
}
"""`sw-a`'s CDP and LLDP tables, which the crawl reads before the Backup (#50)."""

REPLIES = {
    "show interfaces": SHOW_INTERFACES,
    "show interfaces switchport": SHOW_INTERFACES_SWITCHPORT,
    "show interfaces trunk": SHOW_INTERFACES_TRUNK,
    "show ip interface": SHOW_IP_INTERFACE,
    "show etherchannel summary": SHOW_ETHERCHANNEL_SUMMARY,
    "show vlan brief": SHOW_VLAN_BRIEF,
    "show vrf": SHOW_VRF,
    "show ip arp": SHOW_IP_ARP,
    "show ip arp vrf BLUE": SHOW_IP_ARP_VRF_BLUE,
    "show ip arp vrf Mgmt-intf": SHOW_IP_ARP_VRF_MGMT,
    "show mac address-table": SHOW_MAC_ADDRESS_TABLE,
    "show ip ospf neighbor": SHOW_IP_OSPF_NEIGHBOR,
    "show ip eigrp neighbors": SHOW_IP_EIGRP_NEIGHBORS,
    "show ip eigrp vrf BLUE neighbors": SHOW_IP_EIGRP_VRF_BLUE_NEIGHBORS,
    "show ip eigrp vrf Mgmt-intf neighbors": "",
    "show ip bgp summary": SHOW_IP_BGP_SUMMARY,
    "show ip bgp vpnv4 vrf BLUE summary": SHOW_IP_BGP_VPNV4_VRF_BLUE_SUMMARY,
    "show ip bgp vpnv4 vrf Mgmt-intf summary": "",
    "show ip route static": SHOW_IP_ROUTE_STATIC,
    "show ip route vrf BLUE static": SHOW_IP_ROUTE_VRF_BLUE_STATIC,
    "show ip route vrf Mgmt-intf static": "",
    "show standby brief": SHOW_STANDBY_BRIEF,
    "show vrrp brief": SHOW_VRRP_BRIEF,
    "show glbp brief": SHOW_GLBP_BRIEF,
    "show inventory": SHOW_INVENTORY,
    "show snmp user": SHOW_SNMP_USER,
    "show ntp associations": SHOW_NTP_ASSOCIATIONS,
    "show policy-map control-plane": SHOW_POLICY_MAP_CONTROL_PLANE,
    "show ip ssh": SHOW_IP_SSH,
}
"""Every collection command's reply on `sw-a`, keyed by the exact command.

`show system insecure configuration` is not here: `sw-a` runs 17.9.4a, below its 17.18.2
gate (#97), so it is never sent. Its reply is a fixture of its own.
"""
