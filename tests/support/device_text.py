"""Hand-written, synthetic device text for tests (CLAUDE.md: no real device data).

Shaped like Cisco `show version` and privilege output so the parsers have something to read,
with made-up hostnames (`sw-a`, `nx-a`), serials (`TEST...`) and no real addresses.
"""

IOS_XE_SHOW_VERSION = """\
Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, \
RELEASE SOFTWARE (fc5)
Copyright (c) 1986-2023 by Cisco Systems, Inc.

ROM: IOS-XE ROMMON
sw-a uptime is 1 week, 2 days, 3 hours, 4 minutes
System returned to ROM by Reload Command
System image file is "flash:packages.conf"

cisco C9300-48P (X86) processor with 1392536K/6147K bytes of memory.
Processor board ID TEST0000A01
Configuration register is 0x102

Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 56    C9300-48P          17.09.04a         CAT9K_IOSXE           INSTALL
     2 56    C9300-48P          17.09.04a         CAT9K_IOSXE           INSTALL


Switch 02
---------
Switch uptime                      : 1 week, 2 days, 3 hours, 1 minute
Model Number                       : C9300-48P
System Serial Number               : TEST0000A02
"""

IOL_SHOW_VERSION = """\
Cisco IOS Software [Dublin], Linux Software (X86_64BI_LINUX_L2-ADVENTERPRISEK9-M), \
Version 17.12.1, RELEASE SOFTWARE (fc5)
sw-b uptime is 10 minutes
cisco IOU-L2 (i86bi_LinuxL2) processor (revision 2.0) with 2048K/1024K bytes of memory.
Processor board ID TEST0000B01
"""

NXOS_SHOW_VERSION = """\
Cisco Nexus Operating System (NX-OS) Software
Software
  BIOS: version
  NXOS: version 9.3(8)
  NXOS image file is: bootflash:///nxos.9.3.8.bin

Hardware
  cisco Nexus9000 C9300v Chassis
  Intel(R) Xeon(R) CPU  with 16409064 kB of memory.
  Processor Board ID TEST0000N01

  Device name: nx-a
  bootflash:    4287040 kB
Kernel uptime is 0 day(s), 1 hour(s), 2 minute(s), 3 second(s)
"""

ASA_SHOW_VERSION = """\
Cisco Adaptive Security Appliance Software Version 9.16(4)
fw-a up 3 days 2 hours
"""

IOS_XR_SHOW_VERSION = """\
Cisco IOS XR Software, Version 7.5.2
Copyright (c) 2013-2022 by Cisco Systems, Inc.
"""

UNKNOWN_SHOW_VERSION = "Some Other Operating System, Version 1\n"

IOS_XE_PRIVILEGE_15 = "Current privilege level is 15\n"
IOS_XE_PRIVILEGE_1 = "Current privilege level is 1\n"

NXOS_USER_ACCOUNT = """\
user:netops-ro
        this user account has no expiry date
        roles:NA-READ
"""

# -- CDP and LLDP neighbour detail (ticket #50) ---------------------------------------------

IOS_XE_CDP_DETAIL = """\
-------------------------
Device ID: sw-b.example.test
Entry address(es):
  IP address: 198.51.100.2
  IPv6 address: 2001:DB8::2  (global unicast)
Platform: cisco C9300-48P,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/24
Holdtime : 150 sec

Version :
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a
Copyright (c) 1986-2023 by Cisco Systems, Inc.

advertisement version: 2
Native VLAN: 1
Duplex: full
Management address(es):
  IP address: 192.0.2.2

-------------------------
Device ID: SEP00AABBCCDDEE
Entry address(es):
  IP address: 192.0.2.50
Platform: Cisco IP Phone 8865,  Capabilities: Host Phone Two-port Mac Relay
Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): Port 1
Holdtime : 160 sec

Version :
sip8845_65.14-1-1MN-36

advertisement version: 2
Duplex: full
Management address(es):


Total cdp entries displayed : 2
"""

IOS_XE_LLDP_DETAIL = """\
------------------------------------------------
Local Intf: Gi1/0/2
Chassis id: 5254.0012.3401
Port id: Eth1/1
Port Description: Ethernet1/1
System Name: nx-a

System Description:
Cisco Nexus Operating System (NX-OS) Software 9.3(8)
Copyright (c) 2002-2021, Cisco Systems, Inc. All rights reserved.

Time remaining: 99 seconds
System Capabilities: B,R
Enabled Capabilities: B,R
Management Addresses:
    IP: 192.0.2.12
    IPV6: 2001:DB8::12
Auto Negotiation - not supported
Physical media capabilities - not advertised
Media Attachment Unit type - not advertised
Vlan ID: - not advertised

------------------------------------------------
Local Intf: Gi1/0/3
Chassis id: 5254.0012.3402
Port id: ens3
Port Description - not advertised
System Name - not advertised
System Description - not advertised

Time remaining: 110 seconds
System Capabilities - not advertised
Enabled Capabilities - not advertised
Management Addresses - not advertised
Auto Negotiation - not supported
Physical media capabilities - not advertised
Media Attachment Unit type - not advertised
Vlan ID: - not advertised


Total entries displayed: 2
"""

NXOS_CDP_DETAIL_JSON = """\
{
  "TABLE_cdp_neighbor_detail_info": {
    "ROW_cdp_neighbor_detail_info": [
      {
        "ifindex": "83886080",
        "device_id": "sw-a(TEST0000A01)",
        "sysname": "sw-a",
        "numaddr": "1",
        "v4addr": "198.51.100.1",
        "platform_id": "cisco C9300-48P",
        "capability": ["router", "switch", "IGMP_cnd_filtering"],
        "intf_id": "Ethernet1/1",
        "port_id": "GigabitEthernet1/0/2",
        "ttl": "150",
        "version": "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software, Version 17.9.4a",
        "nativevlan": "1",
        "duplexmode": "full",
        "nummgmtaddr": "1",
        "v4mgmtaddr": "192.0.2.1"
      },
      {
        "ifindex": "83886081",
        "device_id": "nx-b(TEST0000N02)",
        "sysname": "nx-b",
        "numaddr": "1",
        "v6addr": "2001:db8::22",
        "platform_id": "N9K-C9300v",
        "capability": ["router", "switch"],
        "intf_id": "Ethernet1/2",
        "port_id": "Ethernet1/2",
        "ttl": "170",
        "version": "Cisco Nexus Operating System (NX-OS) Software, Version 9.3(8)"
      }
    ]
  }
}
"""

NXOS_LLDP_DETAIL_JSON = """\
{
  "neigh_hdr": "neigh_hdr",
  "TABLE_nbor_detail": {
    "ROW_nbor_detail": {
      "chassis_type": "Mac Address",
      "chassis_id": "5254.0012.3403",
      "port_type": "Interface Name",
      "port_id": "Gi1/0/2",
      "l_port_id": "Eth1/1",
      "port_desc": "GigabitEthernet1/0/2",
      "sys_name": "sw-a",
      "sys_desc": "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software, Version 17.9.4a",
      "ttl": "110",
      "system_capability": "B, R",
      "enabled_capability": "B, R",
      "mgmt_addr_type": "IPV4",
      "mgmt_addr": "192.0.2.1",
      "mgmt_addr_ipv6_type": "IPV6",
      "mgmt_addr_ipv6": "not advertised",
      "vlan_id": "1"
    }
  }
}
"""
# Running configs (#51). `CANARY-cfg-...` marks text that may reach only a Backup: never a
# record, an Audit log event, the console or a plaintext file.
CONFIG_CANARIES = ("CANARY-cfg-5b2e-enable", "CANARY-cfg-8d4f-nxos")

IOS_XE_RUNNING_CONFIG = """\
Building configuration...

Current configuration : 330 bytes
!
! Last configuration change at 10:15:30 UTC Wed Nov 18 2026
!
version 17.9
service timestamps debug datetime msec
!
hostname sw-a
!
enable secret 9 CANARY-cfg-5b2e-enable
!
interface GigabitEthernet1/0/1
 description to sw-b
 ip address 192.0.2.1 255.255.255.0
!
banner motd ^C
Authorised access only.
^C
!
end
"""

NXOS_RUNNING_CONFIG = """\

!Command: show running-config
!Running configuration last done at: Wed Nov 18 10:15:30 2026
!Time: Wed Nov 18 10:16:00 2026

version 9.3(8) Bios:version
hostname nx-a
username admin password 5 CANARY-cfg-8d4f-nxos  role network-admin
feature lldp

interface Ethernet1/1
  description to sw-a
"""

# Running configs with the hardening facts (#96). Every secret, hash and community string
# carries a canary, so a test can prove none of it reaches a record or a Finding.
HARDENING_CANARIES = (
    "CANARY-cfg-96-a1b2-enable9",
    "CANARY-cfg-96-a1b2-enable7",
    "CANARY-cfg-96-a1b2-user5",
    "CANARY-cfg-96-a1b2-user7",
    "CANARY-cfg-96-a1b2-community",
    "CANARY-cfg-96-a1b2-auth",
    "CANARY-cfg-96-nxos-user5",
    "CANARY-cfg-96-nxos-community",
    "CANARY-cfg-96-nxos-auth",
)

# Running configs with the NTP, syslog, routing, FHRP and ICMP facts (#101). Every key,
# key-string and password carries a canary, so a test can prove none of it reaches a fact,
# a record or a Finding.
SERVICE_CANARIES = (
    "CANARY-cfg-101-a1b2-ntp-md5",
    "CANARY-cfg-101-a1b2-ntp-sha",
    "CANARY-cfg-101-a1b2-fhrp",
    "CANARY-cfg-101-a1b2-bgp",
)

IOS_XE_SERVICES_CONFIG = """\
Building configuration...

Current configuration : 2048 bytes
!
version 17.9
hostname sw-a
!
ntp authentication-key 1 md5 CANARY-cfg-101-a1b2-ntp-md5
ntp authenticate
ntp trusted-key 1
ntp server 192.0.2.10 key 1
!
logging host 192.0.2.20
logging buffered 64000
logging trap warnings
!
router ospf 1
 network 192.0.2.0 0.0.0.255 area 0
 neighbor 192.0.2.2
!
router bgp 65000
 neighbor 192.0.2.3 password 7 CANARY-cfg-101-a1b2-bgp
!
interface Vlan10
 description to sw-b
 ip address 192.0.2.1 255.255.255.0
 standby 1 ip 192.0.2.254
 standby 1 authentication md5 key-string CANARY-cfg-101-a1b2-fhrp
!
interface Vlan20
 ip address 198.51.100.1 255.255.255.0
 no ip redirects
 no ip unreachables
 no ip proxy-arp
!
interface GigabitEthernet1/0/1
 description access port
 switchport
!
end
"""

NXOS_SERVICES_CONFIG = """\
!Command: show running-config
!Running configuration last done at: Wed Nov 18 10:15:30 2026

version 9.3(8) Bios:version
hostname nx-a
feature ospf
feature hsrp
no password strength-check
logging server 192.0.2.20
ntp authentication-key 1 sha256 CANARY-cfg-101-a1b2-ntp-sha
ntp authenticate
ntp trusted-key 1
ntp server 192.0.2.10 key 1
router ospf 1
  router-id 192.0.2.1

interface Vlan10
  no shutdown
  ip address 192.0.2.1/24
  ip proxy-arp
  hsrp 1
    ip 192.0.2.254
    authentication md5 key-string CANARY-cfg-101-a1b2-fhrp

interface Ethernet1/1
  ip address 198.51.100.1/24
"""

IOS_XE_HARDENING_CONFIG = """\
Building configuration...

Current configuration : 2048 bytes
!
version 17.9
hostname sw-a
!
enable secret 9 CANARY-cfg-96-a1b2-enable9
enable password 7 CANARY-cfg-96-a1b2-enable7
!
username netops-ro privilege 15 secret 5 CANARY-cfg-96-a1b2-user5
username legacy password 7 CANARY-cfg-96-a1b2-user7
!
ip source-route
ip http server
service pad
service finger
ip bootp server
ip rcmd rcp-enable
ftp-server enable
tftp-server nvram:startup-config
!
snmp-server community public RO
snmp-server community CANARY-cfg-96-a1b2-community RW
snmp-server community private RW 99
snmp-server group N3AUTH v3 auth read v1default
snmp-server user n3user N3AUTH v3 auth sha CANARY-cfg-96-a1b2-auth
!
line con 0
 logging synchronous
line vty 0 4
 transport input telnet ssh
line vty 5 15
 transport input ssh
!
end
"""

NXOS_HARDENING_CONFIG = """\
!Command: show running-config
!Running configuration last done at: Wed Nov 18 10:15:30 2026

version 9.3(8) Bios:version
hostname nx-a
feature telnet
feature ftp
username admin password 5 CANARY-cfg-96-nxos-user5  role network-admin
ip http server
no ip source-route
snmp-server community public RW
snmp-server community CANARY-cfg-96-nxos-community RO 10
snmp-server group N3AUTH v3 auth
snmp-server user n3user N3AUTH auth md5 CANARY-cfg-96-nxos-auth
line vty
  access-class 10 in
"""

COMMAND_AUTHORISATION_FAILED = "Command authorization failed.\n"
IOS_XE_INVALID_INPUT = "                 ^\n% Invalid input detected at '^' marker.\n"
NXOS_PERMISSION_DENIED = "% Permission denied for the role\n"
