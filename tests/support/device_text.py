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

COMMAND_AUTHORISATION_FAILED = "Command authorization failed.\n"
IOS_XE_INVALID_INPUT = "                 ^\n% Invalid input detected at '^' marker.\n"
NXOS_PERMISSION_DENIED = "% Permission denied for the role\n"
