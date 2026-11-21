"""Hand-written running configs for the SSH, VTY, AAA and timeout facts (#100).

Synthetic only: `sw-a`/`nx-a`, no real device data. Every secret, hash and key carries a
canary, so a test can prove none of it reaches a fact, a Finding or `topology.json`.
"""

ACCESS_CANARIES = (
    "CANARY-100-access-enable9",
    "CANARY-100-access-user5",
    "CANARY-100-access-user7",
    "CANARY-100-access-tacacs",
    "CANARY-100-access-configkey",
    "CANARY-100-access-nxos",
)

IOS_XE_ACCESS_CONFIG = """\
Building configuration...

Current configuration : 2048 bytes
!
version 17.9
hostname sw-a
!
enable secret 9 CANARY-100-access-enable9
username netops-ro privilege 15 secret 5 CANARY-100-access-user5
username legacy password 7 CANARY-100-access-user7
!
aaa new-model
aaa authentication login default group tacacs+ none
aaa authentication login CONSOLE local
aaa authorization commands 15 default group tacacs+
aaa accounting commands 15 default start-stop group tacacs+
!
tacacs-server key 7 CANARY-100-access-tacacs
!
ip ssh version 1
password encryption aes
key config-key password-encryption CANARY-100-access-configkey
!
line con 0
 exec-timeout 0 0
line vty 0 4
 access-class 10 in
line vty 5 15
 exec-timeout 15 0
!
end
"""

NXOS_ACCESS_CONFIG = """\
!Command: show running-config
!Running configuration last done at: Wed Nov 18 10:15:30 2026

version 9.3(8) Bios:version
hostname nx-a
feature tacacs+
username admin password 5 CANARY-100-access-nxos  role network-admin
aaa authentication login default group tacacs+ none
aaa authorization commands default group tacacs+
aaa accounting default group tacacs+
line console
 exec-timeout 0
line vty
 access-class 10 in
"""
