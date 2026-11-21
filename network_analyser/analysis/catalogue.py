"""Every shipped Check's stable identity, in one place (#93, #102).

A Check id is stable in every Run and is what `topology.json`, the diagram, the Run report and
the Device Role map all point at. A Finding built by more than one module (the Device Role
Finding names the Checks it stopped) reads the names here, so an id is never printed where
the operator should see a name.

`PENDING_CHECK_NAMES` holds the Checks a later ticket ships that a Device Role can still
stop, so the out-of-date Finding names them correctly before they exist (#106: Hardware EoX).
"""

from typing import Final

from network_analyser.records.topology import Check, CheckType

__all__ = [
    "CISCO_LIST_CHECK",
    "GUEST_SHELL_CHECK",
    "MODEL_DRIFT_CHECK",
    "NTP_CHECK",
    "PENDING_CHECK_NAMES",
    "ROLE_CHECK",
    "SNMP_CHECK",
    "SSH_CHECK",
    "check_name",
]

MODEL_DRIFT_CHECK: Final = Check(
    "consistency-model-drift", "Same model on different releases", CheckType.CONSISTENCY
)
SNMP_CHECK: Final = Check(
    "config-snmpv3-user-crypto", "SNMPv3 users on MD5/DES/3DES", CheckType.CONFIGURATION
)
NTP_CHECK: Final = Check("config-ntp-synchronised", "NTP not synchronised", CheckType.CONFIGURATION)
COPP_CHECK: Final = Check("config-copp-applied", "CoPP not applied", CheckType.CONFIGURATION)
SSH_CHECK: Final = Check("config-ssh-key-size", "SSH key under 2048 bits", CheckType.CONFIGURATION)
GUEST_SHELL_CHECK: Final = Check(
    "config-guest-shell", "Guest Shell present", CheckType.CONFIGURATION
)
CISCO_LIST_CHECK: Final = Check(
    "config-cisco-insecure-list", "Cisco insecure-list items", CheckType.CONFIGURATION
)
ROLE_CHECK: Final = Check(
    "config-device-role-out-of-date", "Device Role out of date", CheckType.CONFIGURATION
)

PENDING_CHECK_NAMES: Final[dict[str, str]] = {
    "lifecycle-hardware-eox": "Hardware EoX",
    "config-telnet": "Telnet",
    "config-secret-types": "Weak secret types",
    "config-enable-secret": "Enable password or no enable secret",
    "config-snmp-communities": "SNMPv1/v2c",
    "config-snmpv3-priv": "SNMPv3 without priv",
    "config-insecure-mode": "Insecure mode",
    "config-http-server": "Plain HTTP server",
    "config-legacy-services": "Legacy services",
    "config-ssh-version": "SSHv2 not enforced",
    "config-vty-access-class": "No VTY access-class",
    "config-aaa-fallback": "AAA fallback to none",
    "config-aaa": "No central AAA, authorisation or accounting",
    "config-ntp": "NTP missing, unauthenticated or MD5",
    "config-syslog": "No remote syslog",
    "config-exec-timeout": "No exec-timeout",
    "config-password-type-6": "Type 6 not enabled",
    "config-strength-check": "NX-OS strength-check off",
    "config-brute-force": "No brute-force protection",
    "config-routing-authentication": "Routing authentication missing",
    "config-fhrp-authentication": "FHRP authentication missing",
    "config-icmp": "ICMP redirects, unreachables or proxy ARP",
}
"""Checks a later ticket ships, with the ids the Cisco list and Device Role map already use.

They are the agreed cross-ticket ids (#96, #100, #101, #106): the Cisco insecure-list mapping
points at them now, so an entry starts matching the moment its Check raises a Finding. A Check
that uses another id simply leaves its Cisco entries reported in Cisco's own words, which is
never worse than dropping them."""

_SHOWN_NAMES: Final[dict[str, str]] = {
    check.id: check.name
    for check in (
        MODEL_DRIFT_CHECK,
        SNMP_CHECK,
        NTP_CHECK,
        COPP_CHECK,
        SSH_CHECK,
        GUEST_SHELL_CHECK,
        CISCO_LIST_CHECK,
        ROLE_CHECK,
    )
}


def check_name(check_id: str) -> str:
    """Return the operator-facing name for `check_id`, else the id itself."""
    return _SHOWN_NAMES.get(check_id) or PENDING_CHECK_NAMES.get(check_id, check_id)
