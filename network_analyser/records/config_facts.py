"""The secret-free config facts `platforms` reads and Analysis decides Checks from (#96).

A fact is a `ConfigFact(name, value)`: a fixed name and a plain value, never a config line,
secret, hash, key or community string. `platforms` reads them from the running config at
capture time, inside the visit, and puts them on the device record; `analysis` reads them
through `AnalysisInput.config_facts`. Their names are the published vocabulary in
docs/config-facts.md, so later Checks use exactly the same ones.

A fact that was not read is `Unknown`, never absent and never an empty value: `ConfigFacts.fact`
answers `Unknown` for a name that is not held, so a Check can never read "not looked at" as
"off" (story 126).
"""

from dataclasses import dataclass
from typing import Final

from network_analyser.records.unknown import Unknown

__all__ = [
    "ENABLE_PASSWORD",
    "ENABLE_SECRET",
    "FHRP_GROUPS",
    "FHRP_GROUPS_WITHOUT_AUTHENTICATION",
    "HTTP_SERVER",
    "ICMP_REDIRECTS_L3_INTERFACES",
    "ICMP_UNREACHABLES_L3_INTERFACES",
    "INSECURE_MODE",
    "IP_SOURCE_ROUTE",
    "LEGACY_SERVICES",
    "LOGIN_BLOCK_FOR",
    "NTP_AUTHENTICATED",
    "NTP_CONFIGURED",
    "NTP_MD5_AUTHENTICATION",
    "PASSWORD_STRENGTH_CHECK",
    "PROXY_ARP_L3_INTERFACES",
    "REMOTE_SYSLOG_SERVERS",
    "ROUTING_AUTHENTICATION_MISSING",
    "SECRET_TYPE_0",
    "SECRET_TYPE_4",
    "SECRET_TYPE_5",
    "SECRET_TYPE_6",
    "SECRET_TYPE_7",
    "SECRET_TYPE_8",
    "SECRET_TYPE_9",
    "SNMP_GLOBAL_ENFORCE_PRIV",
    "SNMP_V1_V2C_COMMUNITIES",
    "SNMP_V1_V2C_READ_WRITE_COMMUNITIES",
    "SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME",
    "SNMP_V1_V2C_READ_WRITE_NO_ACL",
    "SNMP_V3_CONFIGURED",
    "SNMP_V3_GROUPS_WITHOUT_PRIV",
    "SNMP_V3_USERS",
    "SNMP_V3_USERS_WITHOUT_PRIV",
    "TELNET_LINES",
    "ConfigFact",
    "ConfigFacts",
    "FactValue",
]

# -- The published fact names (docs/config-facts.md) ------------------------------------------

TELNET_LINES: Final = "telnet_lines"
"""The `line vty` blocks, exactly as the config heads them, where Telnet is permitted."""
SECRET_TYPE_0: Final = "secret_type_0"
"""How many numbered `password`/`secret` lines use type 0 (cleartext)."""
SECRET_TYPE_4: Final = "secret_type_4"
"""How many numbered `password`/`secret` lines use type 4."""
SECRET_TYPE_5: Final = "secret_type_5"
"""How many numbered `password`/`secret` lines use type 5 (MD5 on IOS, SHA-256 on NX-OS)."""
SECRET_TYPE_6: Final = "secret_type_6"
"""How many numbered `password`/`secret` lines use type 6 (AES)."""
SECRET_TYPE_7: Final = "secret_type_7"
"""How many numbered `password`/`secret` lines use type 7 (reversible)."""
SECRET_TYPE_8: Final = "secret_type_8"
"""How many numbered `password`/`secret` lines use type 8."""
SECRET_TYPE_9: Final = "secret_type_9"
"""How many numbered `password`/`secret` lines use type 9."""
ENABLE_SECRET: Final = "enable_secret"
"""True when the running config has an `enable secret` line (IOS/IOS-XE only)."""
ENABLE_PASSWORD: Final = "enable_password"
"""True when the running config has an `enable password` line (IOS/IOS-XE only)."""
INSECURE_MODE: Final = "insecure_mode"
"""True when `system mode insecure` is configured (IOS-XE only)."""
HTTP_SERVER: Final = "http_server"
"""True when the plain HTTP server is enabled."""
IP_SOURCE_ROUTE: Final = "ip_source_route"
"""True when IP source routing is enabled: the default, unless `no ip source-route` is set."""
LEGACY_SERVICES: Final = "legacy_services"
"""The legacy services explicitly enabled, by keyword; empty when none is."""
SNMP_V1_V2C_COMMUNITIES: Final = "snmp_v1_v2c_communities"
"""How many SNMPv1/v2c communities are configured."""
SNMP_V1_V2C_READ_WRITE_COMMUNITIES: Final = "snmp_v1_v2c_read_write_communities"
"""How many of them are read-write."""
SNMP_V1_V2C_READ_WRITE_DEFAULT_NAME: Final = "snmp_v1_v2c_read_write_default_name"
"""How many read-write communities use a default name (`public` or `private`)."""
SNMP_V1_V2C_READ_WRITE_NO_ACL: Final = "snmp_v1_v2c_read_write_no_acl"
"""How many read-write communities have no access list."""
SNMP_V3_CONFIGURED: Final = "snmp_v3_configured"
"""True when SNMPv3 users or groups are configured."""
SNMP_V3_USERS: Final = "snmp_v3_users"
"""How many SNMPv3 users are visible in the running config."""
SNMP_V3_USERS_WITHOUT_PRIV: Final = "snmp_v3_users_without_priv"
"""How many of them have no privacy protocol."""
SNMP_V3_GROUPS_WITHOUT_PRIV: Final = "snmp_v3_groups_without_priv"
"""How many SNMPv3 groups are configured below the `priv` security level."""
SNMP_GLOBAL_ENFORCE_PRIV: Final = "snmp_global_enforce_priv"
"""True when `snmp-server globalEnforcePriv` is set (NX-OS only)."""
NTP_CONFIGURED: Final = "ntp_configured"
"""True when an NTP server, peer or master is configured."""
NTP_AUTHENTICATED: Final = "ntp_authenticated"
"""True when a configured NTP server or peer uses a trusted authentication key."""
NTP_MD5_AUTHENTICATION: Final = "ntp_md5_authentication"
"""True when the authentication key NTP uses is MD5."""
REMOTE_SYSLOG_SERVERS: Final = "remote_syslog_servers"
"""How many remote syslog servers are configured."""
PASSWORD_STRENGTH_CHECK: Final = "password_strength_check"
"""True when NX-OS password strength-check is on, its default; False with `no ...`."""
LOGIN_BLOCK_FOR: Final = "login_block_for"
"""True when `login block-for` brute-force protection is configured (IOS/IOS-XE only)."""
ROUTING_AUTHENTICATION_MISSING: Final = "routing_authentication_missing"
"""The routing protocols configured with no authentication, by fixed keyword."""
FHRP_GROUPS: Final = "fhrp_groups"
"""How many HSRP, VRRP or GLBP groups are configured with an address."""
FHRP_GROUPS_WITHOUT_AUTHENTICATION: Final = "fhrp_groups_without_authentication"
"""How many configured FHRP groups have no authentication."""
ICMP_REDIRECTS_L3_INTERFACES: Final = "icmp_redirects_l3_interfaces"
"""How many L3 interfaces have ICMP redirects enabled."""
ICMP_UNREACHABLES_L3_INTERFACES: Final = "icmp_unreachables_l3_interfaces"
"""How many L3 interfaces have ICMP unreachables enabled."""
PROXY_ARP_L3_INTERFACES: Final = "proxy_arp_l3_interfaces"
"""How many L3 interfaces have proxy ARP enabled, by each Platform's own default."""

type FactValue = bool | int | str | tuple[str, ...] | Unknown
"""One config fact's value. It may be `Unknown` when the fact could not be read."""


@dataclass(frozen=True, slots=True)
class ConfigFact:
    """One secret-free fact read from a device's running config (#96).

    Attributes:
        name: its fixed name, one of the published names above.
        value: its value; `Unknown` when it could not be read.
    """

    name: str
    value: FactValue


@dataclass(frozen=True, slots=True)
class ConfigFacts:
    """The secret-free config facts of one Visited Device (#96).

    Attributes:
        device: the device's id.
        facts: every fact that was read, in name order.
    """

    device: str
    facts: tuple[ConfigFact, ...] = ()

    def fact(self, name: str) -> FactValue:
        """Return `name`'s value, or `Unknown` when it was not read (never "absent")."""
        for item in self.facts:
            if item.name == name:
                return item.value
        return Unknown(f"config fact not collected: {name}")
