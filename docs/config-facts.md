# Config facts (secret-free hardening inputs)

Written 2026-11-21 for [#96](https://github.com/b-git-hub/network-analyser/issues/96) (spec [#92](https://github.com/b-git-hub/network-analyser/issues/92), stories 59-66).

`platforms.read_config_facts(platform, text)` reads a device's running config **inside the visit**, after the Backup has been accepted, and returns plain `records.config_facts.ConfigFact(name, value)` values. The raw config still goes only from `device_gateway` to the Backup sink; no config line, secret, hash, key or community string is kept in a fact, a device record, a Finding or a document.

The facts ride `DeviceRecord.config_facts`; the cli puts them in `AnalysisInput.config_facts` at the Run's end. They are **not** written to `topology.json`: they are an input to Analysis, and the Findings are its output.

## Rules

- A fact that was not read is `Unknown(reason)`, never absent and never an empty value. `ConfigFacts.fact(name)` answers `Unknown` for a name it does not hold, so a Check can never read "not looked at" as "off" (story 126).
- Counts are `int`; presence flags are `bool`; lists are tuples of fixed keywords or vty block headers, never device text.
- A fact name is part of the published vocabulary: later Checks use exactly these names.
- `Platform.IOS_XE` covers both classic IOS and IOS-XE. A Check that differs between them works it out from `VisitedDevice.software_version`: a classic IOS release contains parentheses (`15.2(7)E7`), an IOS-XE release does not (`17.9.4a`, `16.12.4`).

## Vocabulary

| Fact | Value | Platforms | Meaning |
|---|---|---|---|
| `telnet_lines` | `tuple[str, ...]` or `Unknown` | both | The `line vty` block headers where Telnet is permitted, exactly as the config heads them. A block with no `transport input` permits Telnet (the default is `all`). NX-OS also needs `feature telnet`; without it the tuple is empty. `Unknown` when no `line vty` block is shown. |
| `secret_type_0` | `int` | both | Numbered `password`/`secret` lines using type 0 (cleartext). |
| `secret_type_4` | `int` | both | Numbered `password`/`secret` lines using type 4. |
| `secret_type_5` | `int` | both | Numbered lines using type 5. MD5-crypt on IOS and IOS-XE (flagged as weak on both, operator decision on #142), SHA-256 on NX-OS (not flagged). |
| `secret_type_6` | `int` | both | Numbered lines using type 6 (AES). |
| `secret_type_7` | `int` | both | Numbered lines using type 7 (reversible). |
| `secret_type_8` | `int` | both | Numbered lines using type 8. |
| `secret_type_9` | `int` | both | Numbered lines using type 9. |
| `enable_secret` | `bool` | IOS/IOS-XE | The config has an `enable secret` line. |
| `enable_password` | `bool` | IOS/IOS-XE | The config has an `enable password` line. |
| `insecure_mode` | `bool` | IOS/IOS-XE | `system mode insecure` is configured (IOS-XE 26.1.1+). |
| `http_server` | `bool` | both | The plain HTTP server is enabled (`ip http server` or `feature http-server`). |
| `ip_source_route` | `bool` | IOS/IOS-XE | IP source routing is on. The IOS default is on, so only `no ip source-route` makes it `False`. Not read on NX-OS, where no default is proven: the fact is absent there and the Check raises nothing for it. |
| `legacy_services` | `tuple[str, ...]` | both | The legacy services explicitly enabled, by fixed keyword: `PAD`, `finger`, `TCP small servers`, `UDP small servers`, `BOOTP`, `ODR`, `rcmd`, `FTP`, `TFTP`. |
| `ssh_version` | `int` | IOS/IOS-XE | The value of `ip ssh version`: 0 when the line is absent, else 1 or 2. |
| `vty_access_class_missing_lines` | `tuple[str, ...]` or `Unknown` | both | The `line vty` block headers with no inbound `access-class`. `Unknown` when no `line vty` block is shown. |
| `aaa_login_fallback_none` | `int` | both | How many `aaa authentication login` method lists include `none`. |
| `aaa_new_model` | `bool` | IOS/IOS-XE | `aaa new-model` is configured. NX-OS has no such command. |
| `aaa_central_login` | `bool` | both | An `aaa authentication login` method list names a server group (`group`). |
| `aaa_authorization` | `bool` | both | Any `aaa authorization` command is configured. |
| `aaa_accounting` | `bool` | both | Any `aaa accounting` command is configured. |
| `exec_timeout_disabled_lines` | `tuple[str, ...]` | both | The console and vty block headers whose `exec-timeout` is 0 (disabled). An absent line is the vendor default, not a hit. |
| `type_6_enabled` | `bool` or `Unknown` | IOS/IOS-XE; `Unknown` on NX-OS | `password encryption aes` is configured. The NX-OS command is unconfirmed, so NX-OS is `Unknown`, never "absent". |
| `snmp_v1_v2c_communities` | `int` | both | SNMPv1/v2c communities configured. |
| `snmp_v1_v2c_read_write_communities` | `int` | both | How many are read-write. |
| `snmp_v1_v2c_read_write_default_name` | `int` | both | How many read-write communities use a default name (`public` or `private`). |
| `snmp_v1_v2c_read_write_no_acl` | `int` | both | How many read-write communities have no access list. |
| `snmp_v3_configured` | `bool` | both | SNMPv3 users or groups are configured. |
| `snmp_v3_users` | `int` | both | SNMPv3 users visible in the running config. IOS-XE may keep users out of it. |
| `snmp_v3_users_without_priv` | `int` | both | How many of them have no privacy protocol. |
| `snmp_v3_groups_without_priv` | `int` | both | SNMPv3 groups configured below the `priv` security level. |
| `snmp_v3_user_crypto` | `tuple[str, ...]` or `Unknown` | NX-OS | One `<auth>/<privacy>` keyword pair per `snmp-server user` line, in config order, with no user name or key. `auth` is `MD5`, `SHA`, `SHA-256` or `none`. `privacy` is `AES128` when the line has `priv aes-128`, `DES` when it has `priv` without `aes-128`, and `none` when it has no `priv`. An empty tuple means no user is configured. `Unknown` when a user line cannot be read. IOS/IOS-XE read their users from `show snmp user` instead. |
| `snmp_global_enforce_priv` | `bool` | NX-OS | `snmp-server globalEnforcePriv` is set. |
| `ntp_configured` | `bool` | both | An NTP server, peer or master is configured. |
| `ntp_authenticated` | `bool` | both | A configured server or peer uses an authentication key that is also trusted. |
| `ntp_md5_authentication` | `bool` | both | The key NTP uses is MD5. |
| `remote_syslog_servers` | `int` | both | Remote syslog servers configured; local logging commands never count. |
| `password_strength_check` | `bool` | NX-OS | `no password strength-check` turns it off; its absence means on, the default. |
| `login_block_for` | `bool` | IOS/IOS-XE | `login block-for` brute-force protection is configured. |
| `routing_authentication_missing` | `tuple[str, ...]` | both | The routing protocols configured with no authentication, by keyword (`OSPF`, `EIGRP`, `BGP`). |
| `fhrp_groups` | `int` | both | HSRP, VRRP or GLBP groups configured with an address. |
| `fhrp_groups_without_authentication` | `int` | both | How many of those have no authentication. |
| `icmp_redirects_l3_interfaces` | `int` | both | L3 interfaces with ICMP redirects enabled. |
| `icmp_unreachables_l3_interfaces` | `int` | both | L3 interfaces with ICMP unreachables enabled. |
| `proxy_arp_l3_interfaces` | `int` | both | L3 interfaces with proxy ARP enabled, by each Platform's own default (IOS on, NX-OS off). |

## The Checks that read them (#96)

| Check id | Level | Facts |
|---|---|---|
| `hardening-telnet` | High | `telnet_lines` |
| `hardening-weak-secret-types` | High | `secret_type_0`, `_4`, `_5` (IOS and IOS-XE, not NX-OS), `_7` |
| `hardening-enable-secret` | High | `enable_secret`, `enable_password` (IOS/IOS-XE only) |
| `hardening-snmp-v1-v2c` | High; Critical when a read-write community has a default name or no ACL | the four `snmp_v1_v2c_*` facts |
| `hardening-snmp-v3-priv` | High | `snmp_v3_configured`, `snmp_v3_users`, `snmp_v3_users_without_priv`, `snmp_v3_groups_without_priv`, `snmp_global_enforce_priv` (NX-OS) |
| `hardening-insecure-mode` | High | `insecure_mode` (IOS-XE only) |
| `hardening-http-server` | High | `http_server` |
| `hardening-legacy-services` | High | `ip_source_route` (IOS/IOS-XE only), `legacy_services` |

## The Checks that read the service facts (#101)

| Check id | Level | Facts | Gate |
|---|---|---|---|
| `hardening-ntp` | Medium | `ntp_configured`, `ntp_authenticated`, `ntp_md5_authentication` | Always runs; authentication is read only when NTP is configured. |
| `hardening-remote-syslog` | Medium | `remote_syslog_servers` | Always runs. |
| `hardening-strength-check` | Medium | `password_strength_check` | NX-OS only. |
| `hardening-brute-force` | Medium | `login_block_for` | IOS/IOS-XE, classic IOS included. |
| `hardening-routing-authentication` | Medium | `routing_authentication_missing` | Only where the device has a live OSPF, EIGRP or BGP neighbour; each protocol is judged on its own. |
| `hardening-fhrp-authentication` | Medium | `fhrp_groups`, `fhrp_groups_without_authentication` | Only configured groups. |
| `hardening-icmp` | Low | `icmp_redirects_l3_interfaces`, `icmp_unreachables_l3_interfaces`, `proxy_arp_l3_interfaces` | Only where an L3 interface is up. |

A fact that was not read makes the Check raise a Low "could not decide" Finding, never a silent pass (story 6). Later batches ([#100](https://github.com/b-git-hub/network-analyser/issues/100), [#102](https://github.com/b-git-hub/network-analyser/issues/102)) add their own facts alongside these and use the same names for any they share.

## The Checks that read them (#100)

Written 2026-11-21 for [#100](https://github.com/b-git-hub/network-analyser/issues/100) (stories 59, 61, 64-66, 69).

| Check id | Level | Facts |
|---|---|---|
| `hardening-ssh-v2` | High | `ssh_version`; `VisitedDevice.software_version` for the 17.10 boundary |
| `hardening-vty-access-class` | High | `vty_access_class_missing_lines` |
| `hardening-aaa-fallback` | High | `aaa_login_fallback_none` |
| `hardening-aaa-central` | Medium | `aaa_new_model` (IOS/IOS-XE), `aaa_central_login`, `aaa_authorization`, `aaa_accounting` |
| `hardening-exec-timeout` | Medium | `exec_timeout_disabled_lines` |
| `hardening-type-6` | Medium | `type_6_enabled` |

- **SSHv2** is absence-is-the-problem on IOS/IOS-XE: an absent `ip ssh version 2` (fact `0`) is High on classic IOS and IOS-XE before 17.10, whose default is SSH 1.99. On 17.10 and later Cisco refuses SSHv1 by default, so an absent line is a Low "could not decide" until `show ip ssh` is read (#102); the running config cannot show the version in force. NX-OS supports SSHv2 only, so the Check does not apply there.
- **Exec timeout** is absence-is-the-problem for the protection, not for the line: an absent `exec-timeout` is the vendor default (10 minutes on IOS/IOS-XE) and raises nothing. An explicit `exec-timeout 0` is Medium. Console and vty blocks are checked; an AUX block's `exec-timeout 0 1` is a hardening recommendation, not a hit.
- **Central AAA** names the missing items and their count. NX-OS has no `aaa new-model`, so it is judged on its three items, not four.
- **Type 6** reads `password encryption aes` on IOS/IOS-XE. The NX-OS command is unconfirmed, so its fact is `Unknown` and the Check raises a Low "could not decide" there rather than reading silence as "not enabled".
- Every Finding names keywords, line-block headers, type numbers and counts only; no secret, hash, key, method-list name, server group or quoted config line reaches it.
