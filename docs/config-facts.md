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
| `telnet_lines` | `tuple[str, ...]` or `Unknown` | both | The `line vty` block headers where Telnet is permitted, exactly as the config heads them. A block with no `transport input` permits Telnet: the IOS and IOS-XE default is the `all` transport, which Cisco's IOS XE configuration guides state as "by default, the vty transport is Telnet", so the rule is the same on both releases and no release check is needed. NX-OS also needs `feature telnet`; without it the tuple is empty. `Unknown` when no `line vty` block is shown. |
| `secret_type_0` | `int` | both | Secrets in cleartext: numbered `password`/`secret` lines using type 0, and a `password` line under `line` with no type number (IOS prints it that way without `service password-encryption`). |
| `secret_type_4` | `int` | both | Lines using type 4. Every type count reads `password`/`secret` lines (an optional `level N` may come before the number, as in `enable secret level 15 5 ...`) and typed keys (`key`, `key-string`, `md5` or `authentication-key` followed by a type number and a value). A bare `key 7` is a key id, and an `ntp authentication-key` puts its key number there, so neither counts. |
| `secret_type_5` | `int` | both | Numbered lines using type 5. MD5-crypt on IOS and IOS-XE (flagged as weak on both, operator decision on #142), SHA-256 on NX-OS (not flagged). |
| `secret_type_6` | `int` | both | Numbered lines using type 6 (AES). |
| `secret_type_7` | `int` | both | Numbered lines using type 7 (reversible). |
| `secret_type_8` | `int` | both | Numbered lines using type 8. |
| `secret_type_9` | `int` | both | Numbered lines using type 9. |
| `enable_secret` | `bool` | IOS/IOS-XE | The config has an `enable secret` line. |
| `enable_password` | `bool` | IOS/IOS-XE | The config has an `enable password` line. |
| `insecure_mode` | `bool` | IOS/IOS-XE | `system mode insecure` is configured (IOS-XE 26.1.1+). |
| `http_server` | `bool` | both | The plain HTTP server is enabled: `ip http server`, `feature http-server`, or an `nxapi http port <n>` line together with `feature nxapi`. |
| `ip_source_route` | `bool` | IOS/IOS-XE | IP source routing is on. The IOS default is on, so only `no ip source-route` makes it `False`. Not read on NX-OS, where no default is proven: the fact is absent there and the Check raises nothing for it. |
| `legacy_services` | `tuple[str, ...]` | both | The legacy services that are on, by fixed keyword: `PAD`, `finger`, `TCP small servers`, `UDP small servers`, `BOOTP`, `ODR`, `rcmd`, `FTP`, `TFTP`. On IOS/IOS-XE, `PAD` and `BOOTP` are on by default, so only `no service pad` and `no ip bootp server` read as off; NX-OS lists only what its config shows, because neither default is proven there. |
| `ssh_version` | `int` | IOS/IOS-XE | The value of `ip ssh version`: 0 when the line is absent, else 1 or 2. |
| `vty_access_class_missing_lines` | `tuple[str, ...]` or `Unknown` | both | The `line vty` block headers with no inbound `access-class`. `Unknown` when no `line vty` block is shown. |
| `aaa_login_fallback_none` | `int` | both | How many `aaa authentication login` and `aaa authentication enable` method lists include `none`. |
| `aaa_new_model` | `bool` | IOS/IOS-XE | `aaa new-model` is configured. NX-OS has no such command. |
| `aaa_central_login` | `bool` | both | An `aaa authentication login` method list names a server group (`group`). |
| `aaa_authorization` | `bool` | both | An `aaa authorization` command names a server group (`group`). A list using only `local`, `if-authenticated` or `none` is not central authorization. |
| `aaa_accounting` | `bool` | both | Any `aaa accounting` command is configured. |
| `exec_timeout_disabled_lines` | `tuple[str, ...]` | both | The console and vty block headers whose `exec-timeout` is 0 minutes and 0 seconds (disabled). `exec-timeout 0 30` is a real timeout, and an absent line is the vendor default, not a hit. |
| `type_6_enabled` | `bool` or `Unknown` | IOS/IOS-XE; `Unknown` on NX-OS | `password encryption aes` is configured. The NX-OS command is unconfirmed, so NX-OS is `Unknown`, never "absent". |
| `snmp_v1_v2c_communities` | `int` | both | SNMPv1/v2c communities configured, each counted once. NX-OS prints a community's access list on a second line, so its lines are joined by community name. |
| `snmp_v1_v2c_read_write_communities` | `int` | both | How many are read-write: `RW` on IOS, `group network-admin` on NX-OS, which never prints `RW`. |
| `snmp_v1_v2c_read_write_default_name` | `int` | both | How many read-write communities use a default name (`public` or `private`). |
| `snmp_v1_v2c_read_write_no_acl` | `int` | both | How many read-write communities have no access list (an ACL after `RO`/`RW` on IOS; `use-acl`, `use-ipv4acl` or `use-ipv6acl` on NX-OS). |
| `snmp_v3_configured` | `bool` | both | SNMPv3 users or groups are configured. |
| `snmp_v3_users` | `int` | both | SNMPv3 users visible in the running config. IOS-XE may keep users out of it. A `snmp-server user ... v1` or `v2c` line maps a user to a community and is not counted. |
| `snmp_v3_users_without_priv` | `int` | both | How many of them have no privacy protocol. |
| `snmp_v3_groups_without_priv` | `int` | both | SNMPv3 groups configured below the `priv` security level. |
| `snmp_v3_user_crypto` | `tuple[str, ...]` or `Unknown` | NX-OS | One `<auth>/<privacy>` keyword pair per `snmp-server user` line, in config order, with no user name or key. `auth` is `MD5`, `SHA`, `SHA-256` or `none`. `privacy` is `AES128` when the line has `priv aes-128`, `DES` when it has `priv` without `aes-128`, and `none` when it has no `priv`. An empty tuple means no user is configured. `Unknown` when a user line cannot be read. IOS/IOS-XE read their users from `show snmp user` instead. |
| `snmp_global_enforce_priv` | `bool` | NX-OS | `snmp-server globalEnforcePriv` is set. |
| `ntp_configured` | `bool` | both | An NTP server, peer or master is configured. |
| `ntp_authenticated` | `bool` | both | `ntp authenticate` is set and a configured server or peer names an authentication key that is also trusted (`ntp trusted-key 1 - 3` trusts keys 1 to 3). A key line alone authenticates nothing. |
| `ntp_md5_authentication` | `bool` | both | The key NTP uses is MD5. |
| `remote_syslog_servers` | `int` | both | Remote syslog servers configured. Only a top-level `logging host <x>`, `logging server <x>` or `logging <IP address>` counts; `logging on`, `logging userinfo`, `logging buffered` and an indented `logging enable` under `archive` / `log config` are local. |
| `password_strength_check` | `bool` | NX-OS | `no password strength-check` turns it off; its absence means on, the default. |
| `login_block_for` | `bool` | IOS/IOS-XE | `login block-for` brute-force protection is configured. |
| `routing_authentication_missing` | `tuple[str, ...]` | both | The routing protocols configured with no authentication, by keyword (`OSPF`, `EIGRP`, `BGP`). OSPF and EIGRP are judged per interface: a protocol is missing when any live interface that runs it (not shut down, not a loopback, not passive) has no authentication; area, virtual-link, `af-interface` and key-chain forms count. When no interface can be placed, the protocol falls back to "any authentication line anywhere". BGP counts a `password` line under a `neighbor` or a peer template (NX-OS `password 3 ...`, IOS-XE `template peer-session`). |
| `fhrp_groups` | `int` | both | HSRP, VRRP or GLBP groups configured with an address, each counted once per (interface, protocol, group number). |
| `fhrp_groups_without_authentication` | `int` | both | How many of those have no authentication. |
| `icmp_redirects_l3_interfaces` | `int` | both | Live L3 interfaces with ICMP redirects enabled; a `shutdown` interface and a loopback are never counted. |
| `icmp_unreachables_l3_interfaces` | `int` | both | Live L3 interfaces with ICMP unreachables enabled (same rule). |
| `proxy_arp_l3_interfaces` | `int` | both | Live L3 interfaces with proxy ARP enabled, by each Platform's own default (IOS on, NX-OS off); same rule. |

## The Checks that read them (#96)

| Check id | Level | Facts |
|---|---|---|
| `hardening-telnet` | High | `telnet_lines` |
| `hardening-weak-secret-types` | High | `secret_type_0`, `_4`, `_5` (IOS and IOS-XE, not NX-OS; see below), `_7` |
| `hardening-enable-secret` | High | `enable_secret`, `enable_password` (IOS/IOS-XE only) |
| `hardening-snmp-v1-v2c` | High; Critical when a read-write community has a default name or no ACL | the four `snmp_v1_v2c_*` facts |
| `hardening-snmp-v3-priv` | High | `snmp_v3_configured`, `snmp_v3_users`, `snmp_v3_users_without_priv`, `snmp_v3_groups_without_priv`, `snmp_global_enforce_priv` (NX-OS); IOS/IOS-XE read their users from `show snmp user` instead |
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

- **SSHv2** is absence-is-the-problem on IOS/IOS-XE: with no `ip ssh version 2` line, `show ip ssh` says which version is in force, and 2.0 passes while 1.x (including 1.99) is High, on any release. Only when `show ip ssh` was not read does the release decide: High on classic IOS and IOS-XE before 17.10, whose default is SSH 1.99, and a Low "could not decide" on 17.10 and later, where Cisco refuses SSHv1 by default but the running config cannot show it. NX-OS supports SSHv2 only, so the Check does not apply there.
- **Exec timeout** is absence-is-the-problem for the protection, not for the line: an absent `exec-timeout` is the vendor default (10 minutes on IOS/IOS-XE) and raises nothing. An explicit `exec-timeout 0` is Medium. Console and vty blocks are checked; an AUX block's `exec-timeout 0 1` is a hardening recommendation, not a hit.
- **Central AAA** names the missing items and their count. NX-OS has no `aaa new-model`, so it is judged on its three items, not four.
- **Type 6** reads `password encryption aes` on IOS/IOS-XE. The NX-OS command is unconfirmed, so its fact is `Unknown` and the Check raises a Low "could not decide" there rather than reading silence as "not enabled".
- Every Finding names keywords, line-block headers, type numbers and counts only; no secret, hash, key, method-list name, server group or quoted config line reaches it.

## Accuracy rules from the #142 review

- **Type 5 on IOS-XE.** Type 5 (MD5-crypt) is flagged on IOS-XE as well as classic IOS (operator decision on #142, research #76). NX-OS type 5 is SHA-256 and is not flagged. This is a behaviour change: IOS-XE devices with type 5 secrets now get the Finding.
- **SNMPv3 crypto Check on IOS.** `% SNMP agent not enabled` from `show snmp user` means no SNMP, so it reads as no SNMPv3 users and raises no "could not decide" Finding.
- **NX-OS parsers.** `guest_shell` reads "Deactivated" as off, and the SSH key size is read from the RSA section of `show ssh key`, so an ECDSA-only key no longer reports "521 bits".
- **Resolved by the 2026-11-22 operator decision on #142.** The four lower-confidence items below were left for the lab on 2026-11-21. The operator decided each on 2026-11-22; the code, this page and the changelog agree, and lab checks K5, K7 and L1 now verify the rule rather than decide it.
  - **Legacy PAD and BOOTP.** Both are on by default on IOS/IOS-XE: Cisco's IOS WAN Command Reference gives `service pad` the default "All PAD commands and associated connections are enabled", and the IOS Configuration Fundamentals Command Reference says "By default, the BOOTP service is enabled. When disabled, the `no ip bootp server` command will appear in the configuration file." An absent line therefore reads as on, and only `no service pad` and `no ip bootp server` read as off. NX-OS still lists only what its config shows, because neither default is proven there.
  - **IOS-XE vty transport.** Cisco's IOS XE configuration guides (16.12 to 17.16 at the time of writing) state that the default vty transport is Telnet, as on classic IOS. A vty block with no `transport input` therefore stays "Telnet permitted" on both platforms, and reading it as "could not decide" would hide a real exposure. No code change was needed.
  - **CoPP on a blank reply.** A blank `show policy-map control-plane` reply with no `%` line means no policy is applied, and is a real Medium. A reply carrying a `%` line stays "could not decide", as does an unrecognised reply that carries data.
  - **A missing command.** `% Invalid input` keeps the Medium Finding, now worded to name both causes: "The Device Role may be out of date, or the image may not have the command". IOS never splits the two on the error text, because it cannot tell them apart; the Check's name and id are unchanged.
