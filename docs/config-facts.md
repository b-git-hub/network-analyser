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
| `secret_type_5` | `int` | both | Numbered lines using type 5. MD5 on IOS, SHA-256 on NX-OS. |
| `secret_type_6` | `int` | both | Numbered lines using type 6 (AES). |
| `secret_type_7` | `int` | both | Numbered lines using type 7 (reversible). |
| `secret_type_8` | `int` | both | Numbered lines using type 8. |
| `secret_type_9` | `int` | both | Numbered lines using type 9. |
| `enable_secret` | `bool` | IOS/IOS-XE | The config has an `enable secret` line. |
| `enable_password` | `bool` | IOS/IOS-XE | The config has an `enable password` line. |
| `insecure_mode` | `bool` | IOS/IOS-XE | `system mode insecure` is configured (IOS-XE 26.1.1+). |
| `http_server` | `bool` | both | The plain HTTP server is enabled (`ip http server` or `feature http-server`). |
| `ip_source_route` | `bool` | both | IP source routing is on. The vendor default is on, so only `no ip source-route` makes it `False`. |
| `legacy_services` | `tuple[str, ...]` | both | The legacy services explicitly enabled, by fixed keyword: `PAD`, `finger`, `TCP small servers`, `UDP small servers`, `BOOTP`, `ODR`, `rcmd`, `FTP`, `TFTP`. |
| `snmp_v1_v2c_communities` | `int` | both | SNMPv1/v2c communities configured. |
| `snmp_v1_v2c_read_write_communities` | `int` | both | How many are read-write. |
| `snmp_v1_v2c_read_write_default_name` | `int` | both | How many read-write communities use a default name (`public` or `private`). |
| `snmp_v1_v2c_read_write_no_acl` | `int` | both | How many read-write communities have no access list. |
| `snmp_v3_configured` | `bool` | both | SNMPv3 users or groups are configured. |
| `snmp_v3_users` | `int` | both | SNMPv3 users visible in the running config. IOS-XE may keep users out of it. |
| `snmp_v3_users_without_priv` | `int` | both | How many of them have no privacy protocol. |
| `snmp_v3_groups_without_priv` | `int` | both | SNMPv3 groups configured below the `priv` security level. |
| `snmp_global_enforce_priv` | `bool` | NX-OS | `snmp-server globalEnforcePriv` is set. |

## The Checks that read them (#96)

| Check id | Level | Facts |
|---|---|---|
| `hardening-telnet` | High | `telnet_lines` |
| `hardening-weak-secret-types` | High | `secret_type_0`, `_4`, `_5` (classic IOS only), `_7` |
| `hardening-enable-secret` | High | `enable_secret`, `enable_password` (IOS/IOS-XE only) |
| `hardening-snmp-v1-v2c` | High; Critical when a read-write community has a default name or no ACL | the four `snmp_v1_v2c_*` facts |
| `hardening-snmp-v3-priv` | High | `snmp_v3_configured`, `snmp_v3_users`, `snmp_v3_users_without_priv`, `snmp_v3_groups_without_priv`, `snmp_global_enforce_priv` (NX-OS) |
| `hardening-insecure-mode` | High | `insecure_mode` (IOS-XE only) |
| `hardening-http-server` | High | `http_server` |
| `hardening-legacy-services` | High | `ip_source_route`, `legacy_services` |

A fact that was not read makes the Check raise a Low "could not decide" Finding, never a silent pass (story 6). Later batches ([#100](https://github.com/b-git-hub/network-analyser/issues/100), [#101](https://github.com/b-git-hub/network-analyser/issues/101), [#102](https://github.com/b-git-hub/network-analyser/issues/102)) add their own facts alongside these and use the same names for any they share.
