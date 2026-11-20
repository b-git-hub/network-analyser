# Cisco hardening baselines for IOS-XE and NX-OS

Research for the wayfinder ticket "Cisco hardening baselines for IOS-XE and NX-OS", a child of
"Map: Network Analysis, the way to a build spec". Findings dated **2026-11-20**. This file lives
on the throwaway branch `research/cisco-hardening-baselines` and is never merged.

The question: what does Cisco itself recommend for hardening IOS-XE and NX-OS, and which of those
recommendations could Analysis decide as Checks from data a Run already collects, and which would
need new read-only commands? CIS benchmarks are used only as a cross-check.

## Sources

Primary (Cisco), all read on 2026-11-20:

| Key | Document | Version or date |
|---|---|---|
| **XE-HG** | [Cisco IOS XE Software Hardening Guide](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening) | rev 3.2, 08-Dec-2025 |
| **NX-HG** | [Cisco NX-OS Software Hardening Guide](https://sec.cloudapps.cisco.com/security/center/resources/securing_nx_os.html) | updated 29-Sep-2025 |
| **RI** | [Cisco Resilient Infrastructure](https://www.cisco.com/c/en/us/about/trust-center/resilient-infrastructure.html) (hub page) | undated |
| **RI-WARN** | [Resilient Infrastructure IOS XE Security Warnings Reference](https://www.cisco.com/c/en/us/about/trust-center/resilient-infrastructure/resilient-infrastructure-security-warnings-reference.html) | undated |
| **RI-DEP** | [Feature Deprecation and Removal Details (PDF)](https://www.cisco.com/c/dam/en_us/about/doing_business/trust-center/docs/cisco-resilient-infrastructure-feature-deprecation-and-removal-details.pdf) | v1.0, 30-Sep-2025 |
| **RI-XE** | [Insecure Feature Restrictions on IOS XE](https://www.cisco.com/c/en/us/about/trust-center/resilient-infrastructure/insecure-feature-restrictions-on-ios-xe.html) | v1.0, 30-Jul-2026 |
| **RI-SEC** | [Protecting Secrets on Cisco Network Devices](https://www.cisco.com/c/en/us/about/trust-center/resilient-infrastructure/protecting-secrets.html) | 12-Mar-2026 |
| **C9K-PB** | [Cisco C9000 Switching IOS XE Resilient Infrastructure Playbook](https://www.cisco.com/c/en/us/products/collateral/networking/switches/catalyst-9000-switches/c9000-ios-xe-resilient-infra-pb.html) | updated 23-Feb-2026 |
| **XE-PB** | [Cisco IOS XE Resilient Infrastructure Product Bulletin](https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xe-17/ios-xe-resilient-infrastructure-pb.html) | 06-Aug-2026 |
| **SSH-CG** | [Secure Shell Version 2 Support (configuration guide)](https://www.cisco.com/en/US/docs/ios-xml/ios/sec_usr_ssh/configuration/12-2sr/sec-usr-ssh-12-2sr-book.html) | as returned by search; see note on C2 |
| **COPP-NX** | [Verify Control Plane Policing Violations (TAC, Nexus)](https://www.cisco.com/c/en/us/support/docs/quality-of-service-qos/control-plane-policing/217946-verify-control-plane-policing-violations.html) | rev 2.0, 26-Mar-2024 |
| **C9K-REL** | [Recommended Releases for Catalyst 9200/9300/9400/9500/9600](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9300-series-switches/214814-recommended-releases-for-catalyst-9200-9.html) | "current as of September 2026" |
| **N9K-REL** | [Minimum and Recommended Cisco NX-OS Releases for Nexus 9000](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/recommended_release/b_Minimum_and_Recommended_Cisco_NX-OS_Releases_for_Cisco_Nexus_9000_Series_Switches.html) | updated 01-Oct-2026 |
| **NX-LC** | [Cisco NX-OS Software Lifecycle Support Statement](https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/nx-os-software/guide_c07-658595.html) | updated 09-Oct-2026 |
| **SSA** | [Software Suggestion API (Cisco Support APIs)](https://developer.cisco.com/docs/support-apis/software-suggestion/) | v2 |
| **C9K-UPG** | [Upgrade Guide for Cisco Catalyst 9000 Switches](https://cisco.com/c/en/us/support/docs/switches/catalyst-9300-series-switches/216231-upgrade-guide-for-cisco-catalyst-9000-sw.html) | as returned by search |
| **C9K-STK** | [Catalyst 9300 Stack Manager and HA guide, 17.15.x: Managing Switch Stacks](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/stck_mgr_ha/b_1715_stck_mgr_ha_9300_cg/managing_switch_stacks.html) | 17.15.x |
| **VPC-UPG** | [Install/upgrade on Nexus switches in vPC (TAC)](https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/221034-install-upgrade-on-nexus-switches-in-vpc.html) | as returned by search |
| **BLOG-REL** | [Cisco blog: Strengthening the foundation (new release model)](https://blogs.cisco.com/security/strengthening-the-foundation-a-predictable-customer-focused-response-to-ai-accelerated-vulnerability-discovery) | 02-Jun-2026 |

Cross-check only: [CIS Cisco IOS XE 17.x v2.1.1 Level 1 (Tenable audit listing)](https://www.tenable.com/audits/CIS_Cisco_IOS_XE_17.x_v2.1.1_L1)
(CIS lists v2.2.1 as current at [cisecurity.org](https://www.cisecurity.org/benchmark/cisco); not read).

Access notes. The old support-doc URL for the IOS XE guide
(`/c/en/us/support/docs/ios-nx-os-software/ios-xe-16/220270-use-cisco-ios-xe-hardening-guide.html`)
now lands on an index page; the live guide is XE-HG. Pages were read through a summarising fetch,
so commands quoted below come from that reading; a few items are marked **unverified** where a
second source was not found or the fetch was ambiguous. The lab should confirm each command string
before it enters an allow-list, as it does for every v1 command.

## What a Run already holds

From `network_analyser/platforms/ios_xe/commands.py`, `network_analyser/platforms/nxos/commands.py`,
`network_analyser/records/topology.py` and `network_analyser/records/collected.py`:

| Data | IOS-XE command | NX-OS command | In the Topology record today |
|---|---|---|---|
| Running config (**RC**) | `show running-config view full` | `show running-config` (not `all`) | No: held in memory, then locked as the Backup |
| Version (**SV**) | `show version` | `show version` | `model`, `software_version`, `serials`, `stack_members` (number, serial, model; no per-member version) |
| Landing role | `show privilege` | `show user-account <name>` | No |
| Features | none | `show feature \| json` | No (used to skip commands) |
| Interfaces (**IF**) | `show interfaces`, `... switchport`, `... trunk`, `show ip interface`, `show etherchannel summary` | `show interface`, `... switchport`, `show ip interface vrf all`, `show port-channel summary` (all `\| json`) | `Interface`: admin/line state, mode, VLANs, IP, bundle |
| Neighbours (**NB**) | `show cdp neighbors detail`, `show lldp neighbors detail` | same, `\| json` | Links, Unvisited Devices |
| Routing/FHRP (**RT**) | OSPF, EIGRP, BGP summary, static, HSRP, VRRP, GLBP | same set plus vPC | L3 Adjacencies |

Two facts shape every Check below:

- **RC hides defaults.** Neither Platform's captured config shows a setting left at its default.
  NX-OS v1 sends plain `show running-config`, not `show running-config all`. So "line absent" means
  "default", and each Check must know the default for that Platform and release (see the traps
  column). Cisco's own NX-OS CoPP note says the default profiles "are normally hidden" and are
  seen with `show running-config copp all` (COPP-NX).
- **RC is secret-bearing.** It holds hashes, type 7 strings, SNMP communities, TACACS+/RADIUS keys
  and NX-OS SNMP localized keys. A Check reads it in memory during the Run; a Finding may name the
  command keyword and the type number (for example "username secret type 5") but must never quote
  the secret, hash or community string itself.

## Cisco's own priority and severity

- Neither hardening guide assigns a severity per item. Both say to protect the management and
  control planes first and call the data plane "the least important" of the three (XE-HG,
  NX-HG). Strong words used: iACLs are "one of the most critical security controls", `enable secret`
  "must be used", buffered logging "highly recommended", TACACS+ over TLS 1.3 "strongly recommends"
  (XE-HG).
- The Resilient Infrastructure programme is Cisco's clearest priority signal. It lists features
  that get a **warning** from IOS XE 17.18.2 and NX-OS 10.7.1, then a **restriction** (off on a
  fresh install; needs `system mode insecure`) from IOS XE 26.1.1 and NX-OS 10.7.2, then
  **removal** (RI-DEP, RI-XE). Anything on that list is something Cisco itself now calls insecure;
  this research treats those items as **High**.
- On IOS XE 17.18.2 and later, `show system insecure configuration` lists the active insecure
  commands "with severity and remediation", and C9K-PB calls the list exhaustive for those
  releases. That is the only per-item severity Cisco publishes, and it is device-side.

The **Priority** column below is this research's proposal: **High** = on Cisco's deprecation list
or called "must"; **Medium** = in both hardening checklists; **Low** = "if needed" or tuning.

## Resilient Infrastructure deprecation timeline (RI-DEP)

| Feature | IOS XE warning | IOS XE restriction | NX-OS warning | NX-OS restriction |
|---|---|---|---|---|
| Type 0, 5 or 7 credentials in config | 17.18.2 | 26.2.1 | 10.7.1 | 10.7.3 |
| SSH version 1 | 17.18.2 | 26.1.1 | n/a | n/a |
| SNMPv1/v2c | 17.18.2 | 26.1.1 | 10.7.1 | 10.7.2 |
| SNMPv3 noAuthNoPriv or authNoPriv | 17.18.2 | 26.1.1 | 10.7.1 | 10.7.2 |
| SNMPv3 MD5 auth or 3DES priv | 17.18.2 | 26.1.1 | n/a | n/a |
| IP source routing | 17.18.2 | 26.1.1 | 10.7.1 | 10.7.2 |
| TLS 1.0/1.1 | 17.18.2 | 26.1.1 | 10.7.1 | 10.7.2 |
| Telnet | 17.18.2 | 26.1.1 | 10.7.1 | 10.7.2 |
| FTP, TFTP | 17.18.2 | 26.1.1 | 10.7.1 | 10.7.2 |
| HTTP (some exceptions) | 17.18.2 | 26.1.1 | 10.7.1 | 10.7.2 |
| On-Demand Routing, BOOTP server, TCP/UDP small servers, IP finger | 17.18.2 | 26.1.1 | n/a | n/a |
| NTP control messages | TBA | TBA | n/a | n/a |
| TACACS+ with pre-shared key and MD5 | 17.18.2 | 26.1.1 | 10.7.1 | 10.7.2 |
| RADIUS with pre-shared key and MD5 (not RadSec) | 26.1.1 | n/a | 10.7.1 | n/a |

RI-DEP says release numbers "are subject to change". One disagreement: C9K-PB says types 0 and 7
are auto-converted to type 6 on upgrade to 26.1.1; RI-DEP and RI-SEC put auto-conversion at
26.2.1. Treat the release as **unverified** until the lab sees it.

IOS XE 26.1.1 adds a system security mode: `system mode insecure` appears in the saved config,
added automatically on upgrade when insecure commands are present; `show system security mode`
shows the mode (RI-XE). Cisco "advises against the use of insecure mode" (C9K-PB).

## IOS-XE recommendations

How decided: **RC** running config, **SV** `show version`, **IF/NB/RT** already-collected show
data, **NEW** a new command (exact string given).

| # | Recommendation (Cisco's reason) | Source | How decided | False-positive traps | Priority |
|---|---|---|---|---|---|
| X1 | SSH only on VTY: `transport input ssh`; `transport output none` or `ssh`; `transport input none` on unused tty lines (Telnet sends credentials in clear) | XE-HG, RI-WARN #14 | RC: each `line vty` block's `transport input` | Absent `transport input` means the release default, which has varied by release (**unverified** per release); decide from the explicit line, report "default" as unknown, not as a pass | High |
| X2 | `ip ssh version 2` (without it IOS XE runs 1.99, which accepts SSHv1) | XE-HG; SSH-CG says 1.99 is not supported from 17.10 | RC + SV: line absent **and** release earlier than 17.10 | From 17.10 the line may be absent yet v1 is refused; community reports differ on whether it shows (**unverified**). NEW `show ip ssh` gives the version in force | High |
| X3 | No plain-text web server: `no ip http server`; use `ip http secure-server` only if needed; TLS 1.2+ and GCM ciphers | XE-HG, RI-WARN #4-6, C9K-PB | RC: `ip http server`, `ip http tls-version`, `ip http secure-ciphersuite` | Whether absence means off depends on platform day-0 config (**unverified**); WebUI/RESTCONF users need HTTPS, so `secure-server` alone is not a failure | High |
| X4 | `enable secret`, never `enable password` (weak encryption; without a secret the console password can grant privileged access) | XE-HG | RC: `enable password`, missing `enable secret` | None significant | High |
| X5 | Strong stored secrets: types 8 or 9 for hashes (`algorithm-type scrypt`), type 6 for reversible keys; types 0, 4, 5, 7 are weak; type 7 is "treated like plain text" | RI-SEC, XE-HG, RI-WARN #3 | RC: the type digit after `secret`/`password`/`key` on `enable`, `username`, `line`, `snmp-server`, `tacacs`, `radius`, `ntp authentication-key`, key chains | From 16.12.x type 5 is auto-converted to type 9 (RI-SEC); from 26.1.1 or 26.2.1 types 0/7 auto-convert to type 6. Report only the type, never the string | High |
| X6 | Use `password encryption aes` with `key config-key` (type 6) instead of `service password-encryption` (type 7, "weak cipher that is easily reversed") | RI-WARN #3, RI-SEC | RC: `service password-encryption` present, `password encryption aes` absent | **Conflicts with CIS**, which still asks for `service password-encryption` (CIS 1.4.2). Cisco's current advice wins; the master key itself never appears in RC (RI-SEC) | Medium |
| X7 | Central AAA: `aaa new-model`, `aaa authentication login default group tacacs+ ...`, command authorization and accounting at levels 0/1/15, redundant servers | XE-HG | RC | Small sites may rely on local users by design; report "no AAA" separately from "no authorization/accounting" | Medium |
| X8 | TACACS+ over TLS 1.3 (17.18.1+) or RadSec instead of MD5 pre-shared keys | XE-HG, RI-WARN #36, RI-DEP | RC + SV | Only meaningful on releases that support it; today most estates will fail, so keep it informational | Low (rises as releases ship) |
| X9 | Brute-force protection: `login block-for <s> attempts <n> within <s>`; `aaa local authentication attempts max-fail <n>` (Cisco warns this can let an attacker lock out valid users) | XE-HG, CIS cross-check | RC | Privilege 15 users are exempt from max-fail (XE-HG) | Medium |
| X10 | `exec-timeout` on con and vty (default 10 minutes) | XE-HG | RC: `exec-timeout 0 0` or a value above the chosen limit | Absent line = 10-minute default, a pass | Medium |
| X11 | VTY `access-class <acl> in`; Management Plane Protection `management-interface ... allow ssh` | XE-HG, CIS 1.2.5 | RC | The ACL content cannot be judged mechanically; check presence only. MPP or an iACL may do the job instead | High |
| X12 | Disable AUX: `transport input none`, `no exec`, `exec-timeout 0 1` | XE-HG | RC: `line aux 0` block | Many Catalyst models have no AUX line; no `line aux` block means nothing to check | Low |
| X13 | Login banner `banner login` (legal notice; omit name, model, software, owner) | XE-HG | RC | Banner text may be in `banner motd` instead; accept either | Low |
| X14 | SNMP: prefer SNMPv3 `priv`; if v1/v2c, non-trivial community, RO, with ACL, with views | XE-HG, RI-WARN #22-28 | RC: `snmp-server community`, `snmp-server group ... v1/v2c/v3 auth/noauth`, `snmp-server host ... version 1/2c` | Default names (`public`, `private`) can be detected; never echo a community. A configured community with an ACL is still on Cisco's deprecation list | High |
| X15 | SNMPv3 users with SHA-2 auth and AES priv, not MD5/DES/3DES | RI-WARN #22, #24 | **NEW** `show snmp user` | XE-HG: SNMP users "are not displayed in running-config". The group's `priv` level is in RC; the algorithms are not | High |
| X16 | NTP with authentication: `ntp authenticate`, `ntp trusted-key`, `ntp server ... key`; not MD5 (use hmac-sha2-256) | XE-HG, RI-WARN #31-32 | RC | Configured is not working: NEW `show ntp associations` says whether the device is synchronised | Medium |
| X17 | `no ntp allow mode control` | XE-HG (rev 2.0) | RC: shows as `no ntp allow mode control 0` (XE-HG) | Only on releases with the command | Low |
| X18 | Logging: `logging host`, `logging trap 6`, `logging buffered`, `logging source-interface`, `service timestamps log datetime msec show-timezone`, `no logging console`, `no logging monitor` | XE-HG | RC | Defaults for buffered and timestamps exist and may be hidden; check `logging host` (strong) and level 7 (debug) at trap (weak) | Medium |
| X19 | Disable unused or legacy services: `no ip source-route` (on by default), `no service pad`, `no service tcp-small-servers`/`udp-small-servers`, `no ip finger`, `no ip bootp server`, `no service config`, `no ip domain-lookup`, `no router odr`, no `ip rcmd`, no FTP/TFTP config, no `service finger` | XE-HG, RI-WARN #10-13, #15, #18-21, #29 | RC | Defaults differ: source routing is on by default (look for `no ip source-route`); small servers off from 16.6.4, finger and BOOTP off after 16.1 (XE-HG). So the line that matters is sometimes the `no` form, sometimes the positive form | High (deprecated items), Low (domain-lookup, service config) |
| X20 | CDP/LLDP off where not needed (`no cdp enable` per port, or `no cdp run`; `no lldp transmit/receive`) | XE-HG, CIS 2.1.2 | RC + IF + NB: access ports with no Neighbour where CDP/LLDP is still enabled | **Network Analyser itself crawls CDP/LLDP**: flag edge ports only, never infrastructure Links. IP phones and some APs rely on CDP/LLDP (**unverified** from this research). CDP is on by default and LLDP off on IOS XE (default per CIS and common practice; **unverified** from a Cisco page here) | Low |
| X21 | `no ip redirects`, `no ip unreachables`, `no ip proxy-arp`; directed broadcast off (off by default since 12.0) | XE-HG | IF: the already-collected `show ip interface` prints each state per interface (also RC `no ...` lines) | Parser does not read these fields yet; exact strings to be confirmed against fixtures. Unreachables are rate-limited by default; proxy ARP may be needed by some hosts ("consider risk") | Medium |
| X22 | Control-plane protection: CoPP / CPPr / receive ACL | XE-HG | RC: `control-plane` + `service-policy input` | Catalyst 9000 applies `system-cpp-policy` by default and may not show default classes in RC (**unverified**, community). Decide with NEW `show policy-map control-plane` | Medium |
| X23 | Routing protocol authentication (OSPF, EIGRP, RIPv2, BGP `neighbor ... password`), passive-interface default | XE-HG | RC + RT: only for protocols with live neighbours | Auth may sit on a key chain, an OSPF area, a BGP peer-group or template; the Check must resolve inheritance | Medium |
| X24 | BGP `ttl-security hops`, `maximum-prefix`, prefix lists per neighbour | XE-HG | RC + RT (BGP summary lists the neighbours) | iBGP and multihop peers differ; informational | Low |
| X25 | FHRP authentication (`standby/vrrp/glbp ... authentication md5`; default is none) | XE-HG | RC + RT (HSRP/VRRP/GLBP brief) | Plain-text auth is also "authentication"; only MD5/key-chain counts | Medium |
| X26 | SSH tuning: `ip ssh time-out 60`, `ip ssh authentication-retries 3`, RSA key at least 2048 (warning below 3072, EC below 256) | XE-HG, RI-WARN #33-34 | RC for timeout/retries; key size **NEW** `show ip ssh` (**unverified** that it prints the modulus) or `show crypto key mypubkey rsa` | Key size never appears in RC (`crypto key generate` is an exec command) | Medium |
| X27 | Configuration archive and change logging (`archive` / `log config` / `hidekeys`), `configuration mode exclusive` | XE-HG | RC | Informational | Low |
| X28 | `service tcp-keepalives-in/out`; memory and CPU thresholds; `memory reserve critical` | XE-HG | RC | Informational | Low |
| X29 | Data-plane protections where needed: uRPF, DHCP snooping, IP Source Guard, DAI, port security, private VLANs, IP options drop, iACL/tACL | XE-HG ("if needed" and "consider risk") | RC + IF (access ports) | Design-dependent; never a failure on its own. Port security max 1 breaks HSRP (XE-HG) | Low |
| X30 | Insecure mode off (26.1.1+): `system mode insecure` should not be in config | RI-XE, C9K-PB | RC + SV | Only meaningful from 26.1.1; added automatically on upgrade when insecure commands existed | High |
| X31 | Cisco's own list of insecure commands (17.18.2+) | C9K-PB, RI-XE | **NEW** `show system insecure configuration` | Output format and whether it echoes secret values are **unverified**; treat its output as secret-bearing until the lab proves otherwise. Do **not** allow `test system secure db`/`all`: it is an exec action, not a show | High |
| X32 | `no service password-recovery` | XE-HG | RC | Cisco warns recovery then erases the config: a trade-off, not a failure | Low |

## NX-OS recommendations

| # | Recommendation (Cisco's reason) | Source | How decided | False-positive traps | Priority |
|---|---|---|---|---|---|
| N1 | Telnet off: `no feature telnet` (SSHv2 encrypts) | NX-HG, RI-DEP | RC `feature telnet`, or already-collected `show feature \| json` | Telnet is off by default and only offered at setup (NX-HG); exact feature name in JSON to confirm in lab | High |
| N2 | SSH only v2 (NX-OS supports only SSHv2), `ssh key rsa 2048`, `ssh login-attempts` (default 3) | NX-HG | SSHv1 not applicable. Key size **NEW** `show ssh key` | `ssh key` is config on NX-OS but a default key is hidden; JSON support **unverified** | Medium |
| N3 | Password strength-check on (default on; `no password strength-check` disables) | NX-HG | RC: `no password strength-check` | Not retroactive to existing passwords | Medium |
| N4 | Strong local hashes: SHA256 is the default ("type 5" on NX-OS); type 8/9 need explicit configuration | NX-HG | RC: type digit on `username ... password <type>` | **NX-OS type 5 is SHA-256-crypt, not IOS's MD5 type 5**: a cross-Platform "type 5 = weak" rule would be a false positive. Type 8/9 from 10.3(1)F per Cisco Community (**unverified**) | Medium |
| N5 | Type 6 (AES) for reversible keys (TACACS+/RADIUS/OSPF etc.), not default type 7; checklist: "Configure all passwords with type 6 AES encryption" | NX-HG App. A, RI-DEP (warning from 10.7.1) | RC: `key 7` vs `key 6`; `feature password encryption aes` (**unverified** exact string; NX-HG names no command) | Report the type only | High |
| N6 | AAA: TACACS+ (or RADIUS over TLS), command authorization (`aaa authorization commands` and `config-commands`), accounting, redundant servers in a group, fallback to local never `none` | NX-HG | RC | Cisco: do not disable local fallback on both default and console logins (lock-out risk) | Medium (fallback `none`: High) |
| N7 | TACACS+ over TLS 1.3 (10.6+), not MD5 pre-shared key | NX-HG, RI-DEP | RC + SV | Informational until estates move | Low |
| N8 | `exec-timeout` on console and vty (NX-HG states the default is 30 minutes) | NX-HG | RC: explicit `exec-timeout 0` or above the chosen limit | Absent line = default; the NX-HG default value is **unverified** against the configuration guide | Medium |
| N9 | VTY `access-class`; management VRF with ACL on mgmt0 | NX-HG App. A | RC: `line vty` / `access-class`, `ip access-group` on `interface mgmt0` | Up to 16 vty sessions by default; CoPP and iACLs may protect instead | High |
| N10 | MOTD/login banner (`banner motd`) | NX-HG | RC | No banner is configured by default (CIS NX-OS cross-check) | Low |
| N11 | SNMP: SNMPv3 with `snmp-server globalEnforcePriv` (SNMPv3 cannot be disabled and by default accepts noAuthNoPriv); communities strong, rotated and `use-acl` | NX-HG, RI-DEP | RC: `snmp-server community`, `snmp-server user ... auth sha ... priv aes-128`, `globalEnforcePriv`. **Unlike IOS-XE, NX-OS SNMP users are in RC** | Localized keys in RC are secret material: never quote | High |
| N12 | NTP: trusted sources, authentication, several servers | NX-HG | RC: `ntp server`, `ntp authenticate`, `ntp trusted-key` | NTP is on by default (NX-HG). Sync state: **NEW** `show ntp peer-status \| json` (**unverified** JSON) | Medium |
| N13 | Logging: `logging server <host> 6 use-vrf management`, `logging source-interface loopback0`, `logging timestamp milliseconds`, `logging logfile messages 6`, `no logging console`, `no logging monitor` | NX-HG | RC | Defaults hidden; `logging server` presence is the strong part | Medium |
| N14 | CDP off on untrusted ports (on by default); LLDP off by default (`feature lldp`) | NX-HG | RC + `show feature` + IF + NB | Same crawl trap as X20 | Low |
| N15 | `no ip source-route` (on by default) | NX-HG, RI-DEP (warning 10.7.1) | RC | Default on, so the `no` line is what passes | High |
| N16 | `no ip redirects`, `no ip unreachables`, `no ip proxy-arp`; directed broadcast off by default | NX-HG | IF: already-collected `show ip interface vrf all \| json` reports per-interface redirect, unreachable, proxy-ARP and directed-broadcast state (**unverified** JSON keys); RC `no ...` lines | vPC and some platforms need redirects off anyway; test per platform (NX-HG) | Medium |
| N17 | CoPP enabled ("As best practice, all Nexus switches must have CoPP enabled"; without it N9K supervisor traffic is limited to 50 pps) | COPP-NX, NX-HG | RC: `copp profile strict/moderate/lenient/dense` appears in `show running-config copp`; decide with **NEW** `show copp status \| json` | Setup offers "none", which removes the service-policy but keeps class maps (NX-HG) | Medium |
| N18 | Remove Guest Shell (`guestshell destroy`; enabled by default; 2.x is end of life) and keep Bash shell off or gated (`system security hardening sudo prompt-password`) | NX-HG | Bash: RC `feature bash-shell` or `show feature`. Guest Shell: **NEW** `show guestshell` (**unverified** exact form; `show virtual-service list` is an alternative) | Guest Shell state is not a feature line | Medium |
| N19 | Plain HTTP off (NX-API over HTTP; on Cisco's list from 10.7.1) | RI-DEP | RC: `feature nxapi`, `nxapi http port ...` | Mapping of "HTTP" in RI-DEP to NX-API is **unverified** | Medium |
| N20 | Routing protocol and FHRP authentication | NX-HG App. A ("antispoofing", control plane) | RC + RT | Same inheritance trap as X23/X25 | Medium |
| N21 | Configuration checkpoints (`feature scheduler`, scheduled `checkpoint`) | NX-HG | RC | Informational | Low |
| N22 | Data-plane: tACLs, uRPF, IP source guard, DAI, port security, private VLANs, NetFlow | NX-HG ("if needed") | RC + IF | Design-dependent | Low |

## Platform differences that matter to Check design

- **Defaults differ and are hidden in both.** CDP on, LLDP off and source routing on are shared;
  exec-timeout default is 10 minutes on IOS XE and (per NX-HG) 30 on NX-OS; Telnet is a feature
  on NX-OS (`feature telnet`) but a line transport on IOS XE.
- **Secret types are not portable.** NX-OS type 5 is SHA-256 (acceptable); IOS type 5 is MD5
  (weak). Each Platform needs its own type table.
- **SNMPv3 users** are in RC on NX-OS but not on IOS XE.
- **SSHv1** exists only on IOS XE.
- **CoPP** is default-on on Catalyst 9000 and Nexus 9000 but may be hidden from RC on both.
- **NX-OS has `show feature`** already collected: several NX-OS Checks need no RC parsing.
- **Insecure mode** (`system mode insecure`, `show system insecure configuration`) is IOS XE only
  for now; NX-OS gets restrictions from 10.7.2 (RI-DEP) with details "documented in the future"
  (RI-SEC).

## Candidate Checks, ranked

Decidable from data a Run already holds (RC, `show version`, collected show data). Strongest
first: low false-positive risk, on Cisco's deprecation list, needing only one config line.

1. Telnet allowed for management (X1, N1)
2. Reversible or weak stored secrets: types 0/4/7 everywhere, type 5 on IOS-XE only (X5, N4, N5)
3. `enable password` used or `enable secret` missing (X4)
4. SNMPv1/v2c in use: communities, v1/v2c groups and trap hosts, with sub-findings for default
   names, RW and no ACL (X14, N11)
5. SNMPv3 group or NX-OS user without `priv`; NX-OS without `globalEnforcePriv` (X14, N11)
6. Insecure mode on, IOS XE 26.1.1+ (X30)
7. Plain-text HTTP server on (X3, N19)
8. Legacy services on: source routing, PAD, small servers, finger, BOOTP, ODR, rcmd, FTP/TFTP
   (X19, N15)
9. SSHv2 not enforced on IOS-XE releases before 17.10 (X2)
10. No VTY access-class (X11, N9)
11. AAA login fallback to `none` (N6, X7)
12. No central AAA, no command authorization or accounting (X7, N6)
13. NTP missing or unauthenticated, or MD5 keys (X16, N12)
14. No remote syslog server (X18, N13)
15. Idle timeout disabled (`exec-timeout 0`) or above the chosen limit (X10, N8)
16. `service password-encryption` without type 6, or type 6 not enabled (X6, N5)
17. Password strength-check disabled, NX-OS (N3)
18. No brute-force protection, IOS-XE (X9)
19. Routing adjacencies without authentication, for protocols with live neighbours (X23, N20)
20. FHRP groups without MD5 authentication (X25, N20)
21. ICMP redirects, unreachables, proxy ARP or directed broadcast on L3 interfaces, from the
    already-collected `show ip interface` (X21, N16)
22. CDP/LLDP enabled on edge access ports with no Neighbour (X20, N14)
23. Bash shell enabled, NX-OS (N18, `show feature`)
24. AUX line not disabled (X12)
25. No login banner (X13, N10)
26. SSH time-out and retries not set (X26)
27. NTP control messages allowed (X17)
28. TACACS+/RADIUS over MD5 pre-shared keys instead of TLS (X8, N7)
29. BGP neighbours without TTL security or maximum-prefix (X24)
30. No config archive or checkpoints (X27, N21)
31. Keepalives and resource thresholds missing (X28)
32. `service password-recovery` left on (X32)
33. Data-plane protections absent on access or edge ports, informational (X29, N22)

Lifecycle and consistency, all from `show version` already collected:

34. The same model runs different releases across the Visited Devices
35. Stack members, or a StackWise Virtual pair, on different releases or modes (needs the
    stack table in `show version` parsed per member; `StackMember` has no version field today)
36. vPC peers on different NX-OS releases (`show version` plus the vPC record)
37. Catalyst 9000 running in bundle mode instead of install mode
38. IOS XE on a Standard-Support train instead of an Extended-Support one

That is **38 candidate Checks decidable from existing data**, of which about 21 (1 to 21) are
strong enough to ship as Findings and the rest are informational.

Needing new read-only commands (**6 Checks**):

| Check | IOS-XE command | NX-OS command |
|---|---|---|
| A. SNMPv3 users with MD5, DES or 3DES (X15) | `show snmp user` | not needed (users in RC) |
| B. NTP configured but not synchronised (X16, N12) | `show ntp associations` | `show ntp peer-status \| json` |
| C. CoPP not actually applied (X22, N17) | `show policy-map control-plane` | `show copp status \| json` |
| D. SSH host key too short (X26, N2) | `show ip ssh` (or `show crypto key mypubkey rsa`) | `show ssh key` |
| E. Cisco's own insecure-config list, 17.18.2+ (X31) | `show system insecure configuration` | none yet |
| F. Guest Shell present (N18) | not applicable | `show guestshell` (or `show virtual-service list`) |

All are `show` commands, which do not change device state. Each would be added to the per-Platform
allow-list and the Device Role (ADR 0005), and the commands module says adding a command is a
breaking change (minor version bump, CHANGELOG entry). The lab must confirm each string, its JSON
form on NX-OS, and that its output holds no secret; until then treat new outputs like RC. `show ip
ssh` would also settle Check 9 on 17.10+ releases. `show running-config all` on NX-OS would expose
hidden defaults but doubles the secret-bearing capture, so it is not proposed.

Lifecycle Check needing data from outside the device:

39. Not on a Cisco recommended release: compare `show version` against Cisco's published
    recommendation (see below). Not a device command.

## Software consistency and recommended releases

**Consistency.** Cisco's documents say little about "same model, same release" across a network:

- Stack members "must be running compatible software versions"; `show switch` reports members in
  "version-mismatch mode" (C9K-STK). The guide says compatible, not identical.
- vPC peers on different NX-OS versions are treated as a transient upgrade state: Cisco notes
  that during a vPC upgrade keepalive or peer-link may stay down "since Cisco Nexus switches in vPC
  have different version of Cisco NX-OS which is unsupported", and the installer asks for the same
  boot mode on both peers (`show boot mode`) (VPC-UPG).
- Catalyst 9000 "install mode is the newer and recommended mode to run" (C9K-UPG).
- No fetched Cisco page states a general rule that every device of one model must run one release.
  A "same model, different releases" Check is good operational hygiene but rests on this tool's
  policy, not a Cisco statement (**unverified as a Cisco recommendation**).

**Recommended releases.**

- Catalyst 9200 to 9600: Cisco recommends 17.18.4 and 17.15.6 "as of September 2026", and "it is
  recommended that you stay on Extended-Support releases wherever possible". Extended-Support
  trains (17.12, 17.15, 17.18) get 48 months; Standard-Support (17.13, 17.14, 17.16, 17.17) get 12
  (C9K-REL).
- Nexus 9000: 10.5(6)M and 10.6(4)M for newer hardware; older hardware 10.4(7)M, 10.3(8)M (EX)
  or 9.3(16), as of 01-Oct-2026 (N9K-REL). The NX-OS lifecycle statement now says "all major
  release trains will be designated as the recommended release within their lifecycle"; the
  long-lived/short-lived split is gone (NX-LC).
- Cisco moved to scheduled security-hardened releases in 2026; core NOS (IOS XE, NX-OS) ship
  quarterly, and "Any release predating our security-hardened versions carries materially higher
  risk" (BLOG-REL).
- Recommendations are published per platform family, not per PID, on these pages.

**API.** The Cisco Support **Software Suggestion API** v2 returns suggested releases per PID:
`GET https://apix.cisco.com/software/suggestion/v2/suggestions/releases/productIds/{productIds}`
(up to 10 PIDs), plus `.../software/productIds/...` with images and
`.../compatible/productId/{basePID}`; each suggestion carries `isSuggested` Y/N, release, train
and lifecycle (SSA). It needs a Cisco API credential and an internet call, and Cisco Community
threads report that some valid PIDs return nothing. For Network Analyser that means: the device
side (PID and release from `show version`) is already collected, but the comparison needs either
an operator-supplied reference table or a separate, opt-in API step. Putting a Cisco API key into
a Run conflicts with "passwords are never stored" unless it is entered at a prompt like a
Credential Set; this is for the downstream ticket "Which configuration, lifecycle and consistency
Checks ship" to decide.

## Open items for the lab

- Exact `show ip interface` (IOS-XE) text and NX-OS JSON keys for redirects, unreachables, proxy
  ARP and directed broadcast.
- `show feature | json` names for telnet, ssh, nxapi, bash-shell, lldp.
- Whether `show ip ssh` prints the key size and SSH version on current IOS XE releases.
- Whether `show system insecure configuration` echoes secret values.
- Default `transport input` on vty and default HTTP server state per IOS XE release and platform.
- NX-OS exec-timeout default and type 8/9 username syntax.
