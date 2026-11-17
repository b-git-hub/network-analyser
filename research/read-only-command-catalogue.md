# Read-only command catalogue per Platform

Research for [issue #4](https://github.com/b-git-hub/network-analyser/issues/4). This feeds the topology model decision (#11).

**Question.** For IOS/IOS-XE, NX-OS and PAN-OS, which read-only commands or API calls return each piece of data the Topology and Backups need? What output format does each give, and what is the least-privilege role that can run it?

Terms follow [GLOSSARY.md](../GLOSSARY.md): Platform, Backup, Topology, Link, L3 Adjacency, Neighbour, VLAN Mismatch, Visited Device, Credential Set.

Sources are Cisco and Palo Alto Networks documentation, cited inline as [S1]…[S22] and listed at the end. A statement marked **(unverified)** could not be traced to a vendor page and needs a lab check before anyone relies on it. Statements marked **(derived)** follow mechanically from a documented rule, for example the PAN-OS CLI-to-XML mapping [S20], but the exact string was not seen in the docs.

---

## 1. Headline answer

| Platform | Transport that gives structured output with no device change | Backup command | Least-privilege role |
|---|---|---|---|
| IOS / IOS-XE | **None over SSH.** IOS-XE has no general JSON/XML option for `show` commands. Structured data needs NETCONF or RESTCONF with Cisco-IOS-XE-*-oper YANG models [S6][S7], and both must be switched on on the device first. Over SSH the tool has to parse text. | `show running-config` (priv 15), or `show running-config view full` at a lowered level [S1] | A custom privilege level with each allow-listed command moved to it using `privilege exec level N …` [S3]. Priv 15 works but is not least privilege. |
| NX-OS | **SSH with `\| json`** on almost every `show` command [S10]. NX-API returns the same JSON but is off by default [S9]. | `show running-config` (text only) | A **custom role** whose `rule … permit command …` lines cover exactly the allow-list [S4][S5]. **`network-operator` cannot run `show running-config`** [S4]. |
| PAN-OS | **The XML API is XML by design** (`type=op`, `type=config&action=show`) [S13][S14]. It runs over HTTPS, which is enabled by default on the management interface [S12]. | `type=config&action=show` (active config) [S14], or `type=export&category=configuration` (unverified) | Dynamic role **Superuser (read-only)** (CLI `superreader`), which is on the list of roles allowed to use the API [S12][S15]. A custom Admin Role Profile is riskier, because its single XML API "Configuration" switch grants "retrieve **or modify**" [S16]. |

## 2. IOS / IOS-XE (Catalyst)

### 2.1 Structured output

- **SSH CLI.** IOS and IOS-XE have no general `| json` or `| xml` for `show` commands. The newer `show running-config | format netconf-xml|restconf-json` renders only the YANG view of the configuration. A Cisco Community report says it returns nothing for many `show` commands. The tool has to parse text with its own parsers or TextFSM/Genie-style templates. **(unverified: there is no Cisco command reference entry for `| format`.)**
- **NETCONF / RESTCONF (IOS-XE 16.x and later).** Cisco publishes operational YANG models for each data item the tool needs. As of release 17.15.1 the [YangModels/yang](https://github.com/YangModels/yang/tree/main/vendor/cisco/xe/17151) repository has `Cisco-IOS-XE-cdp-oper` (which has `mgmt-address`), `-lldp-oper` (which has `mgmt-addr`), `-matm-oper` (the MAC table), `-arp-oper`, `-interfaces-oper`, `-switchport-oper`, `-vlan-oper`, `-vrf-oper`, `-ospf-oper`, `-eigrp-oper`, `-bgp-oper`, `-stack-oper`, `-ha-oper` and `-spanning-tree-oper` [S7].
  - **Privilege.** Before 17.5, NETCONF and RESTCONF accepted only privilege-15 users. In Cisco's words: "RADIUS or TACACS+ users defined with privilege level 15 access are allowed" [S6]. From 17.5 a read-only user at privilege 1 is supported through NACM. The operator sets it up once with `request platform software yang-management nacm populate-read-rules privilege 1`. That grants `get`, `get-config` and `get-schema`, and "sensitive data gets masked" [S8].
  - **Consequence.** NETCONF and RESTCONF need `netconf-yang` / `restconf` and the HTTPS server switched on by the operator. The tool must never enable them itself. On releases before 17.5 they also force priv 15. A Backup taken through NETCONF as a low-privilege user has its secrets masked, so it may not be a faithful restore copy **(inference from [S8])**.

### 2.2 Privilege model

- The defaults are level 1 (user EXEC) and level 15 (privileged EXEC). There are 16 levels. `privilege exec level N <command>` moves a command to level N, and "all commands whose syntax is a subset of that command are also set to that level" [S3].
- **`show running-config` below level 15 gives a partial config.** It "displays all of the commands that the user is able to modify at their current privilege level" [S1]. To get the whole config at a lower level, the operator configures `privilege exec level N show running-config view full`. On 16.x and later, "depending on the platform", `file privilege N` is also needed [S1]. **Security trade-off:** `file privilege N` opens file-system access at that level, and a full running-config contains secrets. Both are acceptable only because Backups are encrypted at rest. The operator should still make this choice knowingly.
- Role-based CLI views (`parser view`) are an alternative for exact command allow-lists on any IOS-XE image [S2]. TACACS+ per-command authorization is another.
- The default level of each `show` command below **was not verified** against Cisco docs. The recommended role is a dedicated level, for example 7, with every allow-listed command moved to it explicitly. The default level then no longer matters. Run `show privilege` to check the level [S3].

### 2.3 Catalogue

| Data needed | CLI command (SSH) | Structured? | Minimum role |
|---|---|---|---|
| Session setup | `terminal length 0` (session only, not a config change) | n/a | level 1 |
| Platform identification | `show version`, `show inventory` | text; YANG `Cisco-IOS-XE-platform-oper` / `device-hardware-oper` | custom level N |
| Running configuration (Backup) | `show running-config` (priv 15) or `show running-config view full` (lowered level, plus `file privilege N` on 16.x and later) [S1] | text; YANG `get-config` (secrets masked for low priv on 17.5 and later [S8]) | priv 15, or level N with `view full` |
| CDP Neighbours and management IPs | `show cdp neighbors detail` | text; `Cisco-IOS-XE-cdp-oper` (`mgmt-address`, `ip-address`) [S7] | custom level N |
| LLDP Neighbours and management IPs | `show lldp neighbors detail` | text; `Cisco-IOS-XE-lldp-oper` (`mgmt-addr`) [S7] | custom level N |
| MAC address table | `show mac address-table` | text; `Cisco-IOS-XE-matm-oper` [S7] | custom level N |
| ARP table | `show ip arp` and `show ip arp vrf <name>` per VRF (list VRFs with `show vrf`) | text; `Cisco-IOS-XE-arp-oper` [S7] | custom level N |
| Interface status | `show interfaces status`, `show interfaces` | text; `Cisco-IOS-XE-interfaces-oper` | custom level N |
| Port-channels | `show etherchannel summary` | text; interfaces-oper | custom level N |
| Stacks / StackWise Virtual / HA | `show switch`, `show stackwise-virtual`, `show redundancy` | text; `-stack-oper`, `-ha-oper` [S7] | custom level N |
| Trunks and allowed VLANs | `show interfaces trunk` (allowed / allowed-and-active / forwarding-not-pruned), `show interfaces switchport` | text; `Cisco-IOS-XE-switchport-oper` [S7] | custom level N |
| VLAN database | `show vlan brief`, `show vtp status` | text; `Cisco-IOS-XE-vlan-oper` [S7] | custom level N |
| L3 interfaces and subnets | `show ip interface` (prints "Internet address is a.b.c.d/nn"). `show ip interface brief` has **no mask**. | text; interfaces-oper | custom level N |
| OSPF Neighbours (L3 Adjacency) | `show ip ospf neighbor` (all processes) | text; `-ospf-oper` [S7] | custom level N |
| EIGRP Neighbours | `show ip eigrp neighbors`, `show ip eigrp vrf <name> neighbors` | text; `-eigrp-oper` [S7] | custom level N |
| BGP Neighbours | `show bgp all summary` (all AFs) or `show ip bgp summary` / `show ip bgp vpnv4 all summary` | text; `-bgp-oper` [S7] | custom level N |

## 3. NX-OS (Nexus)

### 3.1 Structured output

- **SSH CLI.** NX-OS turns `show` output into XML, JSON or JSON-pretty when piped through a formatter (`| json`, `| json-pretty`, `| xml`). From 9.3(1) there are also `| json native` and `| json-pretty native`. JSON output is capped at 60 MB. Most commands support every format, but "Consistency checker commands support XML, but not any variant of JSON" [S10]. **This needs no device change and is the recommended NX-OS path.**
- **NX-API CLI** (`cli_show`, `cli_show_ascii`) gives the same data over HTTPS. However "NX-API is disabled by default" and needs `feature nxapi`. "The remote HTTP access is disabled by default" [S9]. Each request accepts at most 10 consecutive show commands. An `nxapi_auth` cookie lasts 600 seconds [S9]. Over NX-API "Each command is only executable with the current user's authority", and unauthorised calls return HTTP 401 [S10]. Enabling it is an operator decision, not something the tool does.
- `show running-config` is text. It is captured with `cli_show_ascii` or plain SSH.

### 3.2 Privilege model

- The predefined roles are `network-admin` ("Complete read-and-write access") and `network-operator` ("Complete read access"). However, **"The network-operator role does not have access to the show running-config or show startup-config commands"**, and "Some show commands may be hidden from network-operator users" [S4].
- In a custom role, `rule N permit command <cmd>` adds one command. There can be up to 256 rules per role, and they are applied in descending order. Separately, "some commands can be executed only by using the predefined network-admin role" [S4].
- Cisco's own backup-tool guidance builds a custom role (`role name oxidized`) with these rules: `permit command terminal length 0`, `show version`, `show inventory` and `show running-config`. If `terminal length 0` is left out, the role gets "% Permission denied for the role" [S5].
- Privilege levels 0–15 map to roles `priv-0` … `priv-15` when they are enabled. `priv-15` equals network-admin [S11]. Do not use it.
- **Recommended role:** one custom role that permits exactly the per-Platform allow-list below. The `| json` suffix is part of each allow-listed command string. The role does not inherit network-operator.

### 3.3 Catalogue

| Data needed | CLI command (SSH; add `\| json` unless noted) | Structured? | Minimum role |
|---|---|---|---|
| Session setup | `terminal length 0` | n/a | custom role (must be permitted [S5]) |
| Platform identification | `show version`, `show inventory` | JSON | network-operator or custom |
| Running configuration (Backup) | `show running-config` (**no** `\| json`; the output is text) | text | **custom role only**. network-operator is denied [S4][S5]. |
| CDP Neighbours and management IPs | `show cdp neighbors detail` | JSON | network-operator or custom |
| LLDP Neighbours and management IPs | `show lldp neighbors detail` | JSON | network-operator or custom |
| MAC address table | `show mac address-table` | JSON | network-operator or custom |
| ARP table | `show ip arp vrf all` | JSON | network-operator or custom |
| Interface status | `show interface status`, `show interface` | JSON | network-operator or custom |
| Port-channels | `show port-channel summary` | JSON | network-operator or custom |
| vPC | `show vpc brief`, `show vpc peer-keepalive` | JSON | network-operator or custom |
| Modules / HA | `show module`, `show system redundancy status` | JSON | network-operator or custom |
| Trunks and allowed VLANs | `show interface trunk`, `show interface switchport` | JSON | network-operator or custom |
| VLAN database | `show vlan brief` | JSON | network-operator or custom |
| L3 interfaces and subnets | `show ip interface vrf all` (includes the prefix), `show vrf` | JSON | network-operator or custom |
| OSPF Neighbours | `show ip ospf neighbors vrf all` | JSON | network-operator or custom |
| EIGRP Neighbours | `show ip eigrp neighbors vrf all` | JSON | network-operator or custom |
| BGP Neighbours | `show bgp all summary vrf all` or `show ip bgp summary vrf all` | JSON | network-operator or custom |

The exact NX-OS command syntax above follows standard NX-OS usage and was not checked line by line against the command reference. **(unverified as exact strings.)** Before it is frozen as the allow-list, confirm each command against the target release in a lab or the NX-API sandbox [S19].

## 4. PAN-OS (Palo Alto)

### 4.1 Structured output

- **XML API over HTTPS.** The firewall serves the API over HTTPS by default. Plain HTTP needs an interface management profile [S12]. Request types: `keygen`, `config`, `op`, `export`, `report`, `log`, `commit`, `import`, `user-id`, `version` [S13].
  - Configuration reads: `action=show` returns the **active** (running) config and `action=get` returns the **candidate** [S13][S14]. The Backup should use `show`.
  - Operational commands: `type=op&cmd=<xml>`. The XML body mirrors the CLI. For example, `show system info` becomes `<show><system><info></info></system></show>` [S20]. On the device, `debug cli on` or the API browser at `/api` shows the exact XML for any CLI command [S20].
  - Authentication: `type=keygen` returns an API key, which is then sent in the `X-PAN-KEY` header [S20]. **The API key is a credential.** It stays in memory for one Run and is never logged. Palo Alto recommends key lifetimes and a dedicated API admin account, and says to "Use a POST request for any call that may contain sensitive information" [S12]. That means keygen must use POST and never put the username or password in the URL.
- **SSH CLI** works too. Output is text unless `set cli config-output-format` is used, which is a session setting **(unverified)**. Prefer the XML API.

### 4.2 Privilege model

- The API accepts these dynamic roles: Superuser, **Superuser (readonly)**, Device admin, Device admin (readonly), Vsys admin, Vsys admin (readonly). It also accepts role-based admins built from an Admin Role Profile [S12].
- In an Admin Role Profile, the CLI options are None, superuser, **superreader** ("Read-only access to the firewall"), deviceadmin and **devicereader** ("Read-only access to firewall settings, except password profiles … and administrator accounts") [S15].
- **Trap:** in an Admin Role Profile, the XML API privileges are simple Enable/Disable switches. The **Configuration** switch is described as "Permissions to retrieve **or modify** … configurations". **Operational Requests** is "Permissions to run operational commands", and **Export** covers "configurations … certificates, and keys" [S16]. No XML API switch means "config read-only". A custom role with Configuration on can therefore edit the candidate config, though it cannot commit unless Commit is also on [S16].
- **Recommended role:** **Superuser (readonly)** on a single firewall. Use Device admin (readonly) in multi-vsys setups if superreader is too wide. Both are documented as API-capable and read-only [S12][S15]. It still needs lab checking whether a custom profile with **only** Operational Requests on can run `<show><config><running/></config></show>` and every op command below. **(unverified)**. If it can, that profile would be narrower than superreader.

### 4.3 Platform facts that change the Topology

- **No CDP.** PAN-OS sends and receives LLDP only. CDP appears only in the IoT Security SNMP discovery plugin, which this tool does not use (it uses no SNMP) [S17].
- **LLDP is opt-in.** The admin procedure enables LLDP globally under Network > LLDP and then per interface [S18]. A firewall that has not been set up this way is invisible to LLDP crawling. With profile "None", only the three mandatory TLVs are sent, so **no management address is advertised**. A management address (up to four) needs an LLDP profile [S18]. Neighbours are capped at five per interface [S18]. LLDP is not supported on tap, HA, decrypt-mirror, vwire/VLAN/L3 **subinterfaces**, or PA-7000 LPC interfaces [S17].
- **No EIGRP.** Virtual routers support static, BGP, OSPF, OSPFv3 and RIP [S21].
- **Two routing engines.** The legacy engine uses `show routing …`. The Advanced Routing Engine (logical routers, PAN-OS 10.2 and later) uses `show advanced-routing …` [S22][S21]. The tool must detect which engine is in use, for example by checking for `<advanced-routing>` in the config or trying both.
- **There is no "VLAN database".** VLANs are 802.1Q tags on Layer 3 or Layer 2 subinterfaces and VLAN interfaces. They are read from the config (interface `tag`) and `show interface all`. A firewall trunk's allowed VLAN set is the set of subinterface tags. This matters for VLAN Mismatch.

### 4.4 Catalogue

| Data needed | CLI command | XML API call | Structured? | Minimum role |
|---|---|---|---|---|
| Platform identification | `show system info` | `type=op&cmd=<show><system><info/></system></show>` [S20], or `type=version` [S13] | XML | Superuser (readonly) |
| Running configuration (Backup) | `show config running` | `type=config&action=show&xpath=/config` (active) [S14], or `type=op&cmd=<show><config><running/></config></show>` (derived), or `type=export&category=configuration` (unverified) | XML | Superuser (readonly). A custom profile needs Configuration (read **or write**) or Export [S16]. |
| LLDP Neighbours and management IPs | `show lldp neighbors all` | `type=op&cmd=<show><lldp><neighbors>all</neighbors></lldp></show>` (derived) | XML | Superuser (readonly) |
| CDP Neighbours | not supported [S17] | n/a | n/a | n/a |
| MAC address table (Layer 2 interfaces only) | `show mac all` | `<show><mac>all</mac></show>` (derived) | XML | Superuser (readonly) |
| ARP table | `show arp all` | `<show><arp><entry name="all"/></arp></show>` (derived; check in the API browser) | XML | Superuser (readonly) |
| Interface status, aggregate (`ae`) groups, subinterface tags, L3 IPs and subnets | `show interface all`, `show interface logical`, `show interface <name>` | `<show><interface>all</interface></show>` (derived) | XML | Superuser (readonly) |
| HA | `show high-availability all` / `state`; cluster: `show high-availability cluster state` [S22b] | `<show><high-availability><all/></high-availability></show>` (derived) | XML | Superuser (readonly) |
| VLANs | `show vlan all` (Layer 2 / PVST+) [S22]; tags from config | config `show` and `show interface all` | XML | Superuser (readonly) |
| Routing table | legacy `show routing route`; ARE `show advanced-routing route` [S22] | `<show><routing><route/></routing></show>` (derived) | XML | Superuser (readonly) |
| OSPF Neighbours | legacy `show routing protocol ospf neighbor`; ARE `show advanced-routing ospf neighbor` [S22] | derived from the CLI | XML | Superuser (readonly) |
| BGP Neighbours | legacy `show routing protocol bgp peer`; ARE `show advanced-routing bgp peer status logical-router <lr>` [S22] | derived from the CLI | XML | Superuser (readonly) |
| EIGRP | not supported [S21] | n/a | n/a | n/a |

## 5. Consequences for other tickets

1. **Role and Credential tickets.** No Platform offers a stock read-only role that also gets the full running config:
   - NX-OS needs a custom role, because network-operator is denied `show running-config` [S4].
   - IOS-XE needs priv 15, or a custom level with `view full` plus `file privilege` [S1].
   - PAN-OS needs Superuser (readonly), because custom XML API roles cannot be made config-read-only [S16].

   The tool should ship per-Platform role snippets for operators to apply. These snippets are documentation, never pushed by the tool.
2. **Transport decision.** SSH alone covers everything on IOS-XE (text) and NX-OS (`| json`). PAN-OS is far better served by the HTTPS XML API, which needs no device change. NETCONF, RESTCONF and NX-API each need device configuration the tool cannot make, plus extra open ports. Keep them optional, not required.
3. **Parsing cost is uneven.** IOS/IOS-XE is the only Platform without native structured output over SSH. Its text parsers are the largest test-fixture surface, and every fixture must be synthetic or sanitised per CLAUDE.md.
4. **Topology model (#11).**
   - Firewalls often will not appear as LLDP Neighbours, and never as CDP Neighbours. Links to them will mostly be **inferred** from MAC/ARP data or from shared subnets (L3 Adjacency).
   - A PAN-OS LLDP advertisement often carries no management IP, so Scope-fenced crawling cannot jump from it.
   - The model must allow EIGRP to be absent on PAN-OS. It must also handle VRFs / virtual routers / logical routers as a first-class scope for ARP and routing Neighbours.
   - VLAN Mismatch on a firewall Link compares a switch trunk's allowed list against the firewall's subinterface tags. A PAN-OS VLAN database does not exist to compare against.
5. **Allow-list format.** On NX-OS the `| json` suffix is part of the permitted command string, so the RBAC role and the tool's allow-list must match character for character.

## 6. Open items needing a lab

- PAN-OS: can a custom Admin Role Profile with only Operational Requests read the running config and run every op command above?
- PAN-OS: confirm the exact op XML for `show arp all`, `show lldp neighbors all` and `show high-availability all` in the device API browser.
- IOS-XE: confirm the default privilege level of each catalogued `show` command, and whether `file privilege` is needed on the target Catalyst releases.
- NX-OS: confirm none of the catalogued commands is in the "network-admin only" set [S4], and check the exact JSON command strings against the target release.

## Sources

- [S1] Cisco, *Configure IOS XE to Display Full show running-config for Users with Lower Privilege*, doc 212149. https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-aggregation-services-routers/212149-Configure-IOS-XE-to-display-full-show-ru.html
- [S2] Cisco, *Role-Based CLI Access* (IOS XE). https://www.cisco.com/en/US/docs/ios/ios_xe/sec_user_services/configuration/guide/sec_role_base_cli_xe.html
- [S3] Cisco, *Controlling Switch Access with Passwords and Privilege Levels*, Security Configuration Guide, IOS XE 17.9.x (Catalyst 9300). https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/sec/b_179_sec_9300_cg/controlling_switch_access_with_passwords_and_privilege_levels.html
- [S4] Cisco, *Nexus 9000 NX-OS Security Configuration Guide 10.2(x): Configuring User Accounts and RBAC*. https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/102x/configuration/Security/cisco-nexus-9000-nx-os-security-configuration-guide-102x/m-configuring-user-accounts-and-rbac.html
- [S5] Cisco, *Configure User RBAC for the Oxidized or RANCID Network Configuration Backup Tools* (NX-OS), doc 215024. https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/nx-os-software/215024-configure-user-rbac-for-the-oxidized-or.html
- [S6] Cisco DevNet, *IOS XE: NETCONF/RESTCONF AAA*. https://developer.cisco.com/site/odp/documents/xe-user-guide-xconf-aaa/
- [S7] Cisco IOS-XE YANG models, release 17.15.1, YangModels/yang (Cisco-published). https://github.com/YangModels/yang/tree/main/vendor/cisco/xe/17151
- [S8] Cisco, *Catalyst 9800 Programmability and Telemetry Deployment Guide* (low-privilege NACM read-only from 17.5). https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9800-series-wireless-controllers/catalyst-9800-programmability-telemetry-deployment-guide.html
- [S9] Cisco, *Nexus 9000 NX-OS Programmability Guide 10.3(x): NX-API CLI*. https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/programmability/cisco-nexus-9000-series-nx-os-programmability-guide-release-103x/m-n9k-nx-api-cli-101x.html
- [S10] Cisco, *Nexus 9000 NX-OS Programmability Guide 9.3(x): NX-API CLI* (CLI formatters and the user's authority). https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/progammability/guide/b-cisco-nexus-9000-series-nx-os-programmability-guide-93x/b-cisco-nexus-9000-series-nx-os-programmability-guide-93x_chapter_010011.html
- [S11] Cisco, *Nexus 9000 NX-OS Security Configuration Guide 10.2(x): Configuring TACACS+* (priv-0..priv-15 mapping). https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/102x/configuration/Security/cisco-nexus-9000-nx-os-security-configuration-guide-102x/m-configuring-tacacs.html
- [S12] Palo Alto Networks, *Enabling API Access*. https://docs.paloaltonetworks.com/ngfw/api/api-authentication-and-security/pan-os-api-authentication
- [S13] Palo Alto Networks, *PAN-OS XML API Request Types and Actions*. https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions
- [S14] Palo Alto Networks, *Actions for Reading a Configuration* (show = active, get = candidate). https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-panorama-api/pan-os-xml-api-request-types/pan-os-xml-api-request-types-and-actions/configuration-actions/actions-for-reading-a-configuration
- [S15] Palo Alto Networks, *Device > Admin Roles* (PAN-OS 11.1 web interface help). https://docs.paloaltonetworks.com/ngfw/help/11-1/device/device-admin-roles
- [S16] Palo Alto Networks, *Panorama > Admin Roles* (XML API privilege definitions, PAN-OS 11.1). https://docs.paloaltonetworks.com/ngfw/help/11-1/panorama-web-interface/panorama-admin-roles
- [S17] Palo Alto Networks, *LLDP* overview (supported interface types). https://docs.paloaltonetworks.com/content/techdocs/en_US/ngfw/networking/networking/lldp.html, and *Use SNMP Network Discovery to Learn about Devices from Switches* (CDP via SNMP only). https://docs.paloaltonetworks.com/iot/iot-security-admin/get-started-with-iot-security/firewall-deployment-for-dhcp-visibility/use-snmp-network-discovery-to-learn-about-devices-from-switches
- [S18] Palo Alto Networks, *Configure LLDP* (PAN-OS 10.2) and *View LLDP Settings and Status* (PAN-OS 11.1). https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-networking-admin/lldp/configure-lldp and https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/lldp/view-lldp-settings-and-status
- [S19] Cisco DevNet, *Working with NX-API CLI* (sandbox and message types). https://developer.cisco.com/docs/nx-os/working-with-nx-api-cli/
- [S20] Palo Alto Networks, *Use the CLI to Find XML API Syntax* / *Explore the XML API*. https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/explore-the-api
- [S21] Palo Alto Networks, *Configure Virtual Routers* (supported protocols) and *Enable Advanced Routing*. https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/virtual-routers and https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/advanced-routing/logical-router-overview
- [S22] Palo Alto Networks, *CLI Cheat Sheet: Networking*. https://docs.paloaltonetworks.com/content/techdocs/en_US/pan-os/10-1/pan-os-cli-quick-start/cli-cheat-sheets/cli-cheat-sheet-networking.html. [S22b] *CLI Cheat Sheet: HA*. https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-cheat-sheet-ha
