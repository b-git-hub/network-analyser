# Identifying the Platform on first login

Research for [#3](https://github.com/b-git-hub/network-analyser/issues/3), part of the planning map [#1](https://github.com/b-git-hub/network-analyser/issues/1). It feeds the discovery and crawl decision [#10](https://github.com/b-git-hub/network-analyser/issues/10).
Researched 2026-11-17. Terms follow [GLOSSARY.md](../GLOSSARY.md). Bracketed numbers such as [S1] refer to the [Sources](#sources) list at the end.

## Question

When the tool first reaches a device in the Scope, how can it reliably tell IOS/IOS-XE from NX-OS from PAN-OS, and recognise an unsupported Platform, before it sends any platform-specific command? Which methods are read-only and least likely to trip security alerting?

## Short answer

Identify the Platform **inside the one SSH session that will also do the work**, and use evidence in three tiers, each costing more than the last:

1. **Before authentication (no credentials sent):** read the SSH identification string. `SSH-2.0-Cisco-1.25` means a Cisco classic-IOS-family SSH server (IOS, IOS-XE, and also ASA and other Cisco products). `SSH-2.0-OpenSSH_*` is what NX-OS and PAN-OS present, and so do Linux hosts. This is a **hint only**. It never decides the Platform alone. [S1][S2][S3]
2. **After login, before sending anything:** read the initial buffer and the prompt. A PAN-OS operational prompt is `username@hostname>` [S4]. A Cisco IOS prompt cannot contain `@`, because IOS hostnames allow only letters, digits and hyphens [S5]. This tells PAN-OS from Cisco without sending a command.
3. **One confirming read-only command, chosen by the tier-2 result:**
   - Cisco candidate: `terminal length 0`, then `show version`. The first line names the OS: `Cisco IOS Software…` or `Cisco IOS XE Software…` (IOS/IOS-XE), or `Cisco Nexus Operating System (NX-OS) Software` (NX-OS) [S6][S7].
   - PAN-OS candidate: `set cli pager off`, then `show system info`. The `model: PA-…` and `family:` fields confirm a PAN-OS firewall [S8][S6].
   - If nothing matches, the device is unsupported (ASA, IOS-XR, WLC, Panorama, Linux and so on). Disconnect without sending anything else.

**Do not** use Netmiko's `SSHDetect` as it stands. It sends up to 16 different commands blind, including Linux and other vendors' commands. It sends three invalid commands to a PAN-OS device before the right one. It then disconnects, so the real collection needs a **second login** [S6]. Netmiko's `redispatch()` can instead turn an already-open session into the right driver once the Platform is known, so the device sees one login [S9].

**Do not** identify the Platform over HTTPS first. NX-API is off until an administrator enables `feature nxapi` [S10]. Every useful PAN-OS XML API call needs authentication [S11][S12]. Unauthenticated probing of web UIs is the kind of traffic that security monitoring flags, and the Cisco IOS-XE web UI is a surface Cisco tells customers to disable [S13]. Use the HTTPS APIs only after SSH has identified the Platform, as a collection channel.

## Recommended identification sequence

```
TCP connect to port 22 (only for IPs inside the Scope)
 ├─ read SSH identification string (pre-auth)            -> hint: "cisco-classic" | "openssh" | "other"
 ├─ verify host key (policy in #7), authenticate once with a Credential Set
 ├─ read initial buffer + prompt, send nothing           -> PAN-OS if prompt matches  ^[^@\s]+@[^>\s]+>$
 │                                                       -> Cisco-like if prompt ends in '>' or '#' with no '@'
 ├─ Cisco-like:  "terminal length 0", "terminal width 511", "show version"
 │     first lines contain "Cisco Nexus Operating System"           -> NX-OS
 │     contain "Cisco IOS XE Software" or "IOS-XE Software"         -> IOS/IOS-XE
 │     contain "Cisco IOS Software" (no XR, no ASA strings)         -> IOS/IOS-XE
 │     anything else (e.g. "Cisco Adaptive Security Appliance",
 │       "Cisco IOS XR")                                            -> unsupported
 ├─ PAN-OS-like: "set cli pager off", "show system info"
 │     "model: PA-…" (any family)                                   -> PAN-OS
 │     model is Panorama / M-series, or no match                    -> unsupported (Panorama is out of scope)
 └─ hand the same session to the Platform driver (Netmiko redispatch) and continue the Backup
```

The hint from step 1 changes only the order of tier 3. For example, if the identification string says `Cisco-1.25` but the prompt is `user@host>`, believe the prompt. When tier 2 is ambiguous (for example the prompt never appears, or a login banner confuses the read), fall back to sending `show version` first. A PAN-OS device rejects it as invalid syntax, and the tool then tries `show system info`. That costs one invalid command and nothing else.

## Evidence per method

| Method | What it reveals | Reliability | Read-only? | Alert footprint |
|---|---|---|---|---|
| SSH identification string | `SSH-2.0-Cisco-1.25` on IOS/IOS-XE [S1]. Nmap's database records the same for Cisco IOS generally [S2], and Cisco WLC uses `CISCO_WLC` [S2][S6]. NX-OS appears as `OpenSSH_x FIPS` [S2]. PAN-OS reports OpenSSH (community report only) [S3] | Hint only. Not unique: ASA and other Cisco products share `Cisco-1.25`, and NX-OS, PAN-OS and Linux all show OpenSSH | Yes. The server sends it before any authentication (RFC 4253 §4.2 [S14]) | Lowest. No credentials sent. Some devices log a connection closed before authentication |
| SSH pre-auth banner (`SSH_MSG_USERAUTH_BANNER`, RFC 4252 §5.4 [S15]; Paramiko `Transport.get_banner()` [S16]) | Operator-written legal text | Unreliable: free text. A PAN-OS banner can say "Cisco" | Yes | None beyond the session |
| Initial buffer and prompt after login | PAN-OS: `username@hostname>` in operational mode, `#` in configure mode [S4]. IOS: `host>` or `host#`, and the hostname cannot contain `@` [S5]. NX-OS: `host#`. NX-OS usually prints its copyright header at login (to verify on test devices) | Good for PAN-OS versus Cisco. Weak for IOS versus NX-OS | Yes. Nothing is sent | One successful login, which any method needs anyway |
| `show version` | First line names the OS (see [Signatures](#signatures-that-decide-the-platform)) | Definitive for the Cisco Platforms | Yes. EXEC show command. Works at user EXEC (`>`) on IOS | Logged by command accounting where it is enabled. Invalid on PAN-OS |
| `show system info` | `model`, `family`, `sw-version`, `multi-vsys`, `operational-mode` [S8] | Definitive for PAN-OS | Yes. Operational-mode show command [S8] | Invalid on Cisco: IOS answers `% Invalid input detected` |
| PAN-OS XML API `type=version` | `sw-version`, `model`, `serial`, `multi-vsys` [S12] | Definitive, but needs authentication | Read-only call, but see the keygen warning below | An authentication event per API key or session |
| NX-API `cli_show` `show version` at `/ins` | JSON `chassis_id`, `host_name`, `kickstart_ver_str` and others [S17] | Definitive if enabled. **Off by default** [S10] | `cli_show` is read-only. `cli_conf` and `bash` types also exist, so the client must lock the type [S18] | Basic authentication on every call or the `nxapi_auth` cookie (600 s, not configurable) [S19] |
| Unauthenticated HTTPS fingerprint (for example a `PanWeb Server` header or a redirect to `/php/login.php` on PAN-OS [S2]) | Vendor hint | Weak. Depends on what the management profile exposes | Yes | **High.** Looks like web reconnaissance. Avoid |
| CDP/LLDP advertisement from a Visited Device (Neighbours only) | CDP `version` text such as `Cisco Nexus Operating System (NX-OS) Software, Version 9.2(2)` and `platform_id` [S20]. LLDP System Description carries similar text [S21] | Good hint **before** logging into a Neighbour. Not available for Seeds | Yes. Read on the device already visited | None on the Neighbour |

### Signatures that decide the Platform

Taken from Netmiko's detection table [S6] and cross-checked against the public test fixtures of `ntc-templates` [S7]. All the examples are vendor or lab output, not real network data.

| Platform | Command | Match (case-insensitive) | Notes |
|---|---|---|---|
| IOS/IOS-XE | `show version` | `Cisco IOS XE Software` **or** `IOS-XE Software` **or** `Cisco IOS Software` | IOS-XE 16.x and 17.x print `Cisco IOS XE Software, Version …` and then `Cisco IOS Software [Fuji], …` [S7]. **Older IOS-XE 3.x/15.x prints only `Cisco IOS Software, IOS-XE Software …`** [S7]. Netmiko's `cisco_xe` pattern misses that form and falls back to `cisco_ios` (priority 95) [S6]. Because the glossary treats IOS/IOS-XE as one Platform, this does not matter unless a later ticket needs to tell them apart |
| NX-OS | `show version` | `Cisco Nexus Operating System` or `NX-OS` [S6] | Fixtures open with `Cisco Nexus Operating System (NX-OS) Software` / `TAC support: …` [S7] |
| PAN-OS | `show system info` | `model:\s+PA` [S6] | Fixture shows `family: vm`, `model: PA-VM` [S7]. A Panorama answers the same command with a non-`PA` model, so the pattern excludes it, which is correct (Panorama is out of scope) |
| Reject list | `show version` | `Cisco Adaptive Security Appliance`, `Cisco IOS XR` [S6] | Check these **before** the IOS match. Otherwise a looser `Cisco IOS` regex accepts IOS-XR |

Netmiko treats any of these strings in the output as an error, not a match: `% Invalid input detected`, `%Error`, `Error: Unrecognized command`, `syntax error, expecting`, `command not found` [S6]. Reuse that list so that an error echo is never mistaken for a match.

## How Netmiko's SSHDetect works (and why not to use it as is)

From `netmiko/ssh_autodetect.py` on the `develop` branch, as of the 2026-10-28 commit; the latest release is v4.8.0 [S6]:

- It connects with the `terminal_server` driver, whose `session_preparation` does nothing: "paging is not disabled" [S22]. It sleeps 3 s and keeps the initial buffer.
- `SSH_MAPPER_DICT` maps about 60 device types to `{cmd, search_patterns, priority, dispatch}`. Commands are sent in order of how many types share them, so `show version` goes first (26 types). The 16 distinct commands, in order, are: `show version`, `display version`, `show system`, `show system info`, `uname -a`, `software show`, `show hardware`, `show system status`, `show system package-info`, `get system status`, `show copyright`, `show inventory`, `admin version`, `cat /etc/issue`, `show sys version`, `show version brief`. These commands are read-only in intent, but most are invalid on most devices.
- Each command waits about 1 s and then reads until 6 s of silence (`read_channel_timing(last_read=6.0)`). Detecting PAN-OS therefore takes several invalid commands and roughly half a minute.
- It stops at the first match with priority 99. `cisco_ios` has priority 95, so detection continues and lets `cisco_xe` (99) win when the string is present.
- Some types use `_autodetect_remote_version`, which matches the SSH identification string from `transport.remote_version` (for example `CISCO_WLC`). This proves the identification string is a usable signal for some platforms.
- **It disconnects** after detection, and the documented usage opens a new `ConnectHandler`. That is two logins per device.
- The docstring warns: "The command output must not require paging." IOS `show version` usually runs past 24 lines and stops at `--More--`. Detection still works because the deciding line comes first, but the session is left at a pager prompt.

What to take from it: the **match table**, the **invalid-response list**, and the idea of matching the SSH identification string. What to leave: the blind command sweep, the paging behaviour and the reconnect. Netmiko's `redispatch(obj, device_type)` changes an open connection's class and runs the correct `session_preparation` [S9]. That makes one login per device possible with Netmiko.

## Pager and terminal handling per Platform

| Platform | Commands (in Netmiko's order) | Scope of the change | Source |
|---|---|---|---|
| IOS/IOS-XE | `terminal width 511`, `terminal length 0` | EXEC command for the current session only. `0` means no pausing. The line-configuration `length` command is the persistent form and **must not** be used | Netmiko `cisco_ios.py` [S23]. Cisco command references and community knowledge base [S24] |
| NX-OS | `terminal width 511`, `terminal length 0` | Session (shown by `show terminal`) | Netmiko `cisco_nxos.py` [S25]. Cisco NX-OS tips document [S26] |
| PAN-OS | `set cli scripting-mode on`, `set cli terminal width 500`, `set cli pager off` | Operational-mode CLI settings, not configuration (no commit). Scripting mode disables tab completion and `?` help | Netmiko `paloalto_panos.py` [S27]. PAN-OS "Customize the CLI" [S28] |

Two notes for the read-only allow-list (#4):

- The PAN-OS session commands begin with `set`. The allow-list must list these **exact strings**. A rule such as "`set …` is forbidden" would block them, and a rule such as "`set cli …` is allowed" would be too loose.
- Netmiko's PAN-OS `session_preparation` sends `show system info` itself, to resynchronise with the prompt [S27]. If the tool redispatches into `paloalto_panos`, the identification command and the prep command overlap, and the second run is harmless.

## Unsupported Platforms

Out of scope per the map: ASA/FTD, IOS-XR, Meraki, Panorama and others. They show up as follows:

- **Cisco ASA / FTD:** SSH string `Cisco-1.25` like IOS. `show version` contains `Cisco Adaptive Security Appliance` [S6]. Reject it.
- **IOS-XR:** `show version` contains `Cisco IOS XR` [S6]. Reject it before the generic IOS match.
- **Cisco WLC:** SSH string `CISCO_WLC` [S2][S6]. It can be rejected **before authentication**.
- **Panorama:** `show system info` model is not `PA-*`. Reject it.
- **Linux, other vendors:** OpenSSH string, and the prompt is neither `user@host>` nor Cisco-like. `show version` returns nothing useful. Reject it.

**Glossary tension (flag for #10/#11):** GLOSSARY.md defines an Unvisited Device as one "that was not logged into, because it is outside the Scope, unsupported, or unreachable". For a Seed, the Platform is usually only known **after** login, so an unsupported Seed was in fact logged into. Either the glossary needs a term for a device "logged into but unsupported", or the tool must decide "unsupported" before authenticating. That is possible only from the SSH identification string (WLC) or from a Neighbour's CDP/LLDP advertisement.

## Security alerting and read-only behaviour

- **Authentication is the expensive event.** Lockouts count failed logins: AAA on Cisco, the authentication profile lockout on PAN-OS. Identification inside one session costs exactly one authentication per Credential Set tried. SSHDetect plus a reconnect doubles successful logins. HTTPS keygen adds another.
- **Every command sent may be recorded.** Cisco command accounting (TACACS+/RADIUS) and the NX-OS local accounting log can record commands. Sources disagree on whether NX-OS logs `show` commands by default [S29]. Invalid commands such as `show system info` on Cisco or `uname -a` anywhere look odd in an audit trail. Tiered identification sends **at most one** command that may be invalid on the device.
- **The SSH identification string is free.** It needs no credentials and generates no authentication logs. Netmiko and Paramiko expose it as `transport.remote_version` [S6][S16].
- **Avoid unauthenticated web probes.** Fetching `/`, `/php/login.php` or `/ins` without credentials resembles reconnaissance. On IOS-XE the HTTP server is the surface behind CVE-2023-20198, and Cisco recommends disabling it where it is not needed [S13]. The tool should not assume or encourage it being on.
- **PAN-OS keygen is not side-effect free.** The PAN-OS 9.1 and 10.0 docs say: "If you have an existing key and generate another key for the same user, all existing sessions will end for the user", and that "previous API sessions will be deleted" [S11]. The 11.1 docs instead document **basic authentication** on API calls ("You cannot use basic authentication when you Get Your API Key") and an `X-PAN-KEY` header, and recommend POST for any call that may carry secrets [S12b]. The 10.0 page's example puts the password in a GET query string [S11]. Do not copy it.
- **NX-API types:** `cli_conf` and `bash` sit beside `cli_show` on the same endpoint [S18]. A client that builds requests must hard-code `cli_show` (or `cli_show_ascii`) to stay read-only.

## Facts that affect other tickets

- **#10 Discovery and crawl:** Identification should happen in-session, with one login. Neighbours arrive with a Platform hint from CDP `version` / `platform_id` or the LLDP System Description [S20][S21]. That lets the tool skip logging in to clearly unsupported Neighbours (phones, access points, ASA). Seeds have only the SSH identification string. A TCP 22 probe that reads the identification string doubles as a cheap "is this an SSH device, and is it Cisco classic?" check.
- **#4 Read-only command catalogue:** Add the identification commands and the session-setup commands per Platform to the allow-list as exact strings: `terminal length 0`, `terminal width 511`, `show version`; `set cli scripting-mode on`, `set cli terminal width 500`, `set cli pager off`, `show system info`. Never use the line-configuration `length` command.
- **#2 Libraries:** Netmiko gives detection patterns, Platform drivers and `redispatch()`. `SSHDetect` itself is unsuitable (blind sweep, about 7 s per command, reconnect).
- **#6 / #7 Credential Sets and connection safety:** Prefer SSH for identification. If the PAN-OS XML API is used, prefer basic authentication or the `X-PAN-KEY` header over keygen, because keygen can end the same admin's other sessions on older PAN-OS. Never put credentials in a URL. Any API key is a secret under the same rules as a Credential Set.
- **Glossary:** see the Unvisited Device tension above.

## To verify on test devices (#8)

These points are not confirmed by a primary source. Capture sanitised output on the lab devices:

1. The exact PAN-OS SSH identification string on the PAN-OS versions in scope (community-reported as OpenSSH [S3]).
2. The exact PAN-OS error text for `show version`, and NX-OS's for `show system info`.
3. Whether NX-OS prints its copyright header at every SSH login, which would make tier 2 conclusive for NX-OS.
4. Whether NX-OS read-only roles (`network-operator`) and PAN-OS read-only admins can run every identification and pager command.
5. Whether PAN-OS 11.x/12.x keygen still ends existing sessions, and whether basic authentication works on the minimum PAN-OS version in scope.

## Sources

High-trust primary sources (vendor documentation, library source, RFCs) unless marked otherwise.

- [S1] Cisco, "Configure and Troubleshoot Secure Shell on Cisco Routers and Switches" (doc 4145). The debug output shows `SSH0: sent protocol version id SSH-2.0-Cisco-1.25`. https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-shell-ssh/4145-ssh.html
- [S2] Nmap `nmap-service-probes`, master branch. Match lines for `SSH-…-Cisco-…` (IOS), `OpenSSH_… FIPS` (Cisco NX-OS), `CISCO_WLC`, and Palo Alto PanWeb HTTP fingerprints. Curated observation data, medium trust. https://github.com/nmap/nmap/blob/master/nmap-service-probes
- [S3] Palo Alto LIVEcommunity, "OpenSSH verification and upgrade" (PAN-OS 10.2 reports OpenSSH 8.0). **Community source, low trust.** https://live.paloaltonetworks.com/t5/next-generation-firewall/openssh-verification-and-upgrade/m-p/578427
- [S4] Palo Alto Networks, PAN-OS CLI Quick Start, "Change CLI Modes" (`username@hostname>` / `username@hostname#`). https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start/get-started-with-the-cli/change-cli-modes
- [S5] Cisco IOS command reference, `hostname` (ARPANET rules: letters, digits, hyphens, 63 characters at most). https://www.cisco.com/E-Learning/bulk/public/tac/cim/cib/using_cisco_ios_software/cmdrefs/hostname.htm
- [S6] Netmiko source, `netmiko/ssh_autodetect.py` (`develop`, last changed 2026-10-28; release v4.8.0). https://github.com/ktbyers/netmiko/blob/develop/netmiko/ssh_autodetect.py
- [S7] ntc-templates test fixtures: `tests/cisco_ios/show_version/*.raw`, `tests/cisco_nxos/show_version/*.raw`, `tests/paloalto_panos/show_system_info/*.raw`. https://github.com/networktocode/ntc-templates/tree/master/tests
- [S8] Palo Alto Networks, PAN-OS CLI Quick Start, "View Settings and Statistics" (`show system info` fields and sample prompt `admin@PA-850>`). https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/use-the-cli/view-settings-and-statistics
- [S9] Netmiko source, `netmiko/ssh_dispatcher.py`, `redispatch()`. https://github.com/ktbyers/netmiko/blob/develop/netmiko/ssh_dispatcher.py
- [S10] Cisco DevNet, "Working with NX-API CLI" (`feature nxapi`). Cisco Developer blog "Open NX-OS journey 2": "the API interface is not enabled by default". https://developer.cisco.com/docs/nx-os/working-with-nx-api-cli/ and https://blogs.cisco.com/developer/open-nx-os-journey-2
- [S11] Palo Alto Networks, PAN-OS 10.0 XML API, "Get Your API Key" (keygen, existing sessions end, GET example with credentials in the query). https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key
- [S12] Palo Alto Networks, PAN-OS 10.0 XML API, "Get Version Info (API)" (`type=version` needs a key; returns `sw-version`, `multi-vsys`, `model`, `serial`). https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-panorama-api/pan-os-xml-api-request-types/get-version-info-api
- [S12b] Palo Alto Networks, PAN-OS 11.1 API, "API Authentication and Security" (`X-PAN-KEY` header, basic authentication, POST for sensitive calls). https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-api-authentication
- [S13] Cisco Security Advisory cisco-sa-iosxe-webui-privesc-j22SaA4z (CVE-2023-20198): disable the HTTP Server feature (`no ip http server` / `no ip http secure-server`) where it is not needed. https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z
- [S14] RFC 4253 §4.2, Protocol Version Exchange (`SSH-protoversion-softwareversion`). https://www.rfc-editor.org/rfc/rfc4253#section-4.2
- [S15] RFC 4252 §5.4, Banner Message. https://www.rfc-editor.org/rfc/rfc4252#section-5.4
- [S16] Paramiko source, `paramiko/transport.py` (`remote_version`, `get_banner()`). https://github.com/paramiko/paramiko/blob/main/paramiko/transport.py
- [S17] Cisco DevNet, NX-API CLI reference (Nexus 9000), `show version` (POST to `/ins`, `cli_show`, JSON fields). https://developer.cisco.com/docs/nx-api-cli-reference-for-the-cisco-nexus-9000-series-platform/version-commands
- [S18] Cisco DevNet, "Working with NX-API CLI" (types `cli_show`, `cli_show_ascii`, `cli_conf`, `bash`). https://developer.cisco.com/docs/nx-os/working-with-nx-api-cli/
- [S19] Cisco DevNet, "NX-API CLI Security" (HTTPS, `nxapi_auth` cookie expires after 600 s, not configurable). https://developer.cisco.com/docs/nx-os/nx-api-cli-security
- [S20] Cisco DevNet, NX-API CLI reference (Nexus 9000), CDP commands (`platform_id`, `version` in `show cdp neighbors … detail`). https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/cdp-commands
- [S21] Cisco NCS 1002 configuration guide, LLDP output showing `System Description: Cisco Nexus Operating System (NX-OS) Software …`. https://cisco.com/c/en/us/td/docs/optical/ncs1000/ncs1002-configuration-guide-73x/configuring-controllers.html
- [S22] Netmiko source, `netmiko/terminal_server/terminal_server.py`. https://github.com/ktbyers/netmiko/blob/develop/netmiko/terminal_server/terminal_server.py
- [S23] Netmiko source, `netmiko/cisco/cisco_ios.py` (`session_preparation`) and `netmiko/base_connection.py` (`disable_paging` default `terminal length 0`). https://github.com/ktbyers/netmiko/blob/develop/netmiko/cisco/cisco_ios.py
- [S24] Cisco IOS Configuration Fundamentals Command Reference 12.2, `terminal length` ("for the current session"; `0` turns off pausing). The page timed out during research; the wording comes from the search-index excerpt, and the Cisco community knowledge base article "Output scrolls by and does not stop…" and the Nexus 5000 command reference say the same. Medium trust until re-read. https://www3-realm.cisco.com/en/US/docs/ios/12_2/configfun/command/reference/frf003.html and https://community.cisco.com/t5/networking-knowledge-base/output-scrolls-by-and-does-not-stop-when-quot-show-quot-commands/ta-p/3112194
- [S25] Netmiko source, `netmiko/cisco/cisco_nxos.py` (`session_preparation`). https://github.com/ktbyers/netmiko/blob/develop/netmiko/cisco/cisco_nxos.py
- [S26] Cisco, "Nexus NX-OS tips and tricks" (doc 200714; `terminal width`, `show terminal`). https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/nx-os-software/200714-Nexus-NX-OS-tips-and-tricks.html
- [S27] Netmiko source, `netmiko/paloalto/paloalto_panos.py` (`session_preparation`). https://github.com/ktbyers/netmiko/blob/develop/netmiko/paloalto/paloalto_panos.py
- [S28] Palo Alto Networks, PAN-OS CLI Quick Start, "Customize the CLI" (`set cli scripting-mode`, operational-mode `set cli` commands). https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start/get-started-with-the-cli/customize-the-cli
- [S29] Cisco community threads on the NX-OS local accounting log (they disagree on whether `show` commands are logged). **Community source, low trust.** https://community.cisco.com/t5/network-management/log-configuration-changes-to-syslog-on-nexus-7000/td-p/2509022
