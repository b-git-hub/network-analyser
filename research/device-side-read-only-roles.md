# Device-side read-only roles per Platform (fact-finding)

Research for [issue #14, Device-side read-only roles per Platform](https://github.com/b-git-hub/network-analyser/issues/14). It builds on [Read-only command catalogue per Platform](https://github.com/b-git-hub/network-analyser/issues/4) (branch `research/read-only-command-catalogue`, file `research/read-only-command-catalogue.md`) and does not repeat it.

**Scope.** v1 covers IOS/IOS-XE (Catalyst) and NX-OS (Nexus), over SSH only, through Netmiko/Paramiko. A Credential Set is one username and one password. The tool never sends `enable`, so the account must land at its working privilege at login ([issue #6](https://github.com/b-git-hub/network-analyser/issues/6)). The tool sends only commands from a compiled-in, read-only allow-list.

Terms follow [GLOSSARY.md](../GLOSSARY.md): Platform, Run, Credential Set, Backup, Backup Passphrase, Topology, Neighbour, Visited Device. "SSH session" below means one SSH connection to one device. It is not a Run.

**How to read the evidence.** Sources are numbered [R1]…[R23] and listed at the end. Text in quotation marks is copied from the source. Cisco Community posts are weak evidence: they are marked **[weak]** and never carry a claim alone. Anything not traced to a Cisco page is marked **(unverified)**. Several Cisco Community pages returned HTTP 403 to this session, so for those only the search-engine summary was seen; this is said where it applies.

---

## 1. Headline answers

1. **IOS-XE `view full` is the documented way to give a lower level the full config.** Cisco's command reference says the keyword is "for view-based users who typically can only view the configuration commands that they are entitled to access for that particular view" [R2]. Cisco's TAC note shows a level-10 user getting the full config, with a clear-text local password in it [R1]. Cisco documents the subset rule, so moving `show running-config view full` to level N also moves `show running-config` and `show` to level N [R5]. That can **raise** `show` for level-1 users, not only lower it. Byte-for-byte equality with priv-15 output is **not documented**.
2. **`file privilege N` is poorly documented.** Cisco says only that it is needed "From 16.X version, depending on the platform" [R1]. The command reference says users at or above the level "can access the files under the file system" [R4]. Cisco does not say which file commands this opens. A US DoD STIG treats any value other than 15 as a finding [R23]. Whether it lets a level-N user `delete`, `copy` or `format` is **(unverified)**.
3. **CLI views (parser views) can hold `show running-config view full`.** Plain `show running-config` inside a view is filtered to the view's commands [R2]. Views need `aaa new-model`, a root view entered with the "privilege level 15 password", and a `secret` per view [R10][R11]. TACACS+ can place a user in a view with the `cli-view-name` attribute [R10]. Placing a *local* user in a view at SSH login is **(unverified)**.
4. **Cisco publishes no table of default privilege levels per command.** Command references give "Command Modes", and these do not match known behaviour reliably (section 5). Each default level must be checked on a device. Moving every allow-listed command to level N explicitly makes the defaults matter less.
5. **Landing at level N without `enable` is documented for AAA.** Locally: `aaa authorization exec default local` [R6]. With TACACS+: `priv-lvl=N` plus `aaa authorization exec` [R12]. Cisco's hardening guide prefers TACACS+ over RADIUS. It recommends TACACS+ command authorization and accounting, with local fallback [R14]. RADIUS cannot do command authorization [R12].
6. **A partial IOS config still has the header and `end`.** Cisco's sample has "Building configuration...", "Current configuration : 121 bytes" and `end`, but no `hostname` line [R1]. Header and `end` alone cannot prove a full Backup.
7. **NX-OS rule strings "can contain spaces and regular expressions"** [R15][R19]. Cisco's examples use a trailing `*` [R18][R19]. Cisco says nothing about pipes (`| json`) under RBAC. That needs a lab check.
8. **NX-OS roles on one user are unioned.** "If you belong to multiple roles, you can execute a combination of all the commands permitted by these roles" [R15]. `network-operator` adds every `show` command and "Some non-show commands, such as telnet" [R15]. A `read` rule also opens `debug` commands in Cisco's own example [R15].
9. **Cisco does not say whether NX-OS filters `show running-config` for a custom role.** Cisco's own backup-tool role permits it [R17], so it is not network-admin-only on that release. Whether hashes and keys appear is **(unverified)**.
10. **TACACS+ gives NX-OS roles with `shell:roles`** [R16][R18]. **Turning on NX-OS command authorization "disables user role-based authorization control (RBAC), including the default roles"** [R16]. The AAA server's command set then becomes the only device-side fence.
11. **Self-checks inside the SSH session.** IOS: `show privilege` prints "Current privilege level is N" [R1][R12]. NX-OS: `show user-account <name>` returns the roles [R20], and `show role` "Displays the user role configuration" [R15]. The role each of these needs is **(unverified)**.

---

## 2. Q1: IOS/IOS-XE `privilege exec level N show running-config view full`

**What it changes.**
- Below level 15, `show running-config` "displays all of the commands that the user is able to modify at their current privilege level" [R1].
- Cisco offers "another version of the traditional show run command that bypasses this limitation" [R1]. With `view full`, the user can "view the full show running-config without any omitted commands" [R1].
- Cisco's example configuration [R1] (the sample password is replaced with `<password>` here):
  ```
  username test_user privilege 10 password <password>
  privilege exec level 10 show
  privilege exec level 10 show running-config
  privilege exec level 10 show running-config view full
  alias exec show-running-config show running-config view full
  ```
  The alias is optional. It lets the user type a familiar name.
- Cisco notes the trade-off: "by providing the user access to this version of the command," the original security concern returns [R1].

**Does it also move `show running-config` and `show`?** Yes, by the documented subset rule: "When you set a command to a privilege level, all commands whose syntax is a subset of that command are also set to that level." Cisco's example: "if you set the show ip traffic command to level 15, the show commands and show ip commands are automatically set to privilege level 15 unless you set them individually to different levels" [R5].
- So `privilege exec level N show running-config view full` also sets `show running-config` and `show` to N.
- This can **raise** the level of `show` for level-1 users when N is above 1. Whether that hides `show` commands that still sit at level 1 (for example `show version`) from level-1 users is **(unverified)**. It is an operator-side effect worth a lab check, because it may break other accounts on the device.

**Is the output at level N the same as at priv 15?**
- Cisco's level-10 sample includes `username test_user privilege 10 password 0 <password>` in clear text [R1]. So secrets are not stripped.
- Cisco never says the two outputs are byte-for-byte equal. Lines such as "Current configuration : N bytes" and "! Last configuration change at …" may differ. Type 5/8/9 hashes, type 7 strings and keys are expected to appear, but this is **(unverified)**.

**Which releases have `view full`?**
- Command history: "12.3(8)T | … The view full option was added" [R2].
- It is in the IOS XE 3SE (Catalyst 3850) command reference [R3].
- Cisco's TAC note applies to "IOS XE Cupertino 17.9.1" and says "any Cisco IOS® or Cisco IOS XE device works similar" [R1].
- The Catalyst 9300 17.x command reference pages were too long to read in full here. Presence on every 17.x train is **(unverified)**, though nothing suggests it was removed.

**Does `show running-config view full` work unchanged at priv 15?** It is an option of `show running-config`, whose mode is "Privileged EXEC (#)" [R2]. Cisco does not describe its output at level 15. That it equals plain `show running-config` at priv 15 is **(unverified)**. If true, the tool could always send `view full` and keep one Backup command per Platform.

## 3. Q2: `file privilege N`

**What Cisco documents.**
- Syntax `file privilege level`. "By default the privilege level is set to 15." Mode: global configuration. Introduced in 15.2(2)T [R4].
- Level: "Users with privilege level equal to greater than the file privilege level can access the files under the file system" [R4]. There are no usage guidelines.
- When it is needed: "From 16.X version, depending on the platform, it is also required to add permissions to the files using the command (config)#file privilege <level>" [R1]. **Cisco does not name the platforms or releases.** Which Catalyst 9000 releases need it is **(unverified)**.
  - [weak] A Cisco Community thread (search summary only) reports a Catalyst 9300 user at level 10 getting no output from `show running-config` until a monitoring tool switched to `show running-config view full` [W1]. Another reports `show run view full` at level 5 printing nothing on one router model [W2].

**Can a level-N user then change device state through the file system?**
- Cisco does not list which commands `file privilege` opens. `delete`, `copy`, `format`, `rename`, `mkdir` and `squeeze` each have their own command level. The Fundamentals reference lists `format` and `fsck` as "Privileged EXEC" [R4]. In principle a level-N user still cannot type them unless they are also moved to level N.
- It is **(unverified)** whether `file privilege N` lets some level-N command write to flash or NVRAM indirectly, for example a `show` or `more` variant with a redirect, or `copy running-config <file>` if `copy` sits at a low level. It is also unverified what files a level-N user can then read (logs, crash files, certificates).
- **Security warning (non-Cisco, high-trust):** The DISA STIG for IOS-XE switches says "The default privilege level required for access to the file system is "15"". It treats any other value as "a finding" when persistent logging is enabled. The fix is `file privilege 15` [R23]. Operators under STIG audit cannot use `file privilege N`.

**A full config at level N without `file privilege`:**
- **Priv 15** (no `view full` needed).
- **TACACS+ priv-lvl 15 plus TACACS+ command authorization.** The account is at 15, but the AAA server allows only the allow-list (section 6).
- **A CLI view holding `show running-config view full`.** Whether views on 16.x and later also need `file privilege` is **(unverified)**.
- **NETCONF `get-config`.** The prior research found secrets are masked for low-privilege users on 17.5 and later, so it is not a faithful Backup.

## 4. Q3: Role-Based CLI Access (parser views) on IOS-XE

**What a view grants.** "you have access only to the commands that have been added to that view by the root view user" [R10][R11]. Commands are added with `commands exec include <command>`. `parser view <name> inclusive` "Creates a view including all commands by default" [R10]. Without `inclusive`, a view starts empty.

**Full or filtered config?** Plain `show running-config` in a view is filtered: `view full` exists for "view-based users who typically can only view the configuration commands that they are entitled to access for that particular view" [R2]. A view that includes `show running-config view full` should give the full config. Cisco gives no worked example of that, so it is **(unverified)**.

**Landing in a view at SSH login.**
- TACACS+/RADIUS: authentication uses the attribute "cli-view-name". "AAA authentication associates only one view name to a particular user" [R10].
- Local user: the configuration guides show the `view` keyword only in the lawful-intercept form, "username lawful-intercept [name] [privilege privilege-level | view view-name] password password" [R10]. The IOS XE 3SE command reference lists `username [lawful-intercept] name [privilege privilege-level | view view-name] …` (seen as a search summary only). `username X view V secret …` for an ordinary view, and landing in it at SSH login, is **(unverified)**.
  - [weak] A Cisco Community answer says the view is applied only with `aaa authorization exec default local` [W4].

**Prerequisites.**
- "Your image must support CLI views" [R10].
- "Enable AAA using the aaa new-model command" before creating a view [R10][R11].
- The system "must be in root view", entered with `enable view`. Cisco says "Enter your privilege level 15 password (for example, root password) if prompted" [R10]. So the device needs an enable secret or password. The tool never uses it, but the operator does once, to build the view.
- Each view needs a `secret` before commands can be added, or the device says "%Password not set for view <viewname>" [R10][R11].
- At most 15 views and superviews, root view not counted [R10].
- Restriction: "the 'no' or 'default' commands in combination with any configuration commands are not saved" to startup-config in views. They are lost on reload [R10].

**Risks of turning on `aaa new-model` on a device without it.**
- It is the gate for every other AAA command. "you must first enable AAA with the aaa new-model command" [R7].
- It is hard to back out. "We do not recommend removing the aaa new-model command. This command is required for dot1x." After removing it with `login local` on the VTYs, a reload is needed to return to default behaviour [R8].
- Once on, login and exec authorization come from method lists, not line settings. If no method list exists, behaviour falls back to a default. That default and its effect on live VTY and console logins is **(unverified)** here. It is the classic lockout risk. Cisco's TLS TACACS+ note advises: "It is recommended to configure a temporary user" to avoid lock-out during AAA changes [R22].
- Cisco's hardening guide recommends AAA anyway, with local fallback (section 6) [R14]. On most managed networks it is already on.

## 5. Q4: Default privilege levels on IOS-XE (Catalyst 9000, 17.x)

**What Cisco documents.**
- The defaults are "user EXEC (Level 1) and privileged EXEC (Level 15)" [R5].
- Level 0 holds five commands: "disable, enable, exit, help, and logout" [R1][R8].
- Cisco publishes **no per-command table of default levels**. Command references list "Command Modes" instead. User EXEC (`>`) roughly means level 1, and privileged EXEC only (`#`) means level 15.
- The Command Modes lines are **not reliable** for this. The 17.15 Catalyst 9300 reference lists `show interfaces`, `show interfaces switchport` and `show inventory` as "Privileged EXEC (#)" only [R9]. `show interfaces` is widely reported to work at user EXEC **(unverified)**. Third-party copies of Cisco references disagree on `show cdp neighbors`.

| Command | What Cisco documents | Status |
|---|---|---|
| `terminal length 0`, `terminal width 511` | Session-only settings. No Cisco 17.x mode line was read. | **(unverified)**, widely level 1 |
| `show version` | "use the show version command in user EXEC, privileged EXEC, or diagnostic mode" [R2] | level 1 (documented) |
| `show inventory` | "Privileged EXEC (#)" [R9] | **(unverified)** level |
| `show privilege` | Listed as "Displays the privilege level configuration" [R5]. No mode line. | **(unverified)**, widely level 1 |
| `show interfaces`, `show interfaces switchport` | "Privileged EXEC (#)" [R9] | **(unverified)** level; doc likely incomplete |
| `show cdp neighbors detail`, `show lldp neighbors detail`, `show mac address-table`, `show ip arp` (+ `vrf`), `show vrf`, `show interfaces status`, `show interfaces trunk`, `show etherchannel summary`, `show vlan brief`, `show ip interface`, `show ip ospf neighbor`, `show ip eigrp neighbors`, `show bgp all summary`, `show ip route static` (+ `vrf`), `show standby`, `show vrrp`, `show glbp`, `show switch`, `show redundancy` | No Command Modes line was read for these on a 17.x Catalyst reference. | **(unverified)** |
| `show running-config` | "Privileged EXEC (#)" [R2]. Output is filtered below 15 [R1]. | level 15 for full output (documented) |

**How to check on a device.**
1. Log in with a test user at level 1, then at level N. Run each command. A command above your level fails with `% Invalid input detected at '^' marker.` ([weak] [W3]; see section 7).
2. At each level, `?` lists the commands that level can reach.
3. `show running-config | include ^privilege` shows only *non-default* level assignments, so it cannot show defaults.
4. Hidden parser-dump commands may list levels. They are unsupported, so do not rely on them **(unverified)**.

The prior research recommends moving every allow-listed command explicitly to level N. Then the defaults matter only for the subset-rule side effects in section 2.

## 6. Q5: Landing at level N on SSH login with no `enable`, and TACACS+

**Local user, no AAA.** Cisco's `username … privilege level` sets "the privilege level the user has after gaining access" [R5]. The line uses `login local`. That the user lands at that level on VTY login without `aaa new-model` is the widely reported behaviour, but the Cisco page read here does not spell out the line side **(unverified)**.

**Local user with AAA.** Cisco's Catalyst 9300 task [R6]:
```
aaa new-model
aaa authentication login default local
aaa authorization exec default local
username <name> privilege <N> secret <...>
```
`aaa authorization exec default local` "Configures user AAA authorization, check the local database, and allow the user to run an EXEC shell" [R6]. [weak] Community threads report that without exec authorization a local user lands at the line's level (usually 1) [W4]. Cisco's hardening guide recommends type 9 secrets: `username <username> privilege 15 algorithm-type scrypt secret <secret>` [R14].

**TACACS+.**
- The server returns `priv-lvl` in the shell (exec) service, for example "priv-lvl = 7". The device needs `aaa new-model` and "aaa authorization exec default group tacacs+|radius local". The user then sees "Current privilege level is 7." [R12].
- RADIUS can do the same with `shell:priv-lvl=7`, but "The RADIUS protocol does not support command authorization" [R12].
- On ISE, the shell profile sets Default Privilege (Cisco's example uses 15) [R13].

**Command authorization and the allow-list.**
- `aaa authorization commands <level>` "Runs authorization for all commands at the specified privilege level" [R8]. Each command at a level that has command authorization configured is sent to the AAA server before it runs. Commands at other levels are not checked **(inference from [R8])**.
- "If you configure AAA authorization for a privilege level greater than 0, these five commands will not be included in the privilege level command set" [R8].
- An ISE command set lists permitted commands. "By default if Arguments is left blank, all arguments are … included". A denied command prints "Command authorization failed." [R13]. How arguments are matched (regex, wildcards) was not found on a Cisco page **(unverified)**.
- Interaction: the tool's compiled-in allow-list and the server's command set are **two independent fences**. A command must pass both. So the ISE command set must list every allow-listed command, including `terminal length 0` and `terminal width 511` if they sit at a level with command authorization.
- Fallback caveat: Cisco's own hardening example uses `aaa authorization commands 15 default group tacacs none` [R14]. With `none`, or with `local` for a level-15 local user, a TACACS+ outage removes the command fence. If the account sits at 15, only the tool's allow-list is left.

**Cisco best practice for device admin AAA** [R14]:
- "use TACACS+ instead of RADIUS when TACACS+ is supported by the AAA server". TACACS+ encrypts the whole payload, while RADIUS "only encrypts the password".
- Fallback: "Typical configurations include the use of local or enable authentication if all configured TACACS+ servers are unavailable."
- Command authorization: "Use AAA (TACACS+) for command authorization."
- Command accounting: `aaa accounting commands <level> default start-stop group tacacs`. "Command accounting is not supported with RADIUS."
- Redundant AAA servers, so that "interactive management access, such as SSH, is possible if an AAA server is unavailable."
- "Configure the password retry lockout." "Type 7 passwords are not a secure form of password storage."

## 7. Q6: Telling from inside the SSH session that the config is partial

**What a partial config looks like.** Cisco's level-10 sample, without `view full`, is complete [R1]:
```
Building configuration...

Current configuration : 121 bytes
!
! Last configuration change at 21:10:08 UTC Mon Aug 28 2017
!
boot-start-marker
boot-end-marker
!
!
!
end
```
- The header and `end` are present. `hostname`, `version`, `interface` and `username` lines are missing.
- So "has header and `end`" does not prove a full config. Checks that would catch this sample: a `hostname` line, at least one `interface` line, and a `version` line. These are heuristics from one Cisco sample. Whether some configs legitimately lack one of them is **(unverified)**.
- Whether the "Current configuration : N bytes" number matches the full config or only the shown part is **(unverified)**. In Cisco's sample it is 121 bytes, which fits the shown part only.

**Error text.**
| Situation | Text | Evidence |
|---|---|---|
| Command above the user's privilege level | `% Invalid input detected at '^' marker.` | [weak] [W3] and third-party guides; **(unverified)** on a Cisco page |
| TACACS+ command authorization denies it | `Command authorization failed.` | [R13] |
| Command not in the user's CLI view | Not documented; likely the same as the first row | **(unverified)** |
| `view full` allowed but `file privilege` missing (16.x and later) | Empty output reported | [weak] [W1][W2]; **(unverified)** |

**Is `show privilege` always available at level 1?** Cisco shows it used by non-15 users ("Current privilege level is 10" [R1], "Current privilege level is 7." [R12]). That it sits at level 1 by default is **(unverified)**. It can be moved like any command, so the role should move it to level N explicitly.

## 8. Q7: NX-OS RBAC `rule N permit command <cmd>` matching

**What Cisco documents.**
- A rule is a "command or group of commands defined in a regular expression" [R15].
- "The command-string argument can contain spaces and regular expressions. For example, "interface ethernet *" includes all Ethernet interfaces" [R19].
- Evaluation: "Rules are applied in descending order." "When processing an RBACL for a match, a partial match does not stop the evaluation process. Evaluation continues through each rule until an exact match is found. If no exact match is found, the most precise rule in the list will be chosen for the result." If permit and deny have the same match logic, the higher-numbered rule wins [R15].
- Cisco's TAC examples use a trailing `*` for arguments: `rule 3 permit command ssh *`, `rule 5 permit command ping *` [R18]. They chain config modes with `;`: `rule 11 permit command config t ; interface * ; shutdown` [R18].

**Not documented (all (unverified)):**
- Whether `permit command show version` also permits `show version | json`. Cisco's RBAC and TACACS+ pages say nothing about pipes or output filters. The NX-API guide says "Each command is only executable with the current user's authority" (prior research S10), which does not settle it.
- Whether `permit command show ip arp` also permits `show ip arp vrf all`, or whether `show ip arp *` or `show ip arp vrf all` must be written. The "partial match … most precise rule" wording suggests prefix rules can match longer commands, but that is an inference.

**`terminal width`.** Netmiko's NX-OS driver sends `terminal width 511` and then `terminal length 0` at connect [R21]. So does its IOS driver. Cisco's Oxidized role permits only `terminal length 0`. Without it, the user gets "% Permission denied for the role" [R17]. If the tool keeps Netmiko's default session setup, the role must permit `terminal width 511` too, or the tool must override it **(inference)**. Whether NX-OS lets every role run `terminal width` is **(unverified)**.

## 9. Q8: Several NX-OS roles on one user; what `network-operator` adds; `read` rules

**Several roles.** Yes. "each user can have multiple roles." "If you belong to multiple roles, you can execute a combination of all the commands permitted by these roles." "Access to a command takes priority over being denied access to a command" [R15][R19]. "A maximum of 64 user roles can be assigned to a single user account" [R15]. So `network-operator` plus a tiny role permitting `show running-config` and `terminal length 0` is a supported pattern.

**What `network-operator` adds over a custom role that lists the allow-list.**
- "Complete read access to the entire Cisco NX-OS device" [R15], minus `show running-config` and `show startup-config` [R15].
- "Some non-show commands, such as telnet, may be available for this user role" [R15]. Outbound `telnet`, and possibly `ssh`, `ping` and `traceroute`, let a stolen account reach further into the network. The exact list is **(unverified)**; `show cli syntax roles network-operator` prints it [R15].
- "Some show commands may be hidden from network-operator users" [R15]. Which ones is **(unverified)**.

**Does a custom role start empty?**
- Cisco says: "By default, the user accounts without an administrator role can access only the show, exit, end, and configure terminal commands. You can add rules to allow users to configure features" [R15]. And "The configure terminal command is always permitted and not affected by role configuration rules" [R15].
- It is unclear whether "show" here means every `show` command or only the bare keyword. Cisco's own backup role adds explicit rules for `show version`, `show inventory` and `show running-config` [R17]. That suggests a new role does **not** get all `show` commands, but this is **(unverified)**.
- Either way, `configure terminal` is always reachable. Config commands still need permission. The tool's allow-list is the only thing stopping it being sent.

**`rule permit read` and `rule permit read feature X`.**
- `read` is "a read-only … rule for all operations". `read feature X` is a read-only rule "for a feature" [R19].
- Cisco's example: `rule 3 permit read feature eigrp` "allows you to enable the exec-level show and debug eigrp commands" [R15]. **So a `read` rule opens `debug` commands as well as `show`.** `debug` is not a configuration change, but it can load the CPU and change logging. It is outside a strict read-only allow-list.
- Whether `permit read` includes `show running-config` is **(unverified)**. `network-operator` has "Complete read access" yet is denied `show running-config` [R15]. That suggests `read` alone does not include it.
  - [weak] A community report says a Nexus 9000 `vdc-operator` user could not run `show running-config`, though the same role could on a Nexus 5000 (search summary only) [W5].

## 10. Q9: NX-OS `show running-config` under a custom role

- **Full or filtered?** Cisco does not say. The guides say only that `network-operator` lacks access [R15]. Whether a custom role sees every section, including `username … password 5 …` hashes, SNMP communities and keys, is **(unverified)**. This is the most important NX-OS lab check.
- **Network-admin-only commands.** "Regardless of the read-write rule configured for a user role, some commands can be executed only by using the predefined network-admin role" [R15]. Cisco does not list them. For RANCID's command list, Cisco says only that "Some of the commands in this list can be executed only by user accounts that hold the network-admin user role" [R17].
  - RANCID's list includes `show running-config`, `show version`, `show inventory`, `show module`, `show vlan` and `dir` commands [R17]. Cisco's Oxidized role with `show running-config` works on NX-OS 7.0(3)I7(1) and later [R17]. So `show running-config` itself is not network-admin-only on that release.
  - None of the catalogue's NX-OS commands is named as network-admin-only in any Cisco page read. That none is so is **(unverified)**. `show cli syntax roles network-admin` and `show cli syntax roles network-operator` "Displays the syntax of the commands that the … role can use" [R15], so the two can be compared on a device.

## 11. Q10: TACACS+ / ISE role assignment and command authorization on NX-OS

- **Roles from TACACS+.** The Cisco VSA is `shell:roles`, a space-separated list, for example `shell:roles=network-operator network-admin` (mandatory) or `shell:roles*network-operator network-admin` (optional). "the separator is = (equal sign) for mandatory attributes, and * (asterisk) indicates optional attributes" [R16]. Cisco's ISE example returns `shell:roles="helpdesk"` [R18]. The role must already exist on the switch [R18].
- If a local account has the same name, "the Cisco NX-OS software applies the user roles from the local account to the remote user" [R16].
- What NX-OS does when the server returns no role or an unknown role is **(unverified)**.
- **Command authorization.** Syntax: `aaa authorization {commands | config-commands} {console | default} {group group-list [local] | local}` [R16]. Test it with `test aaa authorization command-type commands user <name> command <string>` [R16].
  - **"Command authorization disables user role-based authorization control (RBAC), including the default roles"** [R16]. With it on, the ISE command set, not the NX-OS role, decides each command.
  - "By default, command authorization is disabled for console sessions" [R16]. It does apply to SSH.
  - Without a fallback, "authorization fails if all server groups fail to respond" [R16].
- Caution from Cisco's Nexus TAC note: "After you enable TACACS authentication, the Nexus device stops using local authentication" [R18].
- Privilege-level (`priv-lvl`) mapping to `priv-N` roles exists but is off by default ("Privilege level support for TACACS+ authorization … Disabled") [R16]. `priv-14` and `priv-15` cannot be modified [R16]. The prior research says `priv-15` equals network-admin.

## 12. Q11: Reading the effective role from inside the SSH session

**IOS/IOS-XE.**
- `show privilege` prints "Current privilege level is N" [R1][R12]. Its default level is **(unverified)** (section 7).
- In a CLI view, Cisco documents `show parser view`, and says "the all keyword is available only to root users" [R11]. The output that names the current view is **(unverified)**.

**NX-OS.**
- `show user-account <name>` returns the user's roles. NX-API JSON fields include `usr_name` and `role` [R20]. "Displays user account information" [R15].
- `show role` "Displays the user role configuration" [R15]. `show role name <role>` shows one role's rules.
- Which role these need is **(unverified)**. If a custom role starts without all `show` commands, each must be permitted explicitly.
- NX-OS "displays all commands in the context sensitive help and in tab completion, regardless of the role assigned to the user" [R16]. So `?` cannot be used to probe what the role allows.
- `show users` is not described in the RBAC guide. It lists logged-in sessions, not roles **(unverified)**.

---

## 13. Consequences and options for the decision

This section lays out options and trade-offs. It does not decide.

### IOS/IOS-XE: how the account reaches a full Backup

| Option | What the operator configures | Gains | Costs and risks |
|---|---|---|---|
| **A. Priv 15** (local or TACACS+) | `username X privilege 15 algorithm-type scrypt secret …` | Simplest. Full config is certain. No `view full` or `file privilege` questions. | The account can do anything. Only the tool's allow-list keeps it read-only. A stolen password is a full admin. |
| **B. Custom level N** | `privilege exec level N <cmd>` for each allow-listed command, plus `show running-config view full`, plus `file privilege N` where needed | Device enforces the allow-list. No AAA needed if `login local` lands at N (unverified). | Subset rule may raise `show` for other level-1 users. `file privilege N` is a STIG finding [R23], and its exact scope is unknown. Default levels are undocumented, so each line must be tested. |
| **C. CLI view** | `aaa new-model`, root view, `parser view …` with each allow-listed command and `show running-config view full`; user placed by TACACS+ `cli-view-name` (local: unverified) | Exact allow-list on the device. `view full` is documented for views. | Needs `aaa new-model` (lockout risk, hard to undo), an enable secret for the root view, and a `secret` per view. 15-view cap. `file privilege` interplay unknown. |
| **D. TACACS+ priv 15 + command authorization** | ISE shell profile at 15; command set listing the allow-list; `aaa authorization commands 0/1/15 …`; accounting | Full config without `view full` or `file privilege`. Central audit through command accounting. Cisco best practice [R14]. | Needs TACACS+. If fallback is `none` or a level-15 local user, a TACACS+ outage removes the fence. ISE argument matching needs testing. |
| **E. B or C with TACACS+ command authorization on top** | Both | Two device-side fences. | Most work for the operator. |

**Shared points.**
- If `show running-config view full` behaves the same at priv 15 (lab check), the tool could always send it. That gives one Backup command for options A to E.
- The tool needs a rule for a partial config. A header plus `end` is not enough (section 7). Options: require `hostname` and at least one `interface` line; compare against `show privilege`; treat `Command authorization failed.` and `% Invalid input` as "data unknown". The existing ticket text frames this as warn vs fail.
- Whatever the option, the tool can check its level with `show privilege` at the start and report the username and level. Usernames may appear in reports ([issue #6](https://github.com/b-git-hub/network-analyser/issues/6)).

### NX-OS: which role

| Option | Role setup | Gains | Costs and risks |
|---|---|---|---|
| **A. One custom role listing every allow-listed command** | `rule N permit command <cmd>` for each, including `terminal length 0`, `terminal width 511` and `show running-config` | Narrowest. Matches the allow-list. | Pipe and argument matching (`\| json`, `vrf all`) is undocumented and must be lab-tested. Easy to miss a command; a miss leaves data "unknown". |
| **B. `network-operator` + small custom role** | `username X role network-operator` and `role <small>` with `show running-config`, `terminal length 0`, `terminal width 511` | Short role. All `show` commands work, `\| json` included (unverified). | Adds every `show`, hidden-command gaps, and non-show commands such as `telnet` [R15]. |
| **C. Custom role with `rule permit read` + `show running-config`** | One role | Short. | `read` opens `debug` commands too [R15]. Whether it includes `show running-config` is unknown. |
| **D. TACACS+ `shell:roles` for A, B or C** | ISE profile returns the role | Central management. | A same-name local account overrides the roles [R16]. |
| **E. TACACS+ command authorization** | ISE command set listing the allow-list | Central audit and allow-list. | "disables user role-based authorization control (RBAC), including the default roles" [R16]. RBAC no longer applies, so the command set is the only fence. Fallback behaviour matters. |

**Shared points.**
- `network-admin` and `priv-15` are never needed for the catalogue as far as the docs show.
- Netmiko's default session setup (`terminal width 511`, `terminal length 0`) must be in both the tool's allow-list and the device role, or the tool must override it [R21].
- Whether `show running-config` under a custom role is a faithful Backup is still open (section 10).

---

## 14. Open lab checks (DevNet CML sandbox)

Use only synthetic configs. Do not copy sandbox output into the repo unless it is sanitised.

**IOS-XE (Catalyst 9000v / Cat8000v, 17.x)**
1. At priv 15, diff `show running-config` against `show running-config view full`. Are they identical apart from timestamps?
2. Configure level 7 with `privilege exec level 7 show running-config view full` only. Then:
   - check whether `show running-config` and `show` show up at level 7 in `show running-config | include privilege`;
   - check whether a level-1 user can still run `show version`.
3. At level 7, with and without `file privilege 7`: does `show running-config view full` give the full config? Diff it against priv 15. Do type 5/8/9 hashes, type 7 strings, keys and SNMP communities appear?
4. With `file privilege 7`, at level 7, try `dir`, `more flash:<file>`, `copy running-config flash:test`, `delete flash:test`, `rename`, `mkdir`, `squeeze` and `format`. Which work? Use a disposable lab image only.
5. Log in at level 1 and at level 7, and run every allow-listed command. Record each default level and each error text.
6. `username X privilege 7 secret …` with `login local` and no `aaa new-model`: does SSH land at 7 (`show privilege`)?
7. The same with `aaa new-model`: with and without `aaa authorization exec default local`.
8. CLI view: create a view with every allow-listed command plus `show running-config view full`.
   - Does `username X view V secret …` work for a non-lawful-intercept view, and does SSH land in it?
   - Does `show running-config view full` give the full config? Is `file privilege` needed?
   - What does `show parser view` print?
   - What error does a command outside the view give?
9. Netmiko connect at level 7 and in a view. Does `terminal width 511` succeed? What does Netmiko do if it fails?
10. Turn on `aaa new-model` on a device that lacks it. Record what happens to existing VTY and console logins before any method list exists.

**NX-OS (Nexus 9000v, 9.3 and 10.x)**
1. Custom role with `permit command show version` only: does `show version | json` work? What about `| json-pretty`, `| include` and `| no-more`?
2. `permit command show ip arp`: does `show ip arp vrf all` work? Then try `permit command show ip arp *`.
3. A new role with no rules: which `show` commands work? Does `show user-account <self>`, `show role` or `show users` work?
4. Custom role with `show running-config`: diff its output against network-admin. Are `username … password 5`, SNMP, TACACS+ and key lines all present?
5. `network-operator` + small role: confirm the union. List the non-show commands available (`show cli syntax roles network-operator`).
6. `rule permit read` alone: does it allow `show running-config`? Does it allow `debug`?
7. Run every catalogue command with `| json` under the narrow role. Record any that need network-admin.
8. Is `terminal width 511` denied without a rule?
9. TACACS+ (if the sandbox has a server): `shell:roles`, an unknown role, and no role returned. With command authorization on, confirm RBAC is bypassed.

---

## Sources

High-trust Cisco sources:

- [R1] Cisco TAC, *Configure IOS XE to Display Full show running-config for Users with Lower Privilege*, doc 212149 (applies to IOS XE 17.9.1). https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-aggregation-services-routers/212149-Configure-IOS-XE-to-display-full-show-ru.html
- [R2] Cisco, *IOS Configuration Fundamentals Command Reference: show protocols through showmon* (`show running-config`, `view full` row, command history; `show version`). https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_protocols_through_showmon.html
- [R3] Cisco, *Configuration Fundamentals Command Reference, IOS XE Release 3SE (Catalyst 3850): show commands* (`show running-config view full`). https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/xe3se/3850/fundamentals-xe-3se-3850-cr-book/show-commands-xe-3se.html
- [R4] Cisco, *IOS Configuration Fundamentals Command Reference: F through K* (`file privilege`, `format`, `fsck`). https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/F_through_K.html
- [R5] Cisco, *Security Configuration Guide, IOS XE 17.9.x (Catalyst 9300): Controlling Switch Access with Passwords and Privilege Levels* (subset rule, `username … privilege`). https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/sec/b_179_sec_9300_cg/controlling_switch_access_with_passwords_and_privilege_levels.html
- [R6] Cisco, *Security Configuration Guide, IOS XE 17.9.x (Catalyst 9300): Configuring Local Authentication and Authorization*. https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/sec/b_179_sec_9300_cg/configuring_local_authentication_and_authorization.html
- [R7] Cisco, *Security Configuration Guide, IOS XE 17.9.x (Catalyst 9300): Configuring TACACS+*. https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/sec/b_179_sec_9300_cg/configuring_tacacs_.html
- [R8] Cisco, *Command Reference, IOS XE 17.15.x (Catalyst 9300): Security* (`aaa new-model`, `aaa authorization`). https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/security_commands.html
- [R9] Cisco, *Command Reference, IOS XE 17.15.x (Catalyst 9300): Interface and Hardware Commands* (Command Modes of `show interfaces`, `show interfaces switchport`, `show inventory`). https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/interface_and_hardware_commands.html
- [R10] Cisco, *Security and VPN Configuration Guide, IOS XE 17.x: Role-Based CLI Access*. https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-role-base-cli.html
- [R11] Cisco, *User Security Configuration Guide, IOS XE 16: Role-Based CLI Access*. https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16/sec-usr-cfg-xe-16-book/sec-role-base-cli.html
- [R12] Cisco TAC, *How to Assign Privilege Levels with TACACS+ and RADIUS*, doc 13860. https://www.cisco.com/c/en/us/support/docs/security-vpn/remote-authentication-dial-user-service-radius/13860-PRIV.html
- [R13] Cisco TAC, *Configure ISE 2.0 IOS TACACS+ Authentication and Command Authorization*, doc 200208. https://www.cisco.com/c/en/us/support/docs/security/identity-services-engine/200208-Configure-ISE-2-0-IOS-TACACS-Authentic.html
- [R14] Cisco, *Cisco Guide to Harden Cisco IOS Devices*, doc 13608-21. https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html
- [R15] Cisco, *Nexus 9000 NX-OS Security Configuration Guide 10.2(x): Configuring User Accounts and RBAC*. https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/102x/configuration/Security/cisco-nexus-9000-nx-os-security-configuration-guide-102x/m-configuring-user-accounts-and-rbac.html
- [R16] Cisco, *Nexus 9000 NX-OS Security Configuration Guide 10.2(x): Configuring TACACS+*. https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/102x/configuration/Security/cisco-nexus-9000-nx-os-security-configuration-guide-102x/m-configuring-tacacs.html
- [R17] Cisco TAC, *Configure User RBAC for the Oxidized or RANCID Network Configuration Backup Tools*, doc 215024 (NX-OS 7.0(3)I7(1) and later). https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/nx-os-software/215024-configure-user-rbac-for-the-oxidized-or.html
- [R18] Cisco TAC, *Configure Custom TACACS Role for Nexus 9K* (ISE 3.2, NX-OS 9.3(5)), doc 221926. https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/221926-configure-custom-tacacs-role-for-nexus-9.html
- [R19] Cisco, *Nexus 5000 Series NX-OS Software Configuration Guide: Configuring User Accounts and RBAC* (rule matching wording, read rules). https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus5000/sw/configuration/guide/cli/CLIConfigurationGuide/sec_rbac.html
- [R20] Cisco DevNet, *Nexus 9000 NX-API CLI Reference: User Account Commands* (`show user-account`). https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/user-account-commands
- [R22] Cisco TAC, *Configure TACACS+ over TLS 1.3 on an IOS XE Device with ISE*, doc 225097 (temporary-user tip). https://www.cisco.com/c/en/us/support/docs/security-vpn/terminal-access-controller-access-control-system-tacacs-/225097-configure-tacacs-over-tls-1-3-on-an.html

Other primary sources (not Cisco):

- [R21] Netmiko v4.4.0 source: `netmiko/cisco/cisco_nxos_ssh.py` and `netmiko/cisco/cisco_ios.py` (`session_preparation` sends `terminal width 511`), and `netmiko/base_connection.py` (`disable_paging` sends `terminal length 0`). https://github.com/ktbyers/netmiko/tree/v4.4.0/netmiko
- [R23] DISA, *Cisco IOS XE Switch NDM STIG*, finding V-220533 (`file privilege` must stay 15), as rendered by stigviewer.com. https://stigviewer.com/stig/cisco_ios_xe_switch_ndm/2024-06-06/finding/V-220533

Weak supporting evidence (Cisco Community; the pages returned HTTP 403 here, so only search-result summaries were seen):

- [W1] *Catalyst 9300 privilege level for show run*. https://community.cisco.com/t5/network-management/catalyst-9300-privilege-level-for-show-run/m-p/3869582
- [W2] *How to configure non-privilege level 15 users to view the full running configuration?* https://community.cisco.com/t5/network-access-control/how-to-configure-non-privilege-level-15-users-to-view-the-full/m-p/2505353
- [W3] *Why show running-config does not give valid output on a lower privilege level* (knowledge base). https://community.cisco.com/t5/security-knowledge-base/why-show-running-config-does-not-give-valid-output-on-a-lower/ta-p/3154493
- [W4] *About aaa new-model* (local user privilege not applied without exec authorization). https://community.cisco.com/t5/network-access-control/about-aaa-new-model/m-p/2951363 and *RBAC associate user to view confusion*. https://community.cisco.com/t5/network-access-control/rbac-associate-user-to-view-confusion/td-p/1346462
- [W5] *Read-only access on Cisco Nexus NX-OS*. https://community.cisco.com/t5/switching/read-only-access-on-cisco-nexus-nx-os/m-p/3862471
