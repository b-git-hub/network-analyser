# Lab checklist

v1 is tested by hand on a booked DevNet *Cisco Modeling Labs* (CML) sandbox. Every booking starts from the same lab, [`lab/network-analyser-lab.yaml`](../lab/network-analyser-lab.yaml), and records its results here. This page gathers every lab check still open on the decision tickets, then walks through the tool.

Decided on [Get devices to test against](https://github.com/b-git-hub/network-analyser/issues/8) and [Testing against recorded device output](https://github.com/b-git-hub/network-analyser/issues/28). Checks were added by [Device-side read-only roles per Platform](https://github.com/b-git-hub/network-analyser/issues/14), [Expected network size and Run limits](https://github.com/b-git-hub/network-analyser/issues/27) and [Release pipeline, signing and versioning](https://github.com/b-git-hub/network-analyser/issues/32).

Sandbox results confirm protocols and command forms, not every hardware model. CML nodes are virtual, so stacks, vPC and platform-specific `show` output may differ on real kit.

## Rules for every booking

- **The Scope is only the CML management addresses seen through the sandbox VPN.** List the lab nodes' management addresses one by one. Never put in the whole sandbox subnet, which also holds the sandbox's own servers, and never any address from your own network.
- **Nothing captured from the lab is committed** (CLAUDE.md: real device data never goes into the repo). A result is a short conclusion in your own words, such as "pass", "lands in the view" or "needs a trailing `*`". Never paste device output, configs, host keys or fingerprints, serial numbers, sandbox addresses or Run folder files into this page, an issue or a commit. Two kinds of text may be quoted, because the code needs them and they identify no device: an SSH identification string, and a command's syntax.
- **Passwords never leave your password manager.** The sandbox credentials stay on the reservation page. The lab file sets every password to `CHANGE_ME`. You set the real lab passwords by hand at the console after boot. They never go into this page, an issue, a commit, a run file or a copy of the lab file. The tool takes them only at its hidden prompts.
- **One Backup Passphrase per Windows account.** Lab Runs use the same check file as real Runs, so lab Backups are locked with your usual Backup Passphrase. Give lab Runs `--label lab` so they are easy to tell apart.
- **Record every result.** Fill in *Result* and *Date (UTC)*. When a result changes code or a decision, also comment on the ticket named in that section's heading.

## Booking log

Check the sandbox's CML version on every booking. The lab file uses the CML 2.7 lab format (`version: 0.2.2`) and the IOL-L2 node, so it needs CML 2.7 or later. Community reports describe a missing Import button, and imports failing after a sandbox change.

| Date (UTC) | CML version | Node images (IOL-L2, Cat8000v, NX-OS 9000v) | Tool version or commit | Notes |
|---|---|---|---|---|
| | | | | |

## Set up the lab

The lab has five nodes, all IOS-XE or NX-OS:

| Node | CML node type | Platform | Management interface | Placeholder address |
|---|---|---|---|---|
| xe-rtr1 | `cat8000v` (Catalyst 8000V) | IOS-XE | GigabitEthernet1, VRF `Mgmt-intf` | 192.0.2.11 |
| xe-sw1 | `ioll2-xe` (IOL-L2) | IOS-XE | Ethernet0/0, VRF `Mgmt-intf` | 192.0.2.12 |
| xe-sw2 | `ioll2-xe` (IOL-L2) | IOS-XE | Ethernet0/0, VRF `Mgmt-intf` | 192.0.2.13 |
| nx-sw1 | `nxosv9000` (NX-OS 9000v) | NX-OS | mgmt0, VRF `management` | 192.0.2.14 |
| nx-sw2 | `nxosv9000` (NX-OS 9000v) | NX-OS | mgmt0, VRF `management` | 192.0.2.15 |

**Synthetic address ranges.** The lab file uses only the RFC 5737 documentation ranges: 192.0.2.0/24 for management placeholders, and 198.51.100.0/24 and 203.0.113.0/24 for the data plane. Its other IPv4 literals are netmasks and the `0.0.0.0` default route. Any other address in `lab/` is a mistake.

The management gateway placeholder is 192.0.2.1. The management interfaces join an unmanaged switch and the external connector `mgmt-bridge`, with CDP and LLDP turned off on them. The data plane uses 198.51.100.0/24 and 203.0.113.0/24, which never leave the lab:

- **Bundles:** Port-channel1 (LACP trunk, VLANs 10 and 20) between xe-sw1 and xe-sw2, and port-channel1 between nx-sw1 and nx-sw2.
- **VLAN Mismatch, on purpose:** the trunk xe-sw1 Ethernet0/3 ↔ nx-sw1 Ethernet1/3. xe-sw1 allows 10, 20 and 30 with native VLAN 1; nx-sw1 allows 10, 20 and 99 with native VLAN 99.
- **OSPF** area 0, with an HMAC-SHA-256 key chain, on three routed /31 links (xe-rtr1–xe-sw1, xe-rtr1–nx-sw1, xe-sw2–nx-sw2) and on VLAN 10.
- **Shared subnet:** 198.51.100.0/25 on VLAN 10 across all four switches, with HSRP address 198.51.100.1 on the two IOS-XE switches. 198.51.100.128/25 on VLAN 20 is shared by xe-sw2 and nx-sw2 only, with no routing protocol.
- **The tool's account** `netanalyser`, with a provisional Device Role: CLI view `NA-READ` on IOS-XE and custom role `NA-READ` on NX-OS ([ADR 0005](adr/0005-device-roles-cut-exactly-to-the-allow-list.md)). They are written by hand from the spec's command catalogue. Once `network-analyser role-snippet` exists ([#53](https://github.com/b-git-hub/network-analyser/issues/53)), replace them with its output and update the lab file.

Steps:

1. Book the CML sandbox from the DevNet Sandbox catalogue and connect its VPN. Record the CML version in the booking log.
2. Copy the lab file to a folder outside the repo. In the copy, replace `192.0.2.1` and `192.0.2.11` to `192.0.2.15` with the gateway and free addresses from the sandbox's management subnet, as listed on the reservation page. If that subnet is not a /24, also change the masks (`255.255.255.0` on IOS-XE, `/24` on NX-OS). Never commit the copy.
3. In CML, use **Import Lab** with the copy. Check that `mgmt-bridge` is set to the bridge that reaches the sandbox management network (the file says *System Bridge*).
4. Start the lab. NX-OS 9000v takes several minutes to boot. If the sandbox can't start every node, delete xe-rtr1. The lab still has two IOS-XE and two NX-OS nodes, but loses the Catalyst 8000V checks and two OSPF links.
5. At each node's console, log in as `admin` with `CHANGE_ME`. Set new passwords, then bring the management interface up. Management interfaces boot shut down so that nothing answers SSH while a password is still `CHANGE_ME`.

   IOS-XE (the enable secret is `CHANGE_ME` until you change it; `enable view` is needed to edit a view):

   ```
   enable view
   configure terminal
    enable algorithm-type scrypt secret <new enable secret>
    username admin privilege 15 algorithm-type scrypt secret <new admin password>
    username netanalyser view NA-READ algorithm-type scrypt secret <new tool password>
    parser view NA-READ
     secret <new view secret>
     exit
    interface <management interface>
     no shutdown
    end
   ```

   NX-OS (the strength check is on again, so the new passwords must be strong):

   ```
   configure terminal
    username admin password <new admin password>
    username netanalyser password <new tool password>
    interface mgmt0
     no shutdown
    end
   ```

   The OSPF key chain and the HSRP key also hold `CHANGE_ME`. They protect only links inside the lab, which nothing outside the lab can reach. Change them on every node if you wish, using the same value on each end.
6. From the PC, check that each management address answers on TCP 22, for example with `Test-NetConnection <address> -Port 22`.
7. **Host keys are new on every booking.** The lab is rebuilt, so a sandbox address that is already in your Trust Store now offers a different key, and the Run records it as `host key changed`. Read each node's fingerprint at its console (check A8), then accept it with `network-analyser trust-key <address> --fingerprint SHA256:…`.
8. Check that the lab came up as designed:

| ID | Check | Result | Date (UTC) |
|---|---|---|---|
| T1 | CDP and LLDP list the expected Neighbour on every data Link (`show cdp neighbors`, `show lldp neighbors`). | | |
| T2 | Both Port-channel1 bundles are up with two members each (`show etherchannel summary`, `show port-channel summary`). | | |
| T3 | OSPF is FULL on all three /31 links and on VLAN 10, including the IOS-XE ↔ NX-OS ones with the HMAC-SHA-256 key chain. If a cross-platform adjacency stays down, record it and remove authentication from that link for this booking only. | | |
| T4 | The VLAN Mismatch trunk is up and the native VLAN mismatch is reported (CDP logs it on xe-sw1 and nx-sw1). | | |
| T5 | HSRP group 10 on VLAN 10 is active on xe-sw1 and standby on xe-sw2 (`show standby brief`). | | |

## Lab checks

### A. Identification and SSH

From [Identifying the Platform on first login](https://github.com/b-git-hub/network-analyser/issues/3), [Connection safety policy](https://github.com/b-git-hub/network-analyser/issues/7) and [Discovery and crawl](https://github.com/b-git-hub/network-analyser/issues/10). Results feed [#49](https://github.com/b-git-hub/network-analyser/issues/49) (identification), [#46](https://github.com/b-git-hub/network-analyser/issues/46) (Trust Store) and [#55](https://github.com/b-git-hub/network-analyser/issues/55) (Sweep).

| ID | Check | Result | Date (UTC) |
|---|---|---|---|
| A1 | The exact SSH identification string each node type presents: IOL-L2, Catalyst 8000V and NX-OS 9000v (for example from `ssh -v`, the "remote software version" line). | | |
| A2 | The NX-OS Sweep pattern: does the NX-OS string match the provisional `OpenSSH_* FIPS`, and do both IOS-XE strings match `Cisco-*`? If not, give the pattern that does. | | |
| A3 | The error text when a command for the wrong Platform is sent (for example `show port-channel summary` on IOS-XE, `show etherchannel summary` on NX-OS). | | |
| A4 | Does NX-OS show its copyright header on every login? | | |
| A5 | Can the `netanalyser` account, under its Device Role, run every identification command (`terminal length 0`, `show version`) on each Platform? | | |
| A6 | Does each Platform accept the client string `SSH-2.0-NetworkAnalyser_<version>`, and does it appear in syslog or AAA accounting? | | |
| A7 | Does each node negotiate with Paramiko 5.0 defaults (no SHA-1 key exchange, no `ssh-rsa` signatures)? Which host key types does each offer? | | |
| A8 | The console command that shows the host key fingerprint on each Platform (for example `show ip ssh`, `show crypto key mypubkey rsa`, `show ssh key rsa`). Does it print a SHA-256 fingerprint or only the raw key? | | |
| A9 | Regenerate one node's host key at the console. The next Run records it as `host key changed` and sends no password; `trust-key` accepts the new key only with its matching fingerprint. | | |

### B. Commands and the allow-list

From [Read-only command catalogue per Platform](https://github.com/b-git-hub/network-analyser/issues/4) and [#14](https://github.com/b-git-hub/network-analyser/issues/14). Results feed [#59](https://github.com/b-git-hub/network-analyser/issues/59) and [#60](https://github.com/b-git-hub/network-analyser/issues/60) (collection and parsers) and [#53](https://github.com/b-git-hub/network-analyser/issues/53) (`role-snippet`).

| ID | Check | Result | Date (UTC) |
|---|---|---|---|
| B1 | The exact allow-list strings: every command in the catalogue runs as written on each Platform, including the per-VRF forms. List any that need a different form. | | |
| B2 | The exact NX-OS `\| json` command strings: which allow-listed NX-OS commands accept `\| json`. | | |
| B3 | The default privilege level of each allow-listed IOS-XE `show` command (check with `show privilege` and `show parser`). | | |

### C. Device Roles

From [#14](https://github.com/b-git-hub/network-analyser/issues/14) and [ADR 0005](adr/0005-device-roles-cut-exactly-to-the-allow-list.md). Results feed [#53](https://github.com/b-git-hub/network-analyser/issues/53) (`role-snippet`) and [#59](https://github.com/b-git-hub/network-analyser/issues/59) and [#60](https://github.com/b-git-hub/network-analyser/issues/60) (landing privilege). Try the IOS-XE file checks on xe-rtr1 too: the Catalyst 8000V has a real bootflash, and IOL's file system may behave differently.

| ID | Check | Result | Date (UTC) |
|---|---|---|---|
| C1 | IOS-XE: does a **local** user land in a CLI view at SSH login, with no `enable`? (Log in as `netanalyser`.) If not, local-only sites use the privilege-level fallback. | | |
| C2 | IOS-XE: does `show running-config view full`, inside a view or at a custom level, need `file privilege N`? | | |
| C3 | IOS-XE: if it does, does `file privilege N` let that level `delete`, `copy`, `format` or `rename` files? If it does, it is never recommended (ADR 0005). | | |
| C4 | IOS-XE: does `show running-config view full` work unchanged at priv 15, with the same output as `show running-config`? | | |
| C5 | IOS-XE fallback: after `privilege exec level 7 …`, does `show` stay usable at level 1 once the snippet puts it back? (Try on one switch and reload it afterwards.) | | |
| C6 | IOS-XE: which command reports the landing privilege or view (`show privilege`, `show parser view`), and what must the role permit for it to run? | | |
| C7 | NX-OS: how are RBAC rules matched against `\| json` and arguments such as `vrf all`? Is a trailing `*` needed? | | |
| C8 | NX-OS: does `show running-config` under the custom role return the full config, with hashes and keys? | | |
| C9 | NX-OS: is any allow-listed command restricted to network-admin only? | | |
| C10 | NX-OS: which command reports the user's own roles (`show user-account <name>`, `show role`), and what must the role permit for it to run? | | |

### D. Backups

From [Encrypting Backups and handling secrets in configs](https://github.com/b-git-hub/network-analyser/issues/5) and [#14](https://github.com/b-git-hub/network-analyser/issues/14). Results feed [#51](https://github.com/b-git-hub/network-analyser/issues/51) (capture and lock Backups). Write a secret line's form with its value replaced, for example `key-string 7 <value>`.

| ID | Check | Result | Date (UTC) |
|---|---|---|---|
| D1 | Does a default config always print a `hostname` line, on both Platforms? | | |
| D2 | What does a truncated low-privilege config look like, and what error appears when `view full` is not permitted? (Describe it; don't paste it.) | | |
| D3 | The exact IOS-XE secret-line forms: routing protocol (the lab's OSPF key chain), keychain, NTP (add an `ntp authentication-key` by hand to see it) and the HSRP key. | | |

### E. Credentials and lockout

From [How Credential Sets are supplied and tried](https://github.com/b-git-hub/network-analyser/issues/6). Results feed [#54](https://github.com/b-git-hub/network-analyser/issues/54) (failure budget).

| ID | Check | Result | Date (UTC) |
|---|---|---|---|
| E1 | How many AAA failures does one wrong SSH password count as, on IOS-XE and on NX-OS? Paramiko sends exactly one password attempt per connect. (IOS-XE: the `%SEC_LOGIN-4-LOGIN_FAILED` log lines, or `show aaa local user lockout` with `aaa local authentication attempts max-fail` set; NX-OS: `show accounting log` or `show logging`.) | | |

### F. Run time and locking

From [Expected network size and Run limits](https://github.com/b-git-hub/network-analyser/issues/27). The CML lab can't hold 1,000 devices, so the Run-time targets are worked out from per-device times measured here.

Estimated Run time ≈ N × *t* ÷ parallelism + N × 1 s, where N is the device count, *t* the per-device time, and 1 s the pause each Backup lock causes. At the default parallelism of 10, the targets hold when:

- a typical Run of 300 devices finishes within 30 minutes: *t* ≤ 50 s;
- the largest Run of 1,000 devices finishes within 2 hours: *t* ≤ 62 s.

| ID | Check | Result | Date (UTC) |
|---|---|---|---|
| F1 | Per-device time, from login to Backup locked, for each node (from the Run report or `audit.log`). Record the slowest per Platform. | | |
| F2 | Using the slowest *t* from F1, are both targets met? | | |
| F3 | The scrypt level pyrage picks on your real PC, from the Run report. It should be 2^18 or above. | | |

### G. The exe on Windows

From [Python network automation libraries and packaging as a Windows exe](https://github.com/b-git-hub/network-analyser/issues/2), [Code signing and Python version](https://github.com/b-git-hub/network-analyser/issues/29) and [#32](https://github.com/b-git-hub/network-analyser/issues/32). These need no device. Results feed [#44](https://github.com/b-git-hub/network-analyser/issues/44) (`build.ps1`) and [#43](https://github.com/b-git-hub/network-analyser/issues/43) (masked prompt).

| ID | Check | Result | Date (UTC) |
|---|---|---|---|
| G1 | The zip size (target under 100 MB; a miss is a warning, not a blocker) and the unpacked folder size, as `build.ps1` prints them. | | |
| G2 | Cold start to the first prompt, with Defender on, on a PC at the smallest supported spec (Windows 11 64-bit, 8 GiB, 4 cores). Target under 5 s; a miss is a warning. | | |
| G3 | Long paths: a Run folder path over 260 characters (a deep `--runs-dir`) works through `\\?\` paths, without relying on the Windows `LongPathsEnabled` setting. | | |
| G4 | Does the unsigned build run at all? Record whether Smart App Control is on (Windows Security → App & browser control) and whether any IT policy blocks the exe, a `.pyd` or a DLL. A block is the trigger to bring signing forward. | | |
| G5 | Masked prompt, paste: a password pasted from your password manager arrives whole, with one `*` per character. | | |
| G6 | Masked prompt, keys: Ctrl+C at any secret prompt cancels cleanly, with no traceback, nothing saved and exit code 3. Backspace removes a character; arrow and function keys put nothing into the password. | | |

## Walkthrough of the tool

Run these on every booking that tests a new build. Use only `netanalyser` Credential Sets, and give the Scope as the lab's management addresses, one `--scope` per address.

| ID | Do this | Expect | Result | Date (UTC) |
|---|---|---|---|---|
| W1 | **A normal Run.** `network-analyser run --scope <each management address> --seed <each management address> --label lab`, with the right `netanalyser` password. | The Ready-to-start block lists the Scope, Seeds and each set's username, with passwords shown only as "held in memory". All five nodes become Visited Devices, each with its landing privilege recorded and a locked Backup (record any Backup not taken, with the reason the Run report gives). The Topology shows both Bundles; the VLAN Mismatch on xe-sw1 Ethernet0/3 ↔ nx-sw1 Ethernet1/3 (native VLAN 1 against 99 as a red `!`; VLANs 30 and 99 on one end only as amber `~`); the Subnet 198.51.100.0/25 with four devices; 198.51.100.128/25 as a line between xe-sw2 and nx-sw2; and OSPF L3 Adjacencies. HSRP address 198.51.100.1, the loopback /32s and the management VRFs create no L3 Adjacency. `diagram.html` and `run-report.html` open with the network cable unplugged. Record the exit code. | | |
| W1b | **The crawl from one Seed.** Repeat W1 with only `--seed <nx-sw1 address>`. | Record which nodes the crawl reached. For each one it didn't, record the reason the Run report gives (for example `outside Scope`, when its Neighbours advertise only data-plane addresses). | | |
| W2 | **A wrong password.** Start a Run with one Credential Set: `netanalyser` with a wrong password. | One login attempt per device, and one at a time while the set is on probation. After the failure budget (3 by default), the set is retired, and the console names its number and username. Devices tried are recorded as `authentication failed (every eligible set tried)`; the rest as `not attempted (Credential Sets retired)`. Compare each device's AAA failure count with check E1. | | |
| W3 | **Ctrl+C.** Start W1 again and press Ctrl+C once while devices are queued. Then do it again, pressing Ctrl+C twice. | Once: no new logins, the console says how many sessions it is waiting on, queued devices are recorded as `not attempted (Run stopped)`, the Topology, diagram and Run report are still written, and the exit code is 3. Twice: sessions close at once, identified devices become partial Visited Devices, and `backups\` holds no partial Backup. | | |
| W4 | **`show-backup`.** `network-analyser show-backup` with no file, then `network-analyser show-backup <Run folder>\backups\<file>.cfg.age`. | With no file, it lists the Run's Backups. With a file, it asks for the Backup Passphrase and prints the config to the console only: no new file appears in the Run folder or in `%TEMP%`. A wrong passphrase is refused. | | |
| W5 | **`render`.** Disconnect the sandbox VPN, then `network-analyser render <Run folder>`. | `diagram.html` and `diagram.drawio` are redrawn from `topology.json` and no device is contacted. `run-report.html` is unchanged. `diagram.drawio` opens in draw.io Desktop with Physical and Routing pages. | | |

## After the booking

- Leave Run folders on your PC. They hold lab data and are never committed.
- The sandbox wipes the lab when the booking ends. Nothing needs undoing on the devices.
- If a result changed a decision, comment on the ticket named in that section's heading.
