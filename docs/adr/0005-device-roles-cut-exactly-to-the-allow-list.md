# Device Roles cut exactly to the allow-list

The account the tool logs in with gets a **Device Role** that permits exactly the commands in the tool's compiled-in allow-list, and no more. On IOS/IOS-XE that is a CLI view; on NX-OS it is one custom role. The obvious alternative was a broad role (priv 15, or `network-operator` plus `show running-config`), which would keep working as later versions add commands. The operator chose the exact role because CLAUDE.md puts security first and Cisco best practice calls for least-privilege read-only roles. The cost of re-applying the role when the allow-list changes is kept low by generating the role from the allow-list itself.

Decided on [Device-side read-only roles per Platform](https://github.com/b-git-hub/network-analyser/issues/14). Cisco sources are in [research/device-side-read-only-roles.md](https://github.com/b-git-hub/network-analyser/blob/research/device-side-read-only-roles/research/device-side-read-only-roles.md).

## Consequences

- **Generated, never pushed.** `network-analyser role-snippet <platform>` prints the role from the same allow-list the tool sends commands from, for a local account and for TACACS+ (an ISE shell profile and command set). A test keeps the snippet and the allow-list identical. The tool only prints the snippet; it never configures a device. RADIUS gets a note only, because it cannot authorise commands.
- **Re-applied each release.** When a release changes the allow-list, its release notes say so and the operator re-applies the printed role. An out-of-date role shows up in the run report as *unknown* data or a missing Backup.
- **IOS/IOS-XE needs `aaa new-model`.** A CLI view affects only the user placed in it, and `show running-config view full` was built for view users. Views need `aaa new-model`, which Cisco advises never removing once set. Where a device can't take it, the fallback is a custom privilege level. That change applies to the whole device: Cisco's subset rule moves `show` itself to the new level, so the snippet puts `show` back at level 1.
- **No `file privilege` that grants writes.** Some IOS-XE platforms need `file privilege N` for `view full`, and the DISA STIG flags any value other than 15. If a sandbox check shows it lets that level delete, copy, format or rename files, it is never recommended. Such platforms then use TACACS+ priv 15 restricted by command authorisation, and local-only sites get no full Backup from them.
- **NX-OS: one exact custom role.** No `network-operator` and no `rule permit read`. `terminal length 0` and `terminal width 511` are permitted, because Netmiko sends them. TACACS+ assigns the role with `shell:roles`. Turning on TACACS+ command authorisation switches the device's role checks off, so the generated ISE command set becomes the only command check.
- **No `enable` in v1.** The account lands at its working privilege at login, so a Credential Set stays one username and one password. A later version may add `enable`; this ADR doesn't rule it out.
- **Privilege is reported, not judged.** The run report records the privilege each login landed at. It warns only when that privilege is too low to explain a missing Backup or *unknown* data, never when it is higher than needed. Later versions may add commands that need it.

## Considered Options

- **Broad read-only role** (IOS priv 15, NX-OS `network-operator` plus a role adding `show running-config`): survives new commands without touching devices, but the account can read and, on IOS, change far more than the tool uses. Rejected as a departure from least privilege.
- **Custom privilege level as the IOS/IOS-XE recommendation:** works without `aaa new-model`, but changes command levels for every user on the device. Kept as the fallback only.
- **Priv 15 restricted by TACACS+ command authorisation:** exact while TACACS+ is up, but the local fallback account is unrestricted. Kept only for platforms where `view full` needs a `file privilege` that grants writes.
