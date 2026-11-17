# Network Analyser

An operator-run tool that logs into Cisco (IOS/IOS-XE, NX-OS) and Palo Alto (PAN-OS) devices inside given IP ranges, backs up their running configuration, crawls CDP/LLDP to find more devices, and draws the topology. Use the vocabulary in [GLOSSARY.md](GLOSSARY.md); flag any term that conflicts with it.

## Where work is tracked

Everything lives on GitHub, not Azure DevOps.

- Repo: https://github.com/b-git-hub/network-analyser
- Issues: https://github.com/b-git-hub/network-analyser/issues
- Board: https://github.com/users/b-git-hub/projects/1
- Planning map: https://github.com/b-git-hub/network-analyser/issues/1 (label `wayfinder:map`). Its child issues are decision tickets labelled `wayfinder:research|prototype|grilling|task`. Read the map before starting any planning work.

Every task that comes out of a session becomes a GitHub issue in this repo, added to the board. The board's "Auto-add sub-issues to project" workflow adds any sub-issue of an item already on the board, so wayfinder tickets (sub-issues of the map) need no manual step. Cloud sessions cannot reach the board, so an issue that is not a sub-issue must be added by the operator, or by the board's "Auto-add to project" workflow if it is switched on. Use the `gh` CLI. On this machine it may only be reachable at `C:\Program Files\GitHub CLI\gh.exe`. Blocking uses GitHub's native "blocked by" relationship, and parent/child uses sub-issues.

## Security comes first

Security outranks convenience, speed and features. When a choice trades security for anything else, take the secure option or stop and ask.

- **The tool is read-only.** It never enters configuration mode and never sends a command that changes device state. Commands are sent from an explicit per-Platform allow-list.
- **Passwords are never stored.** Credential Set passwords are held in memory for one Run only and are entered at a prompt, never read from environment variables or a store the tool writes. They never reach disk, logs, reports, Backups, crash dumps, test fixtures, issues or commits. Usernames are not secret: they may appear in run reports and logs, including which username logged into which device (decided on [How Credential Sets are supplied and tried](https://github.com/b-git-hub/network-analyser/issues/6)).
- **Backups are encrypted at rest.** Running configs contain secrets and hashes, so no plaintext config is written to disk.
- **The Scope is a hard fence.** Never log into a device outside the operator's IP ranges, even when a Neighbour advertises it.
- **Real device data never goes into the repo.** Test fixtures use sanitised or synthetic output: no real hostnames, IPs, configs or secrets.

## Follow vendor best practice

Follow Cisco and Palo Alto Networks best practice by default (for example: SSH only, never Telnet; least-privilege read-only roles; verifying host keys; respecting AAA lockout behaviour). Depart from it only when a decision recorded on a GitHub issue explicitly says it is being skipped and why. When unsure what best practice is, research the vendor's own documentation rather than guessing.
