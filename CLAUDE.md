# Network Analyser

An operator-run tool that logs into Cisco (IOS/IOS-XE, NX-OS) and Palo Alto (PAN-OS) devices inside given IP ranges, backs up their running configuration, crawls CDP/LLDP to find more devices, and draws the topology. **v1 covers Cisco only, over SSH only:** PAN-OS was dropped from v1 on [Get devices to test against](https://github.com/b-git-hub/network-analyser/issues/8), and its earlier decisions are kept for a later effort. Use the vocabulary in [GLOSSARY.md](GLOSSARY.md); flag any term that conflicts with it.

## Where work is tracked

Everything lives on GitHub, not Azure DevOps.

- Repo: https://github.com/b-git-hub/network-analyser
- Issues: https://github.com/b-git-hub/network-analyser/issues
- Board: https://github.com/users/b-git-hub/projects/1
- Planning map: https://github.com/b-git-hub/network-analyser/issues/1 (label `wayfinder:map`). Its child issues are decision tickets labelled `wayfinder:research|prototype|grilling|task`. Read the map before starting any planning work.

Every task that comes out of a session becomes a GitHub issue in this repo, added to the board. The board's "Auto-add sub-issues to project" workflow adds any sub-issue of an item already on the board, so wayfinder tickets (sub-issues of the map) need no manual step. Cloud sessions cannot reach the board, so an issue that is not a sub-issue must be added by the operator, or by the board's "Auto-add to project" workflow if it is switched on. Use the `gh` CLI. Blocking uses GitHub's native "blocked by" relationship, and parent/child uses sub-issues.

### Setting "blocked by" from a cloud session

Cloud sessions cannot set "blocked by": the GitHub MCP tools have no dependency operation. When a session needs a blocking edge, it hands the operator one ready-to-paste command per edge:

```
gh api repos/b-git-hub/network-analyser/issues/<blocked number>/dependencies/blocked_by -F issue_id=<blocker's internal id>
```

- `issue_id` is the blocker's internal issue **id** (for example `6464387517`), not its number. Take it from the `id` that `issue_write` returns on create, or from `issue_read`.
- Give one command per code block, with no `&&`: the operator runs Windows PowerShell 5.1, which rejects `&&`.
- `gh` is installed with winget and is on the operator's PATH as plain `gh`.
- Say which ticket blocks which, and why, beside the commands.
- Also note "Waits on: <ticket name>" in the blocked ticket's body, so the dependency is readable before the operator runs the command.

## Git workflow

**Never push to `main` or merge into it directly.** Every change lands through a pull request,
including documentation and one-line fixes. The operator approves the PR; merge is theirs.

- **One ticket, one branch, one PR.** Branch from the current integration branch (or from
  `main` for a standalone change), name it `ticket-<n>-<slug>`, and open the PR once the gate
  passes. Never reuse another ticket's branch.
- **Close tickets as they land.** When a ticket is complete and its checks pass, close its
  issue with a comment pointing at the work —
  `gh issue close <n> --comment "Delivered on <branch> at <sha>"` — so the board reflects
  reality. Do not batch closed tickets to the end of the build.
- **A build task gets one integration branch and one PR.** When a spec breaks into tickets:
  1. create `build/<spec-or-release>` from `main`;
  2. create each ticket branch from `build/<spec-or-release>`, and merge it back into that
     branch when its gate passes — never into `main`;
  3. close each ticket as it merges, per above;
  4. when every ticket is in, open **one** PR `build/<spec-or-release>` → `main`, listing the
     tickets, the gate result and anything operator-only, for a single approval.
- **Release work is last.** Version bump, changelog, lab role and release notes go on the
  integration branch after all feature tickets, so the single PR carries the whole release.
- **Never rewrite `main`.** If something landed wrongly, fix forward with a revert PR.
- **Tags and releases** are created only after the integration PR is merged.

## Code

Before writing code, read [CODING_STANDARDS.md](CODING_STANDARDS.md): its rules are enforced by tests, and `uv run --locked python scripts/check.py` must pass.

## Wiki

[docs/wiki/index.md](docs/wiki/index.md) holds dated decisions, process notes and lessons from earlier sessions. Read it before planning or implementation work, and follow [its conventions](docs/wiki/conventions.md) when you add to it.

## Security comes first

Security outranks convenience, speed and features. When a choice trades security for anything else, take the secure option or stop and ask.

- **The tool is read-only.** It never enters configuration mode and never sends a command that changes device state. Commands are sent from an explicit per-Platform allow-list.
- **Passwords are never stored.** Credential Set passwords and the Backup Passphrase are held in memory for one Run only and are entered at a prompt, never read from environment variables or a store the tool writes. They never reach disk, logs, reports, Backups, crash dumps, test fixtures, issues or commits. Usernames are not secret: they may appear in run reports and logs, including which username logged into which device (decided on [How Credential Sets are supplied and tried](https://github.com/b-git-hub/network-analyser/issues/6)). **One exception:** the Cisco API Key (client ID and secret) is stored between Runs, but only in one file locked with the Backup Passphrase, and opened only at the end of a Run. It follows every other rule here ([ADR 0008](docs/adr/0008-cisco-api-key-stored-locked-with-backup-passphrase.md)). No other secret may be stored.
- **Backups are encrypted at rest.** Running configs contain secrets and hashes, so no plaintext config is written to disk, not even as an export. Backups are locked with the Backup Passphrase, which follows the same rules as a Credential Set password ([ADR 0004](docs/adr/0004-backups-locked-with-operator-passphrase.md)).
- **The Scope is a hard fence.** Never log into a device outside the operator's IP ranges, even when a Neighbour advertises it.
- **Internet egress is fenced to Cisco.** Only the `advisories` module opens outbound HTTPS. It goes online only to `id.cisco.com` and `apix.cisco.com`, only once, at the end of a Run, after every device password and the Backup Passphrase are wiped. The one other time it goes online is `cisco-key set`, which sends a single token request to `id.cisco.com` to test a newly stored key, with no device data ([ADR 0008](docs/adr/0008-cisco-api-key-stored-locked-with-backup-passphrase.md)). It sends only the de-duplicated PIDs and release strings a lookup needs, never serials, hostnames, IPs or config. Nothing Cisco returns is stored between Runs ([ADR 0007](docs/adr/0007-cisco-lookups-at-run-end-after-secrets-wiped.md)).
- **Real device data never goes into the repo.** Test fixtures use sanitised or synthetic output: no real hostnames, IPs, configs or secrets.

## Follow vendor best practice

Follow Cisco and Palo Alto Networks best practice by default (for example: SSH only, never Telnet; least-privilege read-only roles; verifying host keys; respecting AAA lockout behaviour). Depart from it only when a decision recorded on a GitHub issue explicitly says it is being skipped and why. When unsure what best practice is, research the vendor's own documentation rather than guessing.
