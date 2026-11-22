# Cisco lookups happen at the end of a Run, after device secrets are wiped, and send only models and releases

_Supersedes [ADR 0006](0006-run-refreshes-signed-cisco-advisories-before-secrets.md)._

Analysis now asks Cisco three things about the Visited Devices:
- which Advisories affect a release, from the PSIRT openVuln API;
- end-of-life dates, from the EoX API;
- which releases Cisco suggests and which is latest, from the Software Suggestion API.

All three take the model or release in the request, and the tool learns those only after logging into devices. The operator also wants nothing kept between Runs: the tool is often run once against a network, so a local store of Cisco's data would rarely be reused.

So ADR 0006 is replaced. It refreshed a stored, signed copy of every CSAF Advisory before any secret was typed, and sent no device data. Instead, a Run goes online **once, at its end**:

1. Every device session is closed.
2. Every Backup is already locked.
3. Every Credential Set password and the Backup Passphrase are wiped from memory.
4. The tool then sends Cisco only the **de-duplicated set** of PIDs and release strings it needs, using the Cisco API secret.

That secret is the only one held while online, and it goes only to Cisco's token service. Nothing Cisco returns is written anywhere except as Findings and advice in the Run's outputs.

Decided on [Which configuration, lifecycle and consistency Checks ship](https://github.com/b-git-hub/network-analyser/issues/81).

## Consequences

- **Still one egress module.** `advisories` is the only module that opens an outbound HTTPS connection or imports the HTTP client. It holds no device password and no Backup Passphrase. The only secret it ever holds is the Cisco API secret. It receives plain lists of PIDs and releases from `analysis`. The import test enforces this.
- **What is sent.** Only distinct PIDs (chassis, stack members, supervisors and line cards; never optics, PSUs or fans) and distinct OS type + release strings. Each value must match a strict pattern before it is sent. Serials, counts, hostnames, IPs, config and every other field are never sent. The Audit log records how many calls and values went to each endpoint, never the values themselves.
- **No duplicate requests.** One request per distinct question, batched where the API allows (20 PIDs or releases per EoX call, 10 PIDs per Suggestion call). Calls are paced under Cisco's limits (openVuln allows 30 calls a minute), honour `Retry-After` and Cisco's rate-limit codes, and are retried once.
- **Fence.** Only `id.cisco.com` (token) and `apix.cisco.com` (APIs), only over HTTPS on port 443, with certificates checked against the Windows store. Every redirect is refused. Proxies come from Windows' own setting or `--proxy`, never from environment variables.
- **Trust rests on TLS.** openVuln, EoX and Suggestion replies are not signed, so the CSAF signature check and the built-in PSIRT keys go away. The Run report says the data was fetched over TLS and not signature-checked.
- **Nothing stored.** There is no Advisory Store and no lifecycle store, and nothing is kept between Runs.
- **Outages never stop a Run.** If Cisco can't be reached, or the key is missing, expired or revoked, each affected source gets one Needs-your-attention line, there are no per-device Findings for it, and the Run exits 1.
- **Opt-out.** `--cisco-lookups on|off` (default `on`) replaces `--advisories`. `off` means the Run never goes online.
- **A Cisco key is required for any Cisco data.** How it is supplied and kept is decided on [How Cisco API keys are supplied and kept](https://github.com/b-git-hub/network-analyser/issues/77). It must be in memory at the Run's end, and Cisco's terms forbid embedding it in an open-source project, so it is never built into the exe.

## Considered Options

- **Keep ADR 0006 (signed CSAF, stored, refreshed before secrets):** this was the strongest isolation, but it can't serve EoX or the Suggested Release, and the operator does not want a local store.
- **Pull every CSAF file fresh each Run, held in memory:** this stays keyless and signed, but it means about 5,800 requests and roughly 13 MB compressed per Run whatever the estate size (measured 2026-11-20). The operator preferred a few targeted queries.
- **Look up during the crawl:** results come sooner, but the tool would be online while every device password is in memory.
- **A separate lookup command after the Run:** this adds a second step to a tool that is usually run once.

## Amendment (2026-11-21)

Decided on [Latest Release and Upgrade Target, given what Cisco provides](https://github.com/b-git-hub/network-analyser/issues/121), after the live checks on [Check the release sources with the Cisco API Key](https://github.com/b-git-hub/network-analyser/issues/120). The decision itself is unchanged: one lookup at the Run's end, after secrets are wiped, sending only distinct values and storing nothing. Three points of wording change.

- **What is sent** also includes a **Nexus series alias** (such as `NEXUS9000`), worked out from the model, as openVuln's `platformAlias` on NX-OS queries. It reveals less than the chassis PID, which is already sent, and it is pattern-checked like every other value.
- **Software Suggestion** is asked for the Latest Release through its compatible-releases call, which takes **one chassis PID per call** and is paged, at most 20 pages per PID. The "10 PIDs per Suggestion call" batch applies only to the Suggested-releases call.
- **`currentRelease` is never sent.** It would pair a model with the release it runs, and every value goes out on its own.

## Amendment (2026-11-22)

Decided on [one PID and release pattern for analysis and advisories](https://github.com/b-git-hub/network-analyser/issues/130). The decision is unchanged; two points of wording change.

- **One value, one pattern, one refusal.** `analysis` and `advisories` read the same patterns (`records.lookup_values`). A value that does not match is dropped on its own and is never sent; the rest of the lookup is still asked, and the device whose PID was dropped reads "could not check" (the Suggested Release Check says the PID was not sent). The call is refused whole only when no value is left.
- **A licence-suffixed PID** such as `ISR4451-X/K9` is a PID. One `/` and a short suffix are allowed in the value, and that `/` is the only character written percent-encoded (`%2F`) in a request path. Any other `%`, `/`, `?`, `&`, `#`, `..`, control character or non-ASCII character fails the pattern.

## Amendment (2026-11-22, later)

Decided on [Send licence-suffixed PIDs to Cisco with a raw slash](https://github.com/b-git-hub/network-analyser/issues/162), after the operator's live runs on [Verify Cisco reply shapes with the live API key](https://github.com/b-git-hub/network-analyser/issues/148). The decision is unchanged; one point of wording in the amendment above changes.

- **A licence-suffixed PID goes into the request path as it is, slash included.** Cisco's gateway answers every path call that carries `%2F` or `%252F` with HTTP 400. It answers the raw slash on hardware EoX (one PID or several comma-joined), Software Suggestion and the compatible list. No character of a PID is percent-encoded. The pattern still allows only one `/`, followed by letters, digits and hyphens, so the slash cannot add `..` or any other change to the path, and any `%` fails the pattern. This replaces the `%2F` sentence above.

## Amendment (2026-11-22, #145)

Decided on [SecretScan keeps plaintext secrets while the Run is online](https://github.com/b-git-hub/network-analyser/issues/145): the operator chose option 1. The decision above is unchanged; the code now matches it.

- **The secret scan keeps no value.** `SecretScan` holds each secret's character length and an HMAC-SHA256 fingerprint of it under a random key drawn once per Run. It finds a secret by hashing the windows of that length, so the console, `audit.log`, `topology.json`, the diagrams and the reports are still redacted after step 3's wipe and while the tool is online.
- **Why the device values are not dropped instead.** The files written after step 4 carry Cisco's answers merged with device facts, so their device-derived text is final only at write time. Neutralising it before the online step would mean redacting every field of every record, and would still miss a secret split across two fields.
- **Proved, not asserted.** The Seam 3 test walks what is reachable from the `SecretScan` when the first Cisco request arrives: it holds no typed password and no passphrase, and it still redacts both.
