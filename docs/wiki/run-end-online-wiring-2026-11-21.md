# Run-end online wiring (#104), 2026-11-21

Built on 2026-11-21 on branch `ticket-104-run-end-online`, at the commit ending `(#104)`.

## Order and owners

`cli.run_end.finish` is the Run's end. It runs inside the audit trail (`cli.run_trail`), after
`discovery.crawl` has returned, which happens only once every visit has closed its session and
`BackupLocker.finish` has drained the locking queue:

1. unlock `cisco-key.age` with the Backup Passphrase, only when lookups are on and the file
   exists (`backup_store.unlock_key_file`);
2. wipe every Credential Set password and the passphrase (`cli.run_end.wipe`);
3. build the lookup questions (`cli.run_analysis.lookup_questions`), ask Cisco
   (`advisories.ask_cisco`), adapt the replies (`cli.run_analysis.analysis_answers`);
4. run every Check (`analysis.analyse`), record the `analysis` Audit event, write
   `topology.json`, `diagram.html`, `diagram.drawio` and `findings.html`;
5. wipe the key in a `finally`; the token lives only inside the `advisories` `Session`.

`run_topology.then_save` no longer writes outputs after a completed Run: it writes them only
when the Run never reached step 4 (Ctrl+C, a refused audit log), so a partial write failure
cannot replace Cisco's results with an offline copy.

## Secrets

`Secret.wipe()` drops the object's reference and refuses a later `reveal()`; Python cannot
erase an existing string, so the promise is "no further use", not "zeroed memory". The
`SecretScan` keeps its own copy of each typed value from the moment it is typed, because
`topology.json` and the reports are written after the wipe; `SecretScan.forget()` drops those
copies after the Run's one scan warning. (Superseded 2026-11-22: see Amendments.)

## What is sent, and NX-OS

`analysis.lookup_questions` already emits only de-duplicated, pattern-valid PIDs and OS type +
release strings. The bridge uses the same PID list for EoX and Software Suggestion. Until the
Nexus hardware-family table (story 46) exists, an NX-OS release question is left out of the
openVuln call: `advisories` refuses an NX-OS question without a `platformAlias`, and sending
it would refuse every other question too. EoX by release still includes NX-OS releases.

## Outages

A missing key gives one notice before the first prompt and one Needs-attention line at the
end. A rejected or unusable key, or Cisco unreachable, gives one Needs-attention line per
source (openVuln, EoX, Software Suggestion), no per-device Findings for that source, and no
new exit code (still 1). `topology.json` records `cisco_lookups = {ran, when}`.

## Audit event shape

`analysis` carries `cisco_lookups_ran`, `cisco_lookups_when`, `checks` (id, ran, reason),
`findings_by_level` (four levels), `findings_by_check` (id, count), the token outcome/status/
error code and one `(endpoint, calls, values, retries)` per Cisco endpoint. Counts only: no
device name, no per-device Finding, no Cisco value, no client ID or token.

## Amendments

- 2026-11-22, [#143](https://github.com/b-git-hub/network-analyser/issues/143): a Run that the
  crawl stopped skips step 1 and step 3 (the key is never unlocked, Cisco is never asked) and
  still records its offline `analysis` event. A Ctrl+C during step 3 is treated as lookups that
  did not finish: the outputs are written, the Run is reported stopped, and exits 3. The
  `try`/`finally` now starts straight after the unlock, and a Check that raises on Cisco's
  answers is retried offline. The key joins the scan at the unlock, and `cmd_run` wipes the
  device secrets on every way out of the Run, not only through step 2.
- 2026-11-22, [#145](https://github.com/b-git-hub/network-analyser/issues/145): supersedes the
  **Secrets** claim that the scan keeps a copy of each typed value. `SecretScan` now stores only
  each secret's length and an HMAC-SHA256 fingerprint under a random per-Run key, and matches by
  hashing the windows of that length, so step 2's wipe leaves nothing recoverable while the tool
  is online ([ADR 0007](../adr/0007-cisco-lookups-at-run-end-after-secrets-wiped.md), the
  amendment of the same date). `forget()` still drops the fingerprints after the Run's one scan
  warning, and the Seam 3 test now walks the scan at the first Cisco request to prove no typed
  password or passphrase is reachable from it.
