# The Cisco API Key is stored, locked with the Backup Passphrase

Analysis needs a **Cisco API Key** for every Cisco lookup ([ADR 0007](0007-cisco-lookups-at-run-end-after-secrets-wiped.md)). It is an OAuth2 client ID and client secret from one Cisco API Console app, which covers openVuln, EoX and Software Suggestion (confirmed by the operator on 2026-11-20). The secret never expires. The operator wanted to add the key once, securely, inside the tool, rather than paste it on every Run. So the key is the **first and only secret the tool keeps between Runs**. It lives in `%LOCALAPPDATA%\NetworkAnalyser\cisco-key.age`, an age file locked with the Backup Passphrase. That is the same protection every Backup already has, and Backups hold device secrets and hashes.

This departs from CLAUDE.md's "passwords are never stored" rule, which until now had no exceptions. Credential Set passwords and the Backup Passphrase are still never stored. It also narrows ADR 0007's "online only once, at the end of a Run" by one token-only request from `cisco-key set`.

Decided on [How Cisco API keys are supplied and kept](https://github.com/b-git-hub/network-analyser/issues/77).

## Consequences

- **Opened only at the Run's end.** At Run start the tool only checks that `cisco-key.age` exists. The key is unlocked after every Backup is locked and just before the Backup Passphrase is wiped, so it is never in memory while devices are crawled. `--cisco-lookups off` never touches the file.
- **A missing key never stops a Run.** Before the first prompt the tool prints "No Cisco API key is stored. This Run will skip Cisco lookups. Add one with `cisco-key set`, or pass `--cisco-lookups off`." It then carries on without asking anything. At the end there is one Needs-your-attention line and exit code 1.
- **All three values are secrets.** The client ID, the client secret and the bearer token from `id.cisco.com` are each a `credentials.Secret` and join the `SecretScan` as soon as they exist. Only `advisories` may reveal them, plus `backup_store` to unlock the file. The token is never written anywhere. The Audit log records only the token result (ok, or the HTTP status and Cisco error code) and ADR 0007's call counts, never the client ID.
- **A rejected key is not retried.** An HTTP 400 `invalid_client` from `id.cisco.com` is never retried, and its Needs-your-attention line names `cisco-key set`. A 403 is split by `X-Mashery-Error-Code`: an auth error is not retried, and a rate limit follows ADR 0007's pacing and single retry.
- **The `cisco-key` command:**
  - `cisco-key set` asks for the Backup Passphrase, which must unlock the check file (3 tries), then for the client ID and secret at masked prompts. It locks them into the file and wipes them from memory. It then sends one token request, to `id.cisco.com` only, with no API calls and no device data, and reports the result. `--no-check` skips that request. `set` refuses if there is no check file yet.
  - `cisco-key show` says whether a key is stored and when it was last set. With the passphrase, it also shows the last 4 characters of the client ID. The secret is never shown.
  - `cisco-key remove` deletes the file after a `[y/N]` confirmation.
  - All three take the data folder's single-instance lock and per-user access check, so none can run during a Run.
- **It follows the Backup Passphrase:**
  - `change-passphrase` re-locks `cisco-key.age` in the same pass as the Backups and Run manifests.
  - Starting over by deleting the check file means deleting `cisco-key.age` too.
  - A key file that the current passphrase can't open is reported once as "Cisco key locked with a different passphrase: run `cisco-key set` again".
- **Least privilege is guidance, not enforced:**
  - one Service app with the client-credentials grant and only the three APIs ticked;
  - an end date on the API Developer role;
  - the registration email deleted once the secret is in a password manager.

  `cisco-key set` and the docs say so. The tool cannot check it.
- **Never built in.** Releases are public, and Cisco's terms forbid embedding credentials in open-source projects, so the key never goes into the exe or the repo.

## Considered Options

- **Typed at a hidden prompt every Run:** this keeps "never stored" without exception. But it adds a secret to paste on every Run, which is the opposite of what the operator asked for.
- **Windows DPAPI or Credential Manager:** nothing to type, but any process running as the operator can read the key without asking. ADR 0004 rejected DPAPI for Backups for that reason, and v1 rejected Credential Manager for Credential Sets ([How the operator enters Credential Sets at Run start](https://github.com/b-git-hub/network-analyser/issues/15)).
- **Opening the key at Run start:** this would show a bad file sooner, but the key would sit in memory through the whole crawl for no benefit.
