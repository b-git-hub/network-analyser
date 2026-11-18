# Backups locked with one operator passphrase, not age keys

Every Backup is encrypted in the standard age format with an age passphrase (scrypt) recipient. The passphrase is the **Backup Passphrase**: the operator types it at a hidden prompt at the start of each Run, it is held in memory for that Run only, and it is handled exactly like a Credential Set password. The research on [Encrypting Backups and handling secrets in configs](https://github.com/b-git-hub/network-analyser/issues/5) recommended X25519 key pairs instead, so that no secret is held during a Run. The operator chose a passphrase because creating and looking after key files is too much burden for one operator whose Backups stay on their own PC.

Decided on [Backup storage and encryption](https://github.com/b-git-hub/network-analyser/issues/12).

## Consequences

- **A secret is in memory during every Run.** The Backup Passphrase gets the same rules as Credential Set passwords: never written to disk, logs, reports, crash dumps, fixtures, issues or commits.
- **Prompt order.** At Run start the crash-dump warning comes first, then the Backup Passphrase, then the Credential Sets, so a bad passphrase stops the Run before any device password is typed.
- **Strength.** At least 15 characters (NIST SP 800-63B for a single-factor secret), and it must differ from every Credential Set password typed in the same Run.
- **Typos are caught by a check file.** A small age file in the operator's per-user folder holds a known phrase locked with the passphrase. Each Run must unlock it, or it stops. The first Run asks for the passphrase twice and creates the file. The check file holds no secret: guessing against it is no easier than guessing against a Backup.
- **No recovery.** A forgotten passphrase loses every Backup it locked. The tool says so at first-Run setup and recommends a password manager. There is deliberately no second way in.
- **One secret writes and reads everything.** Anyone who learns the passphrase can open every Backup. There is no per-colleague sharing. A Backup is taken away as its locked file, and whoever opens it needs the passphrase.
- **Still standard age.** `age -d <file>` opens a Backup without Network Analyser. The tool also offers `show-backup`, which prints to the console and never writes plaintext to disk.
- **Cost per file.** age's scrypt costs about a second per encryption at its default work factor, paid once per Backup. The default is not lowered.
- **Changing the passphrase** is open; it is decided on its own ticket.

## Considered Options

- **age X25519 key pairs with an offline recovery key** (the research's recommendation): no secret during a Run, a recovery key and per-colleague sharing, but the operator has to create, protect and keep two key files. Rejected as too complicated for the operator.
- **A passphrase in a file format of our own** (Argon2id plus an AEAD): sound, but we would own the format and nothing else could read it. age's passphrase recipient gives the same properties in a standard format.
- **Windows DPAPI:** no passphrase to type, but ties Backups to one Windows account on one PC and lets any process running as the operator decrypt them silently.
