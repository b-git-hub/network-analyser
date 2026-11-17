# Encrypting Backups and handling secrets in configs

Research for [#5](https://github.com/b-git-hub/network-analyser/issues/5). Feeds the grilling ticket [#12 Backup storage and encryption](https://github.com/b-git-hub/network-analyser/issues/12). Researched 2026-11-17. Terms follow [GLOSSARY.md](../GLOSSARY.md).

## Question

What is the best-practice way for a Windows tool run by one operator to encrypt Backups at rest? Should secrets inside running configs also be redacted? The options compared are age, GPG/OpenPGP, passphrase-based symmetric encryption (libsodium or Fernet with a strong KDF), and Windows DPAPI. The comparison covers key management, Python library maturity, and how each works in a bundled exe.

## Short answer

1. **Encrypt each Backup with age to X25519 public-key recipients.** Use **pyrage**, the Python binding to the Rust `rage` implementation. The tool only needs the operator's **public** key (a recipient) to write Backups. No secret is typed, held or stored during a Run to protect them. The private key (the identity) can stay offline, protected by a passphrase or on a YubiKey. It is used only when someone reads a Backup.
2. **Add a second, offline recovery recipient.** This is the answer to "what if the key is lost". To share a Backup with a colleague, re-encrypt that one file to the colleague's recipient. Do not hand over the operator's identity.
3. **Do not redact the Backup itself.** A Backup is the vendor's unmodified running config, so it can be restored. Every secret in it is protected by the encryption. Redact only **derived** outputs: Topology, the diagram, reports, logs, and any "share" export. Never let a secret-bearing line reach any of them.
4. **Not recommended:**
   - **DPAPI** as the Backup cipher. It ties every Backup to one Windows account on one PC, gives no clean recovery or sharing, and anything running as that user can decrypt silently.
   - **GPG.** It needs an external `gpg.exe` and keyring, and the OpenPGP ecosystem is split.
   - **A home-made passphrase format** (Fernet or libsodium plus Argon2id). It is sound cryptography, but it is a file format we would own forever. A symmetric passphrase also means the same secret both writes and reads every Backup.

The rest of this file is the evidence.

## 1. What the secrets in a running config are, and why encryption is non-negotiable

Cisco's own guidance treats config files as sensitive in their entirety:

- "Configuration files with encrypted passwords should be handled with the same care as a plaintext list of those passwords." Archives "must be stored securely and only shared with trusted individuals." ([Cisco Guide to Harden Cisco IOS Devices](https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html), Password Management / Configuration Management)
- Type 7 is "a simple Vigenère cipher". Cisco says to "consider these passwords obfuscated, not encrypted" (same guide). Cisco's trust centre says type 7 should be treated "for all intents and purposes, [as] plain text" ([Protecting Secrets on Cisco Network Devices](https://www.cisco.com/c/en/us/about/trust-center/resilient-infrastructure/protecting-secrets.html), updated 2026-03-12).
- Among the ways threat actors obtain configs, Cisco lists "administrators' personal computers" (same trust-centre page). The Network Analyser workstation is exactly that.

### Cisco password and secret types

Source: [Cisco trust centre, Protecting Secrets](https://www.cisco.com/c/en/us/about/trust-center/resilient-infrastructure/protecting-secrets.html), unless noted.

| Type | What it is | Reversible? | Risk if a Backup leaks |
|---|---|---|---|
| 0 | Plain text | n/a | Secret exposed directly. "should never be used in running configuration" |
| 4 | Flawed SHA-256 | No | Deprecated immediately, and gone from current OSes. Old configs only |
| 5 | MD5-crypt (`$1$`) | No | Crackable offline by dictionary or brute force. IOS-XE 16.12+ auto-converts type 5 to type 9 |
| 6 | AES-128 under the device master key | Yes, with the key | Safe without the master key. The master key "is never shown in a configuration file" |
| 7 | Vigenère with a public static key | Yes, trivially | Equivalent to plain text |
| 8 | PBKDF2-SHA-256, 80-bit salt, 20,000 iterations (`$8$`) | No | Offline cracking possible but costly |
| 9 | scrypt, 80-bit salt (`$9$`, convoluted `$14$`) | No | "generally considered stronger than type 8" |

Cisco plans that IOS-XE will stop storing type 0 and type 7 where a reversible secret is needed:

- **26.1.1:** syslog warns daily when no master key is set.
- **26.2.1:** credentials auto-convert to type 6 and keys are auto-generated.
- **27.1.1:** upgrades fail without a key.

NX-OS and IOS-XR "will follow similar plans" (trust centre). This shrinks plaintext secrets in future Backups but does not remove hashes or SNMP communities.

### Secret-bearing lines per Platform

These are the lines a parser must never copy into a derived output. Each line in the lists below is either reported by the source cited after it, or is standard command syntax that should be checked against recorded output (ticket #8) before the redaction list is fixed.

**IOS / IOS-XE** ([hardening guide](https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html), [IOS 15MT passwords guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/15-mt/sec-usr-cfg-15-mt-book/sec-cfg-sec-4cli.html), [Catalyst 9600 17.6 password guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9600/software/release/17-6/configuration_guide/sec/b_176_sec_9600_cg/controlling_switch_access_with_passwords_and_privilege_levels.html), [Encrypted Preshared Key](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_conn_ikevpn/configuration/xe-16-9/sec-ike-for-ipsec-vpns-xe-16-9-book/sec-encrypt-preshare.html)):

- `enable secret <5|8|9> …` and `enable password <0|7|6> …`
- `username <u> secret <5|8|9> …` and `username <u> password <0|7|6> …`
- `line con|vty …` → `password <0|7|6> …`
- `snmp-server community <string> RO|RW …`: shown in clear. Cisco calls community strings "passwords". SNMPv3 `snmp-server user` lines are **not** shown in the config (hardening guide).
- `tacacs-server key …`, `tacacs server <n>` → `key <0|6|7> …`, `radius-server key …`, and `radius server <n>` → `key …`. Type 6 for these keys arrived in IOS-XE 16.5.
- `crypto isakmp key <psk> address …`, `crypto keyring` / `crypto ikev2 keyring` → `pre-shared-key …`
- `key chain` → `key-string <0|7|6> …`, routing-protocol MD5 keys (OSPF `message-digest-key`, BGP `neighbor … password`), and `ntp authentication-key …`. These are standard syntax; verify against recorded output.
- Not present: the type 6 master key (`key config-key password-encrypt`, held in private NVRAM) and the SSH RSA private key.

**NX-OS** ([N9K 10.4 user accounts](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/configuration/security/cisco-nexus-9000-series-nx-os-security-configuration-guide-release-104x/m-configuring-user-accounts-and-rbac.html), [N9K 10.4 password encryption](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/configuration/security/cisco-nexus-9000-series-nx-os-security-configuration-guide-release-104x/m-configuring-password-encryption.html), [N7K 8.x SNMP](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus7000/sw/system-management/config/cisco_nexus7000_system-management_config_guide_8x/configuring_snmp.html)):

- `username <u> password 5 …`: type 5 on NX-OS is SHA-256-hashed. Types 8 and 9 are supported from NX-OS 10.3(1)F.
- `snmp-server user <u> <role> auth md5 0x… priv 0x… localizedkey`: these localized SNMPv3 keys **do** appear in `show running-config`. They are derived from the password and the engine ID, and they can be pasted back as-is, so for that device they are credential-equivalent.
- `snmp-server community <string> …`
- `tacacs-server key 7 "…"`, `radius-server key 7 "…"`, and per-host `key 7 …`. These become `key 6` once `feature password encryption aes` and a primary key are set. RADIUS and TACACS+ are the only users of type 6 on NX-OS.
- `key chain` → `key-string 7 …`. MACsec keychains use type 6 when the AES feature is enabled.

**PAN-OS** ([Configure the Master Key](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/certificate-management/configure-the-master-key), [Master Key and Diagnostics 12.2](https://docs.paloaltonetworks.com/ngfw/help/12-2/device/device-master-key-and-diagnostics), [Configure Master Key Encryption Level](https://docs.paloaltonetworks.com/ngfw/administration/certificate-management/master-key-encryption/configure-master-key-encryption-level), [Block Private Key Export](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/decryption/block-private-key-export), [KB: change admin password via XML API](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClkTCAS)):

- `mgt-config/users/entry/phash`: administrator password hash. The KB shows `request password-hash` producing a `$1$…` (MD5-crypt) value, which is offline-crackable. Check newer releases for the format in use. The local user database holds similar `phash` values.
- **Every other password and private key** in the config, such as IKE pre-shared keys, RADIUS/TACACS/LDAP secrets, and certificate private keys. "A master key encrypts all private keys and passwords in a configuration." The algorithm is AES-256-CBC by default, or AES-256-GCM at level 2 (PAN-OS 11.1+).
  - Every firewall ships with a **default master key**, and Palo Alto "recommends you configure a new master key instead of using the default key".
  - From PAN-OS 12.2.2, commits are blocked 60 to 120 days after the default key is detected.
  - Ciphertext under a default key should be treated as weakly protected.
- **API keys are not config lines.** They are tokens generated with `type=keygen` from an admin's credentials. With the default API key lifetime of 0 they **never expire** ([Configure API Key Lifetime](https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/firewall-administration/manage-firewall-administrators/configure-administrative-accounts-and-authentication/configure-api-key-lifetime)). They are invalidated only by a password change, user deletion, "Expire all API Keys", or a certificate commit ([Get Your API Key](https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key)). The key the tool obtains during a Run is credential-equivalent: it must follow the Credential Set rules and never reach a Backup, log or report.

## 2. Redact or not?

| | Encrypt full config (recommended Backup) | Encrypt redacted config |
|---|---|---|
| Restorable as-is | Yes, apart from the device dependencies below | **No.** Every redacted secret must be re-entered by hand. Redacting a type 5/8/9 hash or an NX-OS localized key destroys a value that cannot be regenerated without the original password |
| Exposure if the encryption key leaks | All secrets: type 7 and type 0 directly, hashes crackable offline | Topology, ACLs, IPs only |
| Implementation risk | Low: bytes in, bytes out | A per-Platform redaction grammar that must never miss a line. A missed line is silent |
| Fits "no plaintext config on disk" | Yes | Yes, but only if the redacted copy is **also** encrypted. A redacted config still holds IPs, ACLs and hostnames |

Device dependencies that limit "restore as-is" even without redaction:

- **IOS-XE type 6** values restore only on a device with the same master key. Cisco advises storing the key "securely" for RMA (trust centre).
- **NX-OS**: Type-6 configs fail to decrypt on a switch with a different primary key, and are "not rollback-compliant" (N9K password-encryption guide).
- **PAN-OS**: a config loads on another firewall only when "both use the same master key" (Block Private Key Export).

**Recommendation:** keep the Backup unredacted and encrypted. Treat redaction as a **filter on everything derived from a Backup**: parsers, Topology, diagram, reports, the audit log, and test fixtures (CLAUDE.md already bans real data in fixtures). Optionally offer a later "export redacted copy for sharing" (still encrypted) built on the same filter. A redacted file is a sharing artefact, never a Backup.

## 3. Encryption options compared

### age (recommended)

- **Format:** the open [C2SP age v1 spec](https://github.com/C2SP/C2SP/blob/main/age.md).
  - A random 128-bit file key, wrapped once per recipient. The payload is ChaCha20-Poly1305 in a STREAM construction over 64 KiB chunks, so truncation is detected. The header carries an HMAC-SHA-256.
  - **Multiple recipients** per file are supported.
  - **Passphrase (scrypt) recipients** "MAY NOT be mixed" with other recipient types. A file is either passphrase-only or key-only.
  - The Go reference uses scrypt work factor logN 18 by default ("1s on a modern machine") and caps at 22 on decrypt ([age scrypt.go](https://github.com/FiloSottile/age/blob/main/scrypt.go)). 2^18 is above OWASP's minimum of N=2^17 ([OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)).
- **Ecosystem:** several independent implementations read the same files: Go `age`, Rust `rage`, and the Python binding.
  - The [`age` CLI](https://github.com/FiloSottile/age) installs on Windows via winget, Chocolatey or Scoop, so an operator or colleague can decrypt a Backup **without Network Analyser**.
  - YubiKey identities are available via `age-plugin-yubikey`.
  - Built-in hybrid post-quantum recipients (`mlkem768x25519`) arrived in age v1.3.0.
- **Python:** [pyrage](https://pypi.org/project/pyrage/) 1.4.0 (2026-08-23), MIT licence, abi3 wheels for **Windows x86-64** (CPython 3.10+), with Trusted Publishing provenance.
  - API: `x25519.Recipient.from_str()`, `encrypt(data, [recipients])`, `decrypt(data, [identities])`, and `passphrase.encrypt/decrypt`.
  - In-memory only (no streaming API shown). That is fine because a running config is kilobytes to a few MB.
  - Plugin (YubiKey) and post-quantum support in pyrage is **not documented**. Decrypt-side use of those features can go through the `age` CLI instead.
- **Key management for one operator:**
  - The **tool holds only recipients (public keys)**, for example in a recipients file next to the exe. A public key is not a credential, so storing it does not conflict with "Credential Sets are never stored".
  - The operator's identity is kept off the Run path: in a passphrase-protected identity file, which `age` supports, or on a YubiKey.
  - **Recovery:** encrypt every Backup to a second recipient whose identity is printed or kept offline in a safe. Losing the daily key then loses nothing.
  - **Sharing:** decrypt one Backup and re-encrypt it to the colleague's `age1…` recipient. Alternatively, add the colleague as a standing recipient.
  - **Rotation:** add a new recipient, and re-encrypt old Backups if needed.
- **Bundled exe:** pure wheel and native extension, with no external binary. PyInstaller one-file mode unpacks code to a temp `_MEI*` folder and its `.pyc` files "could in principle be decompiled" ([PyInstaller operating mode](https://pyinstaller.org/en/stable/operating-mode.html)). That does not matter here, because no secret lives in the exe; recipients are public.
- **Limitations:**
  - age does not authenticate the sender. Anyone with the public key could create a "Backup", so integrity hashes and a run manifest are #12's job.
  - pyrage has one maintainer. If it stalls, the format is standard and another implementation can read the files.

### Passphrase-based symmetric (libsodium/PyNaCl, or pyca/cryptography Fernet / AEAD + Argon2id)

- **Primitives are sound and well-packaged:**
  - [PyNaCl](https://pypi.org/project/PyNaCl/) 1.6.2 bundles libsodium in its Windows wheels.
  - [cryptography](https://pypi.org/project/cryptography/) 50.0.2 has Windows wheels, and [Argon2id since 44.0.0](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/).
  - libsodium `crypto_pwhash` defaults to Argon2id. SENSITIVE (1 GiB, ~3.5 s) is suggested for "highly sensitive data and non-interactive operations" ([libsodium pwhash](https://doc.libsodium.org/password_hashing/default_phf)).
  - `secretstream_xchacha20poly1305` gives truncation-proof file encryption ([libsodium secretstream](https://doc.libsodium.org/secret-key_cryptography/secretstream)).
  - OWASP Argon2id minimum is m=19 MiB, t=2, p=1 (or m=46 MiB, t=1).
- **Fernet** is AES-128-CBC + HMAC-SHA-256. It holds the whole message in memory and leaks the creation timestamp in plaintext. Its docs recommend Argon2id when using passwords ([Fernet](https://cryptography.io/en/latest/fernet/)).
- **Why not:**
  - We would design and own a file format: salt, KDF parameters, version, AEAD framing and nonce handling. AEAD nonces must never repeat ([cryptography AEAD](https://cryptography.io/en/latest/hazmat/primitives/aead/)).
  - No outside tool can read these files.
  - The same secret both writes and reads every Backup, so the operator must type it each Run, and it must be held in memory like a Credential Set.
  - Sharing means sharing the passphrase.
  - A forgotten passphrase loses every Backup.
  - If a passphrase model is ever wanted, age's scrypt recipient gives the same properties in a standard format.

### GPG / OpenPGP

- **Mature and widely known:** public-key encryption, multiple recipients, and smartcards.
- **Python story is weak for a bundled exe:**
  - [python-gnupg](https://gnupg.readthedocs.io/en/latest/) is a `subprocess` wrapper that requires a `gpg` executable and a keyring home directory.
  - Under GnuPG 2.1+, passing passphrases needs `allow-loopback-pinentry` in `gpg-agent.conf`, with known version quirks.
  - On Windows that means installing Gpg4win or shipping GnuPG's binaries, which are GPL-licensed, inside our package.
  - The pure-Python PGPy implements RFC 4880 only.
- **The standard has split:**
  - [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html) (July 2024) obsoletes RFC 4880 and recommends Argon2 S2K.
  - GnuPG follows LibrePGP, and only enables RFC 9580 structures behind an `--allow-9980` option added in 2.5.24 ([GnuPG 2.5.24 announcement](https://lists.gnupg.org/pipermail/gnupg-announce/2026q3/000516.html)).
- **Verdict:** more moving parts and more ambient state than age, for no gain at this scale. Worth reconsidering only if the organisation already mandates PGP keys.

### Windows DPAPI

- `CryptProtectData`: "only a user with the same logon credential as the user who encrypted the data can decrypt the data", and "usually … on the same computer". The exception is roaming profiles. `CRYPTPROTECT_LOCAL_MACHINE` lets **any** user on the PC decrypt. A MAC is included. ([CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata))
- **Recovery:** if the password is reset rather than changed, old DPAPI data cannot be decrypted. On a domain this is recoverable via the DC backup keys ([DPAPI backup keys on AD DCs](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi-backup-keys-on-ad-domain-controllers)). A standalone workstation has no such recovery.
- **Not deprecated, but changing:** the prompt-struct flow is deprecated and will be removed in April 2027 (same CryptProtectData page).
- **Why not as the Backup cipher:**
  - Backups would be bound to one Windows profile on one machine.
  - There is no way to share with a colleague, and no recovery recipient.
  - Any process running as the operator can decrypt with no extra secret.
  - It is invisible to the operator, which is convenient but means "encrypted at rest" is only as strong as the Windows login.
- **Possible supporting role:** protecting a local, non-critical cache. It must never be the only key to a Backup.

## 4. Comparison table

| | age (pyrage) | Passphrase + Argon2id (own format) | GPG | DPAPI |
|---|---|---|---|---|
| Secret needed during a Run | **None** (public recipient) | Passphrase | None (public key), but needs keyring | None (implicit Windows login) |
| Who can decrypt | Holder of an identity | Anyone with the passphrase | Holder of a private key | That Windows user on that PC (or any user with LOCAL_MACHINE) |
| Recovery if key lost | Second offline recipient | None | Second recipient / revocation | Domain backup key only |
| Share one Backup | Re-encrypt to colleague's recipient | Share passphrase | Re-encrypt to colleague's key | Not possible without decrypting |
| Readable without our tool | Yes (`age`/`rage` CLI) | No | Yes (gpg) | No |
| Python on Windows | pyrage wheel, MIT | PyNaCl / cryptography wheels | python-gnupg + external gpg.exe | pywin32 / ctypes |
| Bundled exe | Self-contained | Self-contained | Needs GnuPG binaries + agent | Self-contained |
| Format ownership | Open spec, several implementations | Ours | OpenPGP (split standard) | Microsoft blob |

## 5. Facts that matter to other tickets

- **#4 / #7 (read-only commands, least-privilege roles):** on IOS, `show running-config` below privilege 15 "displays all of the commands that the current user is able to modify". A read-only user therefore gets a nearly empty config. Cisco's documented fix is `show running-config view full` plus raising that command's privilege. From 16.x some platforms also need `file privilege <level>` ([Cisco: Configure Full Running Config for Users with Low Privilege Levels](https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-aggregation-services-routers/212149-Configure-IOS-XE-to-display-full-show-ru.html), [IOS Privilege Levels Cannot See Complete Running Configuration](https://www.cisco.com/c/en/us/support/docs/security-vpn/terminal-access-controller-access-control-system-tacacs-/23383-showrun.html)). The Backup command per Platform must account for this.
- **#6 (Credential Sets):** PAN-OS API keys never expire by default and survive the Run. Prefer a flow that does not leave a long-lived key behind, or document the trade-off. Any obtained key must be handled exactly like a Credential Set.
- **#12 (Backup storage):**
  - Decide the recipients file location and the recovery recipient.
  - Hash or sign over ciphertext, or keep a plaintext hash inside the encrypted envelope, because a plaintext hash of a config lets a guess be confirmed.
  - Keep unencrypted metadata minimal (hostname and timestamp are already a disclosure).
  - Decryption for viewing can be the `age` CLI or a tool subcommand that never writes plaintext to disk.
- **#2 (libraries/packaging):** add pyrage (Windows wheel) to the candidate list. No external binaries are needed for encryption.
- **General:** Python cannot reliably zero `str`/`bytes`, and a crash dump can hold a decrypted config or Credential Set. The crash-dump rule in CLAUDE.md needs an explicit mitigation, for example avoiding full-memory dumps.

## Confidence and gaps

- **High:** age format and behaviour; DPAPI behaviour; Cisco type definitions and plans; PAN-OS master key behaviour; library versions as published on PyPI on 2026-11-17.
- **Medium, verify on recorded output (#8):**
  - Exact keyword forms of the IOS routing-protocol, NTP and keychain lines.
  - The current PAN-OS `phash` format on 10.x–12.x.
  - Which PAN-OS fields appear as master-key ciphertext.
- **Unknown:** whether pyrage exposes age plugins or post-quantum recipients, and whether it can read passphrase-protected identity files. Neither is needed if the tool only encrypts.
