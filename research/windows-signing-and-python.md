# Research: code signing and Python version for the Windows build

Answers the questions on [Code signing and Python version for the Windows build](https://github.com/b-git-hub/network-analyser/issues/29). Researched on 2026-11-18 against primary sources. Every claim cites its source. Anything marked **Not confirmed** could not be traced to a primary source and needs checking before a decision depends on it.

This is a throwaway research note on branch `research/windows-signing-and-python`. It is never merged.

## Summary

| Question | Answer |
| --- | --- |
| Can one person use Azure Artifact Signing? | Yes, but only as an **individual in the United States or Canada**, or as an organisation in a listed country. Needs a paid Azure subscription. Basic tier is **$9.99/month** for 5,000 signatures. |
| Can it sign from GitHub Actions? | Yes, with `azure/artifact-signing-action@v2` on a Windows runner, authenticated with OIDC (recommended). |
| Alternatives | OV/IV certificates whose key is held in a vendor cloud HSM (SSL.com eSigner, DigiCert KeyLocker, Certum SimplySign) or a token. Since 1 March 2026 they are valid for at most 460 days. |
| SmartScreen | **No option avoids the first-download warning.** OV, EV and Artifact Signing all start with no reputation. Signing shows a publisher name and lets reputation carry over between versions. |
| Smart App Control | Blocks unknown **unsigned** binaries. Any binary signed by a CA in the Microsoft Trusted Root Program runs, so every exe, DLL and `.pyd` in the build must be signed. |
| Signing a one-folder build | Sign after PyInstaller finishes, with UPX off. The python.org runtime files are already PSF-signed. The **bootloader exe and every third-party `.pyd` are unsigned** and must be signed by us. A uv-managed (python-build-standalone) runtime is **entirely unsigned**, so build with python.org CPython. |
| Newest CPython that everything supports with Windows wheels | **CPython 3.14** (3.14.10 is current). 3.15 is blocked by PyYAML, a Netmiko dependency, which has no 3.15 Windows wheel. |
| 3.14 support dates | Bugfix releases with binary installers until about Oct 2027 (3.14.16). Source-only security fixes until **Oct 2030** (end of life). |
| `getpass(echo_char="*")` on Windows | It works in a real console (cmd, PowerShell and Windows Terminal all use one). But it **does not handle arrow or function keys**: their two-character codes go into the password and echo two `*`. And when stdin is not the console it **falls back to an echoing read**. Both break the [issue 15](https://github.com/b-git-hub/network-analyser/issues/15) requirements, so we need a small `msvcrt` reader of our own. |

---

## 1. Azure Artifact Signing (formerly Trusted Signing)

### What it is

- A Microsoft-managed signing service. Keys live in "FIPS 140-3 level 3 certified HSMs" and are never handed out. It supports Public Trust, Private Trust, VBS enclave, CI policy and test signing. ([Overview](https://learn.microsoft.com/en-us/azure/artifact-signing/overview))
- "The Authenticode certificate that's used for signing with the profile is never given to you. All certificates are securely stored within the service and are accessible only at the time of signing." ([FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq))
- Certificates are valid for **three days**, so every signature must be timestamped. Microsoft recommends `http://timestamp.acs.microsoft.com/`. ([Signing integrations](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations))
- It does not issue EV certificates and "There's no plan to issue EV certificates in the future." ([FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq))
- You cannot set a custom CN or O. The CN is always the validated legal name. ([FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq))

### Who can use it

- "Public Trust certificates are available to organizations in the United States, Canada, the European Union, the United Kingdom, Australia, New Zealand, Japan, South Korea, Singapore, Switzerland, Norway, and Israel. **Individual developers must be located in the United States or Canada.**" ([Quickstart, prerequisites](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart))
- Free, trial and sponsored Azure subscriptions are not supported. A paid subscription, such as pay-as-you-go, is required. ([FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq))
- For individual validation, the Azure billing account must have Account Type **Individual**, and its legal name and sold-to address must match the government ID. The certificate shows the city, state/province and country, but not the street address or email. ([Quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart))
- **Not confirmed:** earlier write-ups said organisations needed three years of verifiable history. The current quickstart and FAQ do not state such a requirement.

### Identity checks

- **Individual:** you complete a Microsoft Entra Verified ID through AU10TIX: a government photo ID, a Face Check selfie, and email and phone PIN checks. The credential is then held in Microsoft Authenticator and shared with Artifact Signing. A utility bill or bank statement may be asked for as proof of address. ([Quickstart, Individual Developer tab](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart); [FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq))
- **Organisation:** legal name, website, a primary email on the organisation's domain, a business identifier and address, plus a named individual who also completes the individual check. It takes "from 1 to 30 business days", and you get three attempts if more documents are asked for. ([Quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart))
- Identity validation expires and must be renewed. Reminders start 60 days before expiry, and certificate renewal stops if it lapses. ([FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq))
- Identity validation can only be done in the Azure portal, not from the CLI. ([Quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart))

### Cost

| SKU | Price/month | Signatures/month included | Certificate profiles | Overage |
| --- | --- | --- | --- | --- |
| Basic | **$9.99** | 5,000 | 1 of each type | $0.005/signature |
| Premium | $99.99 | 100,000 | 10 of each type | $0.005/signature |

- Quotas and profile counts come from the [pricing page](https://azure.microsoft.com/en-us/pricing/details/artifact-signing/). That page renders prices by script, so the dollar figures come from Microsoft's public [Azure Retail Prices API](https://prices.azure.com/api/retail/prices?$filter=serviceName%20eq%20%27Trusted%20Signing%27) (meter names "Basic Account", "Premium Account" and "Signature Overage", service name still "Trusted Signing", effective 2024-06-01). Microsoft's [SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation) page agrees: "Starts at $9.99/month".
- Billing is not pro-rated: the full monthly SKU amount is charged however late in the month you start. ([FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq))
- For this project, Basic's 5,000 signatures a month is far more than a release needs (roughly 10 to 20 unsigned binaries per build; see §4).

### GitHub Actions

- GitHub Actions is a supported integration, through [`azure/artifact-signing-action`](https://github.com/Azure/artifact-signing-action). ([Signing integrations](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations))
- From the action's README:
  - examples use `@v2`
  - it "can only be executed on Windows runners" (windows-2022 or windows-2025; Windows Arm runners are not supported)
  - OIDC with Azure federated credentials is the recommended authentication; client secret and certificate also work
  - the identity needs the *Artifact Signing Certificate Profile Signer* role
  - inputs `files-folder`, `files-folder-filter` (e.g. `exe,dll,pyd`) and `files-folder-recurse` sign a whole folder
  - `file-digest` defaults to SHA256
  - `timestamp-rfc3161` should be `http://timestamp.acs.microsoft.com`
- For local signing instead of CI: SignTool from Windows SDK ≥ 10.0.2261.755, the .NET 8 runtime and the Artifact Signing dlib, all bundled in `winget install -e --id Microsoft.Azure.ArtifactSigningClientTools`. ([Signing integrations](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations))
- **Not confirmed:** whether the `files-folder-filter` wildcard accepts `pyd`. The README says the filter is a comma-separated extension list, so it should, but check this on the first CI run.

### Evidence that it fits Python builds

The python.org 3.14.10 Windows binaries are signed by **Python Software Foundation**. Their leaf certificate is valid for exactly three days (24 to 27 Oct 2026). It is issued by *Microsoft ID Verified CS EOC CA 04*, under *Microsoft ID Verified Code Signing PCA 2021* and *Microsoft Identity Verification Root Certificate Authority 2020*. We checked this by reading the Authenticode blob of `python314.dll` from [python-3.14.10-embed-amd64.zip](https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip). The three-day validity and the "Microsoft ID Verified" chain match Artifact Signing's documented behaviour, which suggests (we did not confirm it) that CPython itself is signed with Artifact Signing. The FAQ names the same PCA: "Microsoft ID Verified Code Signing PCA 2021".

## 2. Alternatives: OV/IV certificates on a cloud HSM or token

### Rules that apply to every public CA

- Since 2023-06-01 the CA/Browser Forum Code Signing Baseline Requirements (§6.2.7.4.2) say that "CAs SHALL ensure that the Subscriber's Private Key is generated, stored, and used in a suitable Hardware Crypto Module". So a downloadable `.pfx` is no longer possible: it is a token, a vendor cloud HSM, or your own attested HSM. ([CA/B Forum CSBR](https://cabforum.org/working-groups/code-signing/requirements/))
- For certificates issued on or after **1 March 2026**, "the validity period MUST NOT exceed 460 days" (CSBR §6.3.2, ballot CSC-31, BR v3.10). The current version is 3.11.0. ([CA/B Forum CSBR](https://cabforum.org/working-groups/code-signing/requirements/)) Certum notes that multi-year products now need free re-issues. ([Certum shop](https://shop.certum.eu/open-source-code-signing-on-simplysign.html))

### Options open to an individual (prices as listed by each vendor, Nov 2026)

| Vendor / product | Subject | Certificate | Key storage and signing | CI / GitHub Actions |
| --- | --- | --- | --- | --- |
| **SSL.com IV** (Individual Validated) | Individual's verified name, "no business registration required" | $129/yr (falls to $96.75/yr on 5-yr terms) | eSigner cloud HSM. The product page lists Tier 1 at **$15/mo for 240 signings**, but the older [pricing guide](https://www.ssl.com/guide/esigner-pricing/) (updated 2024-05) says $20/mo for 20, so the two disagree. Other options: YubiKey token $379, or bring your own Azure Key Vault Premium/Managed HSM ($75 attestation). | eSigner product page: GitHub Actions via "eSigner CKA + signtool.exe in workflow"; CKA is Windows-only. |
| **DigiCert KeyLocker** (OV) | Organisation (OV); **not confirmed** that DigiCert issues OV to individuals | Price **not confirmed** (not shown in public docs) | DigiCert cloud HSM, through `smctl` or a KSP/PKCS#11 for SignTool | [`digicert/code-signing-software-trust-action@v1`](https://docs.digicert.com/en/digicert-keylocker/ci-cd-integrations-and-deployment-pipelines/plugins/github/binary-signing-using-github-actions.html) on Windows, Ubuntu or macOS runners, with API key and client-certificate secrets. |
| **Certum Open Source Code Signing (SimplySign)** | Natural person, prefixed "Open Source Developer" | €49 (cloud) or €69 (with card) | SimplySign cloud, FIPS 140-2 L3 / CC EAL4+. Needs the SimplySign mobile and desktop apps. 5,000 signatures/month limit. | **Not confirmed.** The product page says nothing about CI, and the mobile-app login suggests interactive use. Meant for open-source software. |

Sources: [SSL.com IV](https://www.ssl.com/products/software-integrity/code-signing/iv/), [SSL.com eSigner](https://www.ssl.com/products/software-integrity/signing-service/), [DigiCert KeyLocker GitHub Actions](https://docs.digicert.com/en/digicert-keylocker/ci-cd-integrations-and-deployment-pipelines/plugins/github/binary-signing-using-github-actions.html), [Certum Open Source in the Cloud](https://shop.certum.eu/open-source-code-signing-on-simplysign.html).

**Comparison for this project:**
- **Artifact Signing** is the cheapest automated option (about $120/yr) and needs no secret beyond OIDC in GitHub Actions. It is only open to an individual living in the US or Canada.
- **Outside those countries**, SSL.com IV with eSigner works from GitHub Actions for about $129/yr plus about $180–240/yr for eSigner. That is roughly 2.5× the cost, and it needs a long-lived eSigner credential stored as a GitHub secret.

## 3. Windows reputation: SmartScreen and Smart App Control

### SmartScreen

- SmartScreen weighs two signals: **publisher reputation** (is it signed, and by a known publisher?) and **file hash reputation**. "Even when signed, a newly created binary could still show a SmartScreen warning until its hash or publisher certificate accumulates sufficient evidence of positive reputation." ([SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation))
- First-download behaviour by certificate type ([same page](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)):
  - Store: no warning.
  - OV/EV: "Warning — app flagged as unrecognized until reputation accumulates; verified publisher name is displayed".
  - Unsigned or self-signed: "Windows protected your PC"; the user must choose "Run anyway", and enterprise policy can block that.
- "**EV certificates no longer bypass SmartScreen.** ... Paying a premium for EV solely to avoid SmartScreen warnings is no longer justified." ([same page](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation))
- Artifact Signing: "reputation accumulates over time based on download volume and behavior". ([same page](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)) The FAQ adds: "The prompt stops appearing once the file hash has sufficient download history." ([FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq))
- How long it takes: "There is no exact threshold, but it can take several weeks and hundreds of clean installs from a wide audience." For a one-operator tool this threshold will probably **never** be reached, so expect the "unrecognized app" prompt on every new release, showing our publisher name. Enterprise admins can submit files through the [Microsoft Security Intelligence portal](https://www.microsoft.com/en-us/wdsi/filesubmission). ([same page](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation))
- Reputation can carry across versions only when they are signed with the same publisher identity. "Use a consistent signing identity." ([same page](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)) **Not confirmed:** how SmartScreen keys publisher reputation when Artifact Signing issues a new three-day certificate every few days. Microsoft's pages say reputation builds; they don't say what it is keyed on.
- SmartScreen checks files that carry the Mark of the Web. A zip downloaded from GitHub Releases and extracted with Explorer passes the mark on to the extracted files. **Not confirmed** against a Microsoft primary source in this research.

### Smart App Control (SAC)

- In enforcement mode, SAC lets a binary run if Microsoft's app intelligence predicts it is safe, **or** if it is "signed with a certificate issued by a certificate authority (CA) within the Trusted Root Program". "Malware, Potentially Unwanted Apps (PUA), and unknown, unsigned code are blocked by default." ([SAC overview](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview))
- SAC "evaluates binaries as it loads them". You should "test all code paths". "Ensuring that you correctly sign all your binaries is the best way to make sure users don't encounter issues." ([Test with SAC](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control)) "Smart App Control signature checks apply to all executable files, not just those downloaded from the Internet." ([SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)) In practice, **every** `.exe`, `.dll` and `.pyd` the frozen app loads must be signed or reputable.
- SAC does not distinguish OV, EV and Artifact Signing: any Trusted Root Program CA counts. Artifact Signing's root (*Microsoft Identity Verification Root CA 2020*) is Microsoft's own, and the python.org binaries signed through it are part of every CPython install. **Not confirmed:** an explicit Microsoft statement that SAC accepts Artifact Signing. It is implied by the "Trusted Root Program" rule.
- "Recent Windows updates allow Smart App Control to be enabled without requiring a clean installation." ([Microsoft Support: What is Smart App Control](https://support.microsoft.com/en-us/topic/what-is-smart-app-control-285ea03d-fa88-4d56-882e-6698afdb7003)) This means operator PCs may have SAC on even when they were not clean-installed. **Not confirmed:** the minimum build. Secondary sources give 26100.8116 / 26200.8116 (April 2026 update), but no Microsoft page lists it.
- To test: apply the `SmartAppControlAuditNoISG.bin` policy, which ignores cloud reputation and so tests signing alone, then read CodeIntegrity events 3076 (audit) and 3077 (enforce). ([Test with SAC](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control))

## 4. Signing every exe and DLL in a PyInstaller one-folder build

### What PyInstaller does

- PyInstaller's docs cover code signing only for macOS (`--codesign-identity`). It has **no Windows signing step**, so we sign after the build. (PyInstaller 6.22.3 `doc/feature-notes.rst`, `doc/usage.rst`; [docs](https://pyinstaller.org/en/stable/feature-notes.html#macos-binary-code-signing))
- During the build PyInstaller writes the icon, version resource and manifest into the exe, then appends the PKG archive and updates the PE checksum and timestamp (`PyInstaller/building/api.py`, v6.22.3). **The exe must therefore be signed last**, after `COLLECT`, and never touched again. Microsoft says the same: "Avoid modifying files after signing". ([SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation))
- The bootloader finds its archive with a "full back-to-front file search for MAGIC" so that it still works with "extra appended data after embedded package (e.g., digital signature)" (PyInstaller CHANGES, [issue 2372](https://github.com/pyinstaller/pyinstaller/issues/2372)). A signed onedir exe still runs.
- **Turn UPX off (`--noupx`).** When UPX is on PATH, PyInstaller compresses each collected DLL and `.pyd` with it. That rewrites binaries, which strips the python.org signatures, and "may end up corrupting a collected shared library", for example DLLs with Control Flow Guard. (PyInstaller [usage: Using UPX](https://pyinstaller.org/en/stable/usage.html#using-upx)) Also leave `--strip` off.

### What is already signed and what is not (checked 2026-11-18)

We read the PE security directory of each file. The checker is at `scratchpad/scripts/sigcheck.py` and was not committed.

| Origin | Files | Signed? |
| --- | --- | --- |
| python.org CPython 3.14.10 (embeddable zip, same binaries as the installer) | `python314.dll`, `python3.dll`, all stdlib `.pyd` (`_ssl`, `_socket`, `_hashlib`, `_ctypes`…), `libcrypto-3.dll`, `libssl-3.dll`, `libffi-8.dll`, `sqlite3.dll` | **Signed: Python Software Foundation** (Artifact Signing chain; `libffi-8.dll` via DigiCert) |
| python.org bundle | `vcruntime140.dll`, `vcruntime140_1.dll` | Signed: Microsoft |
| **uv-managed CPython** (python-build-standalone `cpython-3.14.6+20260718-x86_64-pc-windows-msvc-install_only_stripped`, what `uv python install` fetches) | `python.exe`, `python314.dll`, `_ssl.pyd`, `libcrypto-3-x64.dll` | **UNSIGNED** (only `vcruntime140.dll` is signed) |
| PyInstaller 6.22.3 wheel (bootloader) | `run.exe`, `runw.exe` (become our `network-analyser.exe`) | **UNSIGNED** |
| cryptography 50.0.2 | `_rust.pyd` | **UNSIGNED** |
| pyrage 1.4.0 | `pyrage.pyd` | **UNSIGNED** |
| bcrypt 5.0.0 / PyNaCl 1.6.2 / cffi 2.1.1 / PyYAML 6.0.3 | `_bcrypt.pyd`, `_sodium.pyd`, `_cffi_backend…pyd`, `_yaml…pyd` | **UNSIGNED** |

### Recipe

1. **Build with python.org CPython, not uv's managed Python.** Otherwise the interpreter DLL and every stdlib extension in `_internal\` are unsigned, and SAC would block them. In uv, pin to the system interpreter, e.g. `uv venv --python <path to python.org python.exe>` with `python-preference = "only-system"`. On GitHub Actions, `actions/setup-python` for Python < 3.16 uses "official Python executables ... simply downloaded from python.org". ([actions/python-versions](https://github.com/actions/python-versions)) Note that [PEP 773](https://peps.python.org/pep-0773/) retires the traditional `.exe` installer by 3.16, but the NuGet packages continue.
2. Run `pyinstaller --onedir --noupx` with no `--strip`.
3. Sign **every unsigned PE file** under `dist\network-analyser\`: the exe and every `.dll` and `.pyd` that has no valid signature. Leave PSF- and Microsoft-signed files alone. Re-signing them is allowed (SignTool appends or replaces the signature) but not needed. **Not confirmed:** whether replacing the PSF signature on a python.org DLL changes SmartScreen or SAC behaviour. Keeping them as shipped is the safer default.
   - With the GitHub Action: `files-folder: dist/network-analyser`, `files-folder-filter: exe,dll,pyd`, `files-folder-recurse: true`. That also re-signs PSF files, which is acceptable.
   - For exact control, use SignTool with `/fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256` on a list built by `signtool verify /pa` failures. ([Signing integrations](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations))
4. Check: run `signtool verify /pa /all` on every PE file and fail the build on any unsigned one. Then zip. The zip itself cannot carry an Authenticode signature.
5. Before the first release, test on a PC with SAC in evaluation mode plus the `SmartAppControlAuditNoISG` policy, and confirm no 3076 events. ([Test with SAC](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control))
6. Do not sign anything that could be seen as a PUA ([SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)). A credentialed network crawler is legitimate, but the signing identity carries its reputation.

## 5. CPython version

### Package support (PyPI JSON API, 2026-11-18)

| Package (latest) | Requires-Python | Classifiers | Windows x64 wheel | Works on 3.14? | Works on 3.15? |
| --- | --- | --- | --- | --- | --- |
| [PyInstaller 6.22.3](https://pypi.org/project/pyinstaller/) | `>=3.8,<3.16` | 3.8–3.15 | `py3-none-win_amd64` | Yes (3.14 support added in 6.15.0) | Yes (added in 6.21.0) |
| [Netmiko 4.8.0](https://pypi.org/project/netmiko/) | `>=3.10,<4.0` | 3.10–3.14 | pure (`py3-none-any`) | Yes | Not declared |
| [Paramiko 5.1.0](https://pypi.org/project/paramiko/) | `>=3.9` | 3.9–3.15 | pure | Yes | Yes |
| [cryptography 50.0.2](https://pypi.org/project/cryptography/) | `>=3.9` (not 3.9.0/3.9.1) | 3.9–3.15 | `cp311-abi3`, `cp315-abi3.abi3t`, `cp314t` | Yes | Yes |
| [pyrage 1.4.0](https://pypi.org/project/pyrage/) | `>=3.10` | none | `cp310-abi3-win_amd64` | Yes (abi3) | Yes (abi3, not free-threaded) |
| [TextFSM 2.1.1](https://pypi.org/project/textfsm/) | none | none | pure | Yes | Yes |
| [ntc-templates 9.3.0](https://pypi.org/project/ntc-templates/) | `>=3.10,<4.0` | 3.10–3.14 | pure | Yes | Not declared |
| Transitive: [bcrypt 5.0.0](https://pypi.org/project/bcrypt/) | `>=3.8` | to 3.14 | `cp39-abi3` | Yes | Yes (abi3) |
| Transitive: [PyNaCl 1.6.2](https://pypi.org/project/PyNaCl/) | `>=3.8` | to 3.14 | `cp38-abi3` | Yes | Yes (abi3) |
| Transitive: [cffi 2.1.1](https://pypi.org/project/cffi/) | `>=3.10` | to 3.15 | `cp314`, `cp315` | Yes | Yes |
| Transitive (Netmiko): [**PyYAML 6.0.3**](https://pypi.org/project/PyYAML/) | `>=3.8` | to 3.14 | `cp310`…`cp314` only | Yes | **No 3.15 wheel** (sdist only) |

The data comes from `https://pypi.org/pypi/<name>/json` for each package. Other transitive dependencies (`pyserial`, `scp`, `rich`, `invoke`, `markdown-it-py`, `pygments`) are pure Python.

**Result: CPython 3.14 is the newest version on which every listed package, and every transitive dependency, ships a Windows x64 wheel.** On 3.15, PyYAML (required by Netmiko) would have to build from its sdist. That breaks a binary-only, hash-locked uv install. Netmiko and ntc-templates also do not yet declare 3.15. Use the regular (GIL) build, not the free-threaded `3.14t`: pyrage ships only an abi3 wheel, and abi3 does not cover free-threaded builds.

### Dates

| Version | Status (2026-11-18) | First release | Last bugfix release with binary installers | End of life |
| --- | --- | --- | --- | --- |
| 3.15 | bugfix (3.15.2 current) | 2026-10-09 | — | Oct 2031 (scheduled) |
| **3.14** | **bugfix (3.14.10 current, released 2026-10-25)** | 2025-10-07 | **3.14.16, about 2027-10-05** | **Oct 2030** (scheduled) |
| 3.13 | security | 2024-10-07 | ended | Oct 2029 |

Sources:
- [devguide versions](https://devguide.python.org/versions/)
- [PEP 745 (3.14 schedule)](https://peps.python.org/pep-0745/): bugfix releases "approximately every two months for approximately 24 months"; 3.14.11 expected 2026-12-01; 3.14.16 on 2027-10-05 is "the final regular bugfix release with binary installers"; after that, source-only security fixes "until October 2030"
- python.org release API (`/api/v2/downloads/release/`) for the current point releases

After about October 2027, 3.14 security fixes come as source only, with no Windows binaries. From then on the build either stays on the last 3.14 binary or moves to 3.15 (once PyYAML ships 3.15 wheels) or a later version.

## 6. The `*`-masked prompt

### Does `getpass(echo_char="*")` work in Windows consoles?

- The 3.14 docs: "Changed in version 3.14: Added the *echo_char* parameter", and "*echo_char* must be a single printable ASCII character and each typed character is replaced by it". The line-editing caveat in the docs is for Unix only. ([getpass docs](https://docs.python.org/3.14/library/getpass.html); [What's New 3.14](https://docs.python.org/3.14/whatsnew/3.14.html), [gh-77065](https://github.com/python/cpython/issues/77065))
- On Windows, `getpass.getpass` is `win_getpass`. We read [`Lib/getpass.py` at v3.14.10](https://github.com/python/cpython/blob/v3.14.10/Lib/getpass.py); it is identical at v3.14.0, and v3.15.2's `win_getpass` is unchanged, since the 3.15 line-editing work is Unix-only. The function:
  - writes the prompt with `msvcrt.putwch`, then loops on `msvcrt.getwch()`;
  - stops on `\r` or `\n`;
  - raises `KeyboardInterrupt` on `\x03`;
  - on `\b`, removes the last character and erases one `*` with `\b \b`;
  - **appends everything else** to the password and echoes `echo_char`.
- `_getwch` reads "a single character from the console without echoing". For "a function key or arrow key ... The first call returns `0` or `0xE0`. The second call returns the key scan code." ([MS CRT `_getch, _getwch`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/getch-getwch))
- cmd, PowerShell (console host) and Windows Terminal all give the process a real Windows console, so `msvcrt` works in all three. **Not confirmed** by a single Microsoft page covering all three; test on the sandbox, as issue 15 already plans.

**Conclusion: it works, but it does not meet issue 15's requirements:**

1. **Arrow and function keys are not handled.** Reading the code against the CRT contract: pressing ← adds `'\xe0'` plus a scan-code character to the password and prints `**`. The password is silently corrupted. This is inferred from the source, so confirm it on Windows.
2. **It can fall back to echoing.** If `sys.stdin is not sys.__stdin__`, `win_getpass` calls `fallback_getpass`, which warns "Password input may be echoed" and reads from `sys.stdin` with echo. A secret could then appear on screen or in a captured stream. That is against CLAUDE.md, so the tool must refuse instead.
3. Ctrl+C: the code expects `getwch()` to return `'\x03'`, but the `msvcrt` docs say for `getch()` that "The Control-C keypress cannot be read with this function" ([msvcrt docs](https://docs.python.org/3.14/library/msvcrt.html)). **Not confirmed** which happens. Either way Python ends up raising `KeyboardInterrupt`, but check on the sandbox that no traceback leaks and that the Run is cancelled cleanly.
4. Paste: pasted text arrives as ordinary key events, one `*` per character, which is what issue 15 wants. **Not confirmed** for conhost's right-click and Ctrl+V paste; test on the sandbox.
5. `echo_char` must be a single printable ASCII character, or it raises `ValueError` ([gh-138514](https://github.com/python/cpython/issues/138514)). `"*"` is fine.

### What our own `msvcrt` reader needs

A small loop on `msvcrt.getwch()`, modelled on `win_getpass` but stricter:

- **Refuse, never fall back.** If stdin or stdout is not an interactive Windows console (`sys.stdin.isatty()` is False, `sys.stdin is not sys.__stdin__`, or `msvcrt` is missing), stop the Run before any secret is asked for. Never call `getpass.fallback_getpass` or `input()`.
- **Enter:** `'\r'` or `'\n'` ends input. Refuse an empty password, as issue 15 decided.
- **Ctrl+C:** `'\x03'` raises the tool's own cancel, giving the clean "Run cancelled, nothing saved" path with no traceback. Also catch `KeyboardInterrupt` around the loop, in case the console delivers Ctrl+C as a signal instead.
- **Backspace:** `'\b'` removes the last character and, only if one was removed, writes `\b \b`.
- **Arrow and function keys:** on `'\x00'` or `'\xe0'`, read **one more** `getwch()` and throw both away, with no echo. ([MS CRT `_getwch`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/getch-getwch)) Optionally ring the bell with `'\a'`.
- **Other control characters** (`< ' '`, e.g. Ctrl+Z `\x1a`, Esc `\x1b`, Tab): drop them, or treat Esc as "clear". Never add them to the secret.
- **Echo:** write exactly one `*` per accepted character with `msvcrt.putwch`, which goes to the console itself, not to stdout or a log, and then `\r\n` at the end. Never write the typed characters anywhere.
- **Characters outside the BMP:** `_getwch` returns UTF-16 code units, so an emoji arrives as two surrogates. Join the halves (`s.encode('utf-16','surrogatepass').decode('utf-16')`) before using the string, and print one `*` per code point. This is an edge case, inferred and not tested.
- **Memory:** a Python `str` cannot be wiped. Keep the secret in one variable for the Run, as ADR 0004 already accepts. The crash-dump check covers the remaining risk.
- **Test matrix on the booked sandbox:** cmd (conhost), PowerShell (conhost), Windows Terminal. In each, try typing, Backspace, ←/→/Home/Del/F1, Ctrl+C, Ctrl+V and right-click paste, and a password-manager auto-type.

Using the stdlib `getpass(echo_char="*")` would only be acceptable with a wrapper that does the console check first (point 2). Even then the arrow-key problem (point 1) remains, so **our own reader is the recommendation**.

## Not confirmed, to check before deciding

- Whether SmartScreen publisher reputation carries across Artifact Signing's rotating three-day certificates.
- An explicit Microsoft statement that SAC accepts Artifact Signing signatures. It is implied by the Trusted Root Program rule, and CPython's own binaries rely on it.
- The minimum Windows 11 build that lets SAC be turned on without a clean install.
- DigiCert KeyLocker pricing, and whether DigiCert issues OV to individuals. Whether Certum SimplySign can sign unattended in CI.
- SSL.com eSigner Tier 1: the two SSL.com pages disagree ($15/240 signings against $20/20).
- How `getwch()` handles Ctrl+C, and the arrow-key corruption in `win_getpass`. Both are inferred from source and docs; confirm on Windows.
