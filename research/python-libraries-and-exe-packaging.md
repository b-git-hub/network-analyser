# Python network automation libraries and packaging as a Windows exe

Research for [issue #2](https://github.com/b-git-hub/network-analyser/issues/2). Researched 2026-11-17. Every version, date and licence below comes from PyPI JSON metadata (`https://pypi.org/pypi/<name>/json`), the project's own repository, or vendor documentation, as cited. Nothing here was built or run: no exe was produced, so size and start-up figures are bounds, not measurements.

## Answer

- **Device access:** build on **Netmiko 4.8.x** (with Paramiko 5.x underneath) for SSH to all three Platforms. Use **TextFSM and ntc-templates** for structured output, plus NX-OS's native `| json` where a command supports it. For the PAN-OS HTTPS API, use **pan-python** (`pan.xapi.PanXapi`) with an explicit, verifying `ssl.SSLContext`. Run concurrency with the standard library's `concurrent.futures.ThreadPoolExecutor`.
- **Do not build on** Scrapli, Genie/pyATS, NAPALM, Nornir, or pan-os-python. The reasons, in short:
  - Scrapli 2.x and pyATS/Genie publish no Windows builds at all.
  - pan-os-python silently turns off TLS certificate checks and gives you no way to turn them back on.
  - NAPALM and Nornir add weight, write-capable features and stale or legacy plugins, but nothing this tool needs.
- **Packaging:** use **PyInstaller ≥ 6.22.3**, Authenticode-signed. Nuitka is a credible fallback but costs more to set up. Expect antivirus and SmartScreen friction whichever tool you choose. Signing with a stable publisher identity is the only lever that reliably improves it over time, and it never removes the friction on day one.

## 1. Libraries for talking to devices

### 1.1 Comparison

| Library | Latest (PyPI) | Licence | Windows | Platforms relevant here | Concurrency model | Structured output | Verdict |
|---|---|---|---|---|---|---|---|
| **Netmiko** | 4.8.0, 2026-09-21 | MIT | Yes (pure-Python wheel on Paramiko) | IOS, IOS-XE, NX-OS: "regularly tested"; PAN-OS: "limited testing" [N1] | Synchronous, blocking; one connection per thread | `send_command(use_textfsm=True / use_ttp=True / use_genie=True)` [N2] | **Use** |
| **Scrapli** (2.x, "scrapli2") | 2026.11.12 | MIT | **No.** Owner: "Windows has never and will never be supported" [S3] | Platform definitions are YAML [S1] | Sync, plus async via epoll/kqueue in libscrapli [S4] | TextFSM/Genie helpers | **Reject** |
| Scrapli 1.x (legacy) | 2026.2.20 (last pure-Python release) [S2] | MIT | Partly (paramiko/ssh2/asyncssh transports; the default `system` transport is Unix-only) | IOS-XE, NX-OS (core); PAN-OS via scrapli-community | Sync and asyncio | TextFSM/TTP/Genie | **Reject**: frozen, no fixes coming [S4] |
| **Nornir** | 3.6.1, 2026-10-30 | Apache-2.0 | Yes | None of its own; needs a connection plugin | `ThreadedRunner` = `ThreadPoolExecutor`, 20 workers by default [R1] | Whatever the plugin returns | **Reject** (see 1.4) |
| **NAPALM** | 5.2.0, 2026-07-27 | Apache-2.0 | Yes | Core: `ios` (via Netmiko), `nxos` (NX-API), `nxos_ssh` (via Netmiko). PAN-OS only through community `napalm-panos` 0.7.1 [M1][M2] | Synchronous | Normalised getters; LLDP only, **no CDP getter** [M1] | **Reject** (see 1.5) |
| **pan-os-python** | 1.13.1, 2026-07-22 | ISC | Yes | PAN-OS, Panorama | Synchronous | Object model over the XML API | **Reject**: no TLS verification (see 1.3) |
| **pan-python** | 0.26.0, 2026-06-18 | ISC | Yes (pure Python, no dependencies) | PAN-OS XML API, keygen | Synchronous | Raw XML / `xml_python()` | **Use**, with an explicit `ssl_context` |
| **TextFSM** | 2.1.1, 2026-11-10 | Apache-2.0 | Yes (pure Python) | n/a (parser engine) | n/a | Tables from templates | **Use** |
| **ntc-templates** | 9.3.0, 2026-09-14 | Apache-2.0 | Yes (data files) | 143 `cisco_ios_*`, 82 `cisco_nxos_*`, 21 `paloalto_panos_*` templates [T1] | n/a | Lists of dicts | **Use** |
| **Genie / pyATS** | 26.10, 2026-11-03 | Apache-2.0 | **No.** Wheels for Linux and macOS only; docs list Linux and macOS as tested [G1][G2] | Very broad Cisco parser library | n/a | Rich nested dicts | **Reject** |

PyPI data was taken on 2026-11-17 from each project's JSON endpoint, e.g. https://pypi.org/pypi/netmiko/json.

### 1.2 Netmiko: why it fits, and how to configure it safely

- **Maintained and moving.** There were releases in 2024-07, 2024-12, 2025-06, 2026-05 and 2026-09 [N3]. Release 4.8.0 added Paramiko 5 support and a fix that removes Netmiko's `SecretsFilter` when a connection fails, and it brought in bandit and pip-audit in CI [N3]. The README states Python 3.11–3.15 [N4]; PyPI metadata says `>=3.10`.
- **Everything installs from Windows wheels.** The Netmiko stack resolves to pure-Python or `win_amd64` wheels: netmiko, paramiko, cryptography, bcrypt, pynacl, cffi, textfsm, ntc-templates, pyyaml, rich, pygments, pyserial, scp, invoke. Together they come to **about 7.4 MB of compressed wheels**, and nothing needs a compiler.
- **Its defaults are not secure-first, so these are mandatory settings for this project** (all from `netmiko/base_connection.py` [N2]):
  - `ssh_strict` defaults to `False`, which installs Paramiko's `AutoAddPolicy` and silently trusts any host key. The tool must pass `ssh_strict=True` (which installs `RejectPolicy`) and supply known keys through `alt_host_keys` / `alt_key_file` or `system_host_keys`. How keys are first learned is a decision for the host-key ticket.
  - `allow_agent` defaults to `False`. Keep it that way.
  - `session_log` records everything read from the channel, including running configs. Never enable it in the product. Netmiko already strips the `password` and `secret` values from its own `logging` output through `SecretsFilter`.
- **Structured output.** `send_command(..., use_textfsm=True)` looks up a template by platform and command in ntc-templates. For `cisco_xe` it falls back to the `cisco_ios` templates when no XE-specific template exists [N5]. ntc-templates has none prefixed `cisco_xe_` [T1].
- **Threads, not asyncio.** Netmiko has no async API, so parallel Runs use threads. That is fine here: SSH work is I/O-bound and Paramiko releases the GIL while it waits on sockets.

### 1.3 PAN-OS: pan-python, not pan-os-python

- pan-python's `PanXapi` takes an `ssl_context` argument. When it is `None`, the library does this:
  ```python
  # don't perform certificate verification
  kwargs['context'] = ssl._create_unverified_context()
  ```
  The code is unchanged from v0.17.0 to v0.26.0 [P1][P2].
- pan-os-python builds its API client in `PanDevice.generate_xapi()` from only `api_key, hostname, port, timeout` and **never passes an `ssl_context`** [P3]. Every pan-os-python connection therefore skips TLS certificate verification, and the library has no option to change that. Long-open upstream issues ask about certificate handling (#87, #120, #554) [P4].
- pan-os-python 1.13.1 also pins `pan-python ^0.17.0` [P5]. That is the 2022-03 release; pan-python has since reached 0.26.0 [P6].
- **Recommendation:** call `pan.xapi.PanXapi` directly, always with a verifying `ssl.SSLContext`. Pin the device's management certificate, because PAN-OS management certificates are often self-signed. How a certificate is first trusted belongs with the host-key / trust ticket.
- `PanXapi` defaults to `use_get=False` [P1], so `keygen` sends the Credential Set in a POST body rather than in the URL.
- Netmiko's `paloalto_panos` SSH driver also works, but it is only at "limited testing" tier [N1]. Prefer the XML API for PAN-OS and keep SSH as the fallback.
- ntc-templates covers `show lldp neighbors all`, `show system info`, `show arp all`, `show interface all` and `show routing route` for PAN-OS [T1]. PAN-OS has no CDP template.

### 1.4 Nornir: little gain, real cost

- Nornir's threaded runner is essentially a `ThreadPoolExecutor(num_workers=20)` [R1]. That is one standard-library call this tool can make itself.
- **The Windows-viable plugins are weak:**
  - `nornir_netmiko` last released 1.0.1 on 2023-12-07, and its repository was last pushed 2024-04-05 [R2].
  - `nornir_scrapli` pins `scrapli<2026.2.21` (legacy scrapli), with the comment "scrapli 2.0 … is not supported yet" [R3].
- **Security frictions:**
  - Nornir's logging is on by default and writes `nornir.log` to the working directory [R4].
  - Its `Host` inventory model carries `password` as an attribute [R5].

  Both are workable, but they cut against the "Credential Sets are never stored" rule for no functional gain.

### 1.5 NAPALM: designed for configuration management, which this tool must not do

- Its `ios` and `nxos_ssh` drivers sit on Netmiko anyway [M1].
- Installing it pulls in junos-eznc, pyeapi, ncclient, lxml, ttp and netutils [M3], none of which this tool needs.
- Its getter matrix has `get_lldp_neighbors_detail` but no CDP getter [M1]. CDP is half of the crawl.
- It exposes `load_*_candidate` / `commit_config`, so it can write to devices, and the read-only guarantee would then rest on discipline rather than on the library.
- PAN-OS support exists only through the community `napalm-panos` (0.7.1, 2026-06-11).

### 1.6 Scrapli and Genie: blocked on Windows

- **Scrapli.** Since 2026.10.3, scrapli is a ctypes wrapper over **libscrapli**, a Zig library with libssh2 and pcre2 underneath [S1]. Every 2.x release ships wheels only for macOS (arm64) and Linux glibc/musl (x86_64, aarch64) [S2].
  - Windows requests were closed by the owner with "Windows has never and will never be supported" ([scrapli#406](https://github.com/carlmontanari/scrapli/issues/406); see also [#393](https://github.com/carlmontanari/scrapli/issues/393)).
  - Legacy 1.x (2026.2.20) is the "last release w[ith]" asyncssh. A reported MITM concern with `auth_strict_key` on that transport was closed without a fix for that reason ([scrapli#386](https://github.com/carlmontanari/scrapli/issues/386)) [S4].
- **Genie / pyATS.** Every recent `genie` and `pyats` release ships only `manylinux`, `musllinux` and `macosx` wheels, with no `win_amd64` and no sdist [G1]. pyATS docs list Linux and macOS as the tested platforms [G2]. Netmiko's `use_genie=True` is therefore unusable on Windows.

### 1.7 Structured output strategy per Platform

| Platform | Primary | Notes |
|---|---|---|
| IOS / IOS-XE | SSH + TextFSM (ntc-templates `cisco_ios_*`) | Templates exist for `show cdp neighbors detail`, `show lldp neighbors detail`, `show mac-address-table`, `show ip arp`, `show interfaces switchport`, `show vlan`, `show ip route`, `show ip ospf neighbor`, `show ip eigrp neighbors`, `show ip bgp summary`, `show version`, `show inventory` [T1]. |
| NX-OS | SSH + `show … \| json` where supported; TextFSM (`cisco_nxos_*`) otherwise | Cisco: "most commands" support JSON/XML output, testable with `\| validate-json` [C1]. JSON avoids template drift. NX-API (HTTPS) needs `feature nxapi`, a device config change, so it is out of scope unless already enabled. |
| PAN-OS | XML API via pan-python (op commands return XML) | Running config: op `show config running`. LLDP: `show lldp neighbors all`. |

TextFSM templates are community-maintained and break when output formats change. Fixtures must be sanitised or synthetic (per CLAUDE.md), and template output should be checked by tests.

### 1.8 Paramiko 5 removes SHA-1: older devices may become Unvisited Devices

Paramiko 5.0.0 (2026-05-09) removed:
- SHA-1 key exchange, including `diffie-hellman-group1-sha1`;
- RSA signatures with SHA-1 (`ssh-rsa`);
- GSSAPI.

It also raised the group-exchange minimum modulus to 2048 bits [K1]. Paramiko 4.0.0 had already removed DSA keys [K1].

- **Consequence:** a device that offers only `diffie-hellman-group14-sha1` key exchange or only an `ssh-rsa` host-key signature cannot be logged into. The tool should report it as an Unvisited Device ("unsupported").
- Recent IOS-XE 17.x defaults include `rsa-sha2-512 rsa-sha2-256` host keys [C2]. Older trains and older NX-OS need checking.
- Netmiko accepts `paramiko>=3.5.1` [N6], so pinning Paramiko 4.x would bring SHA-1 back. That trades security for reach, so under CLAUDE.md it needs an explicit decision.

## 2. Packaging as a Windows exe

### 2.1 Comparison

| Tool | Latest | Licence (and what it means for the exe) | Single exe on Windows | Notes |
|---|---|---|---|---|
| **PyInstaller** | 6.22.3, 2026-09-12 | GPL-2.0+ with bootloader exception: "The executable bundles generated by PyInstaller from your source code can be shipped with whatever license you want" [I1] | Yes (`--onefile`) | Python 3.8–3.15 [I2]. Hooks for `cryptography`, `bcrypt`, `nacl` ship in pyinstaller-hooks-contrib [I3]. **Recommended.** |
| **Nuitka** | 4.3.5, 2026-11-08 | **AGPL-3.0** with the "Nuitka Runtime Library Exception", which lets compiled output be "conve[yed] … under terms of your choice" [U1][U2] | Yes (`--mode=onefile`) | Compiles to C, so it needs a C compiler. MinGW64 "does not work with Python 3.13 or higher", which leaves MSVC 2022+ (or Zig/clang-cl) [U3]. **Fallback.** |
| cx_Freeze | 8.7.4, 2026-10-27 | PSF-2.0 | **No.** Single-file "is not supported by cx_Freeze" on Windows; it offers `bdist_msi` instead [X1] | Only fits if an MSI installer becomes acceptable. |
| PyOxidizer | 0.24.0, 2022-12-30 | MPL-2.0 | Yes | No release since 2022; repository last pushed 2024-12. **Dormant; reject.** |
| Briefcase | 0.4.7 | BSD-3-Clause | No (MSI/app installers) | Status "4 - Beta"; aimed at installers, not a portable exe. |

### 2.2 Native dependencies (cryptography, Paramiko and friends)

- `cryptography` 50.0.2 ships `cp39-abi3-win_amd64` wheels, which work for every Python 3.9+. `bcrypt` 5.0.0 and `pynacl` 1.6.2 ship `abi3-win_amd64` wheels, and `cffi` 2.1.1 ships per-version Windows wheels.
- Nothing needs a local compiler under PyInstaller.
- Hooks for `cryptography`, `bcrypt` and `nacl` exist in pyinstaller-hooks-contrib [I3].
- **There is no hook for `ntc_templates` or `textfsm`** [I3], and the templates are data files that Netmiko finds through `importlib.resources` or the `NET_TEXTFSM` environment variable [N5]. The build must add `--collect-data ntc_templates`, or the TextFSM lookups will fail only at runtime.
- Nuitka has the equivalent `--include-package-data` [U3].

### 2.3 Antivirus false positives

- PyInstaller's own position: there is "no magic `--i-am-not-malware` option". Heuristic AV "respond[s] by blocking anything PyInstaller", and false positives should go to the AV vendor (e.g. Microsoft's submission portal) [I4].
- PyInstaller lists three mitigations [I4][I5]:
  - report false positives to the vendors;
  - recompile the bootloader yourself (an option "to avoid anti-virus false positives that result from the wide-spread use of pre-compiled bootloaders");
  - buy a code-signing certificate.
- Its maintainers also note that `--windowed` builds draw higher detection rates [I4].
- Nuitka: "Binaries compiled on Windows with default settings … might be recognized by some AV vendors as malware … only in Nuitka commercial there is actual support and instructions for how to do it" [U3].
- At build time, Defender and the indexer can lock fresh binaries. Nuitka advises excluding the build directory [U3], and PyInstaller added retry logic for AV interference in 6.3.0 and 6.11.1 [I2].

### 2.4 SmartScreen, Smart App Control and code signing

- **EV certificates no longer bypass SmartScreen.** Microsoft says the instant bypass "was removed in 2024", so OV, EV and Azure Artifact Signing (formerly Trusted Signing) all start with warnings until reputation builds [W1][W2].
- **Reputation is per file hash and per publisher certificate.** Signing every release with the same identity lets later releases inherit reputation. An unsigned exe starts at zero on every build [W2].
- **Smart App Control** on Windows 11 "will block execution of unsigned files unless the file has a positive reputation" [W2]. An unsigned exe may simply not run on such machines.
- **Signing options** [W1]:

  | Option | Cost | Availability / notes |
  |---|---|---|
  | Azure Artifact Signing | about US$9.99/month | Organisations in the US, Canada, EU and UK; individuals in the US and Canada only |
  | OV certificate | US$150–300/year | Private key must be held on an HSM or token |
  | Self-signed certificate | Free | Only for enterprises that push the certificate as trusted through Intune or GPO |

- In managed enterprises, IT can submit files for review, and "Trusted Intranet locations" are exempt from SmartScreen [W2].

### 2.5 Exe size and start-up time (not measured)

- **Size.** The third-party stack is about 7.4 MB of compressed wheels (see 1.2). The final size will be dominated by the bundled CPython runtime and whatever diagram or GUI library the Topology ticket picks. **Measure this in a prototype; no figure is given here.**
- **Start-up, PyInstaller `--onefile`.** The exe unpacks itself into `%TEMP%\_MEIxxxxxx` on every launch and deletes it on exit, so it starts slower than `--onedir`. The folder is left behind if the process crashes or is killed [I6].
- **Start-up, Nuitka onefile.** Nuitka unpacks to `{TEMP}/onefile_{PID}_{TIME}` by default. It can instead cache to a fixed `{CACHE_DIR}/…` path to avoid re-unpacking, which also keeps Windows Firewall from seeing "a different" binary each Run [U3].
- **Security of the onefile temp extraction:**
  - PyInstaller warns that a local attacker could tamper with the extracted libraries, and says "Do *not* give administrator privileges to a one-file executable on Windows" [I6].
  - GHSA-9fxf-4qw3-ghmr (high severity, fixed in 6.22.1, published 2026-08-15) was a local privilege escalation through spoofed environment variables for privileged onefile executables [I7]. Pin PyInstaller ≥ 6.22.3.
  - The tool needs no admin rights (SSH and HTTPS only), so it should declare `asInvoker`.
- **Code confidentiality.** PyInstaller removed bytecode encryption (`--key`) in 6.0 [I2], and bundled `.pyc` files can be decompiled [I6]. That is acceptable: the tool's safety rests on no secrets being in the code, not on hiding the code.

## 3. Licensing summary for the bundled exe

| Component | Licence |
|---|---|
| Netmiko, scrapli, ttp, rich, pyyaml | MIT |
| cffi | MIT-0 |
| TextFSM, ntc-templates, cryptography (Apache-2.0 OR BSD-3), bcrypt, PyNaCl, Nornir, NAPALM | Apache-2.0 |
| pan-python, pan-os-python | ISC |
| pyserial, invoke, pygments | BSD |
| **Paramiko** | **LGPL-2.1** |
| **scp** | **LGPL** |
| asyncssh (not recommended) | EPL-2.0 OR GPL-2.0+ |

All licences are from PyPI metadata.

**Point for the packaging decision:** Paramiko and `scp` are LGPL. Distributing an exe that bundles them carries the LGPL's obligations: the licence text, source availability, and the user's ability to replace the library. `--onedir` makes "replace the library" trivial; `--onefile` makes it harder. For an internal tool that is never distributed outside the organisation this may not matter. This is not legal advice, so confirm before any external distribution. PyInstaller's and Nuitka's own licences place no restriction on the exe's licence [I1][U2].

## 4. Facts that affect other tickets

1. **Host-key and certificate trust ticket.**
   - Netmiko's default is `AutoAddPolicy`, which silently trusts any host key. The product must run with `ssh_strict=True`.
   - pan-os-python cannot verify TLS at all, and pan-python skips verification unless it is given an `ssl_context`.
   - Both mean the trust-on-first-use and pinning design has to live in our code.
2. **Device compatibility / Unvisited Device ticket.** Paramiko 5 removed SHA-1 key exchange and `ssh-rsa` signatures. Older IOS and NX-OS trains that offer only SHA-1 algorithms cannot be logged into without pinning an older Paramiko, which is a security trade-off that needs an explicit decision.
3. **Vendor HTTPS API ticket.**
   - NX-API needs `feature nxapi` enabled on the device, and the tool never changes config. Use SSH plus `| json` instead.
   - For IOS-XE, structured data over SSH comes from TextFSM. RESTCONF/NETCONF would need device-side enablement. This was not verified here and belongs to that ticket.
4. **Logging / crash-dump ticket.**
   - Never enable Netmiko `session_log`: it would write running configs to disk in plaintext.
   - Nornir, if it were ever used, writes `nornir.log` by default.
   - PyInstaller onefile leaves `_MEI*` folders behind after a crash. They hold code only, never data, but the behaviour is worth documenting.
5. **Distribution ticket.**
   - Budget for code signing (Azure Artifact Signing or an OV certificate).
   - Expect SmartScreen warnings at first and Smart App Control blocks on unsigned builds.
   - Decide onefile versus onedir, weighing the LGPL point and onefile's AV and start-up cost.
6. **Python version.** Python 3.13 is the safe target: Netmiko supports 3.11–3.15, PyInstaller 3.8–3.15, Nuitka needs MSVC for 3.13+, and all native dependencies ship Windows wheels for it.

## Sources

### Netmiko
- [N1] Netmiko PLATFORMS.md (support tiers): https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md
- [N2] Netmiko `base_connection.py` (`ssh_strict`, `AutoAddPolicy`, `SecretsFilter`, `session_log`, `use_textfsm`/`use_ttp`/`use_genie`): https://github.com/ktbyers/netmiko/blob/develop/netmiko/base_connection.py
- [N3] Netmiko releases, 4.8.0 notes: https://github.com/ktbyers/netmiko/releases/tag/v4.8.0
- [N4] Netmiko README: https://github.com/ktbyers/netmiko/blob/develop/README.md
- [N5] Netmiko `utilities.py` (`get_template_dir`, `cisco_xe` → `cisco_ios` fallback): https://github.com/ktbyers/netmiko/blob/develop/netmiko/utilities.py
- [N6] Netmiko on PyPI (dependencies): https://pypi.org/project/netmiko/

### Scrapli
- [S1] scrapli docs (libscrapli, Zig, transports): https://carlmontanari.github.io/scrapli/ and https://carlmontanari.github.io/scrapli/migration/
- [S2] scrapli release files on PyPI (no `win` wheels from 2026.2.22rc1 onwards): https://pypi.org/project/scrapli/#files
- [S3] "Windows has never and will never be supported": https://github.com/carlmontanari/scrapli/issues/406 and https://github.com/carlmontanari/scrapli/issues/393
- [S4] asyncssh removed; 2026.02.20 is the last release with it: https://github.com/carlmontanari/scrapli/issues/386

### Nornir
- [R1] Nornir runners: https://github.com/nornir-automation/nornir/blob/main/nornir/plugins/runners/__init__.py
- [R2] nornir_netmiko: https://github.com/ktbyers/nornir_netmiko and https://pypi.org/project/nornir-netmiko/
- [R3] nornir_scrapli pyproject (pins legacy scrapli): https://github.com/scrapli/nornir_scrapli/blob/main/pyproject.toml
- [R4] Nornir logging defaults: https://github.com/nornir-automation/nornir/blob/main/nornir/core/configuration.py
- [R5] Nornir inventory `Host`: https://github.com/nornir-automation/nornir/blob/main/nornir/core/inventory.py

### NAPALM
- [M1] NAPALM support matrix: https://napalm.readthedocs.io/en/latest/support/index.html
- [M2] napalm-panos: https://github.com/napalm-automation-community/napalm-panos and https://pypi.org/project/napalm-panos/
- [M3] NAPALM on PyPI (dependencies): https://pypi.org/project/napalm/

### Palo Alto (pan-python, pan-os-python)
- [P1] pan-python `xapi.py` v0.17.0: https://github.com/kevinsteves/pan-python/blob/v0.17.0/lib/pan/xapi.py
- [P2] pan-python `xapi.py` v0.26.0: https://github.com/kevinsteves/pan-python/blob/v0.26.0/lib/pan/xapi.py
- [P3] pan-os-python `generate_xapi`: https://github.com/PaloAltoNetworks/pan-os-python/blob/develop/panos/base.py
- [P4] pan-os-python certificate issues: https://github.com/PaloAltoNetworks/pan-os-python/issues/87, https://github.com/PaloAltoNetworks/pan-os-python/issues/120, https://github.com/PaloAltoNetworks/pan-os-python/issues/554
- [P5] pan-os-python pyproject: https://github.com/PaloAltoNetworks/pan-os-python/blob/develop/pyproject.toml
- [P6] pan-python releases: https://github.com/kevinsteves/pan-python/releases

### Parsers (ntc-templates, Genie / pyATS)
- [T1] ntc-templates template tree and index: https://github.com/networktocode/ntc-templates/tree/master/ntc_templates/templates
- [G1] genie / pyats release files on PyPI: https://pypi.org/project/genie/#files and https://pypi.org/project/pyats/#files
- [G2] pyATS getting started (tested platforms): https://pubhub.devnetcloud.com/media/pyats/docs/getting_started/index.html

### Paramiko
- [K1] Paramiko changelog (4.0.0, 5.0.0, 5.1.0): https://www.paramiko.org/changelog.html

### Cisco
- [C1] Cisco Nexus 9000 NX-OS Command Reference 10.3(x), Command Output Formats: https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/103x/command-reference/show/b_n9k_show_commands_103x/m_show_xml.html. See also the NX-API CLI chapter of the Programmability Guide 10.1(x): https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/101x/programmability/cisco-nexus-9000-series-nx-os-programmability-guide-release-101x/m-n9k-nx-api-cli-101x.html
- [C2] Cisco IOS XE 17.x SSH algorithms: https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-secure-shell-algorithm-ccc.html

### PyInstaller
- [I1] PyInstaller licence: https://pyinstaller.org/en/stable/license.html
- [I2] PyInstaller changelog: https://pyinstaller.org/en/stable/CHANGES.html
- [I3] pyinstaller-hooks-contrib stdhooks: https://github.com/pyinstaller/pyinstaller-hooks-contrib/tree/master/_pyinstaller_hooks_contrib/stdhooks
- [I4] PyInstaller antivirus guidance (issue template): https://github.com/pyinstaller/pyinstaller/blob/develop/.github/ISSUE_TEMPLATE/antivirus.md
- [I5] Building the bootloader: https://pyinstaller.org/en/stable/bootloader-building.html
- [I6] How the one-file program works: https://pyinstaller.org/en/stable/operating-mode.html
- [I7] PyInstaller security advisories: https://github.com/pyinstaller/pyinstaller/security/advisories/GHSA-9fxf-4qw3-ghmr

### Nuitka
- [U1] Nuitka LICENSE.txt (AGPL-3.0): https://github.com/Nuitka/Nuitka/blob/develop/LICENSE.txt
- [U2] Nuitka Runtime Library Exception: https://github.com/Nuitka/Nuitka/blob/develop/LICENSE-RUNTIME.txt
- [U3] Nuitka README / user manual (compilers, onefile, AV, Defender, data files): https://github.com/Nuitka/Nuitka/blob/develop/README.rst

### cx_Freeze
- [X1] cx_Freeze FAQ (single file): https://cx-freeze.readthedocs.io/en/stable/faq.html

### Microsoft
- [W1] Microsoft Learn, Code signing options for Windows app developers: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options
- [W2] Microsoft Learn, SmartScreen reputation for Windows app developers: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation
