> Exploration notes written 2026-11-18 at `b-git-hub/network-analyser@a069d68` by the spec #37 exploration agent. A snapshot, not maintained: tickets win over these notes. Later decisions: [spec-37-implementation-calls](../spec-37-implementation-calls.md).

# What this cloud container can and can't verify (checked 2026-11-18)

## 1. Machine
- Ubuntu 24.04 on x86_64: 4 cores, 15 GiB RAM, running as **root (uid 0)**.
  - An elevation check that uses `os.geteuid()==0` on Linux would always fire here. On non-Windows, treat the check as "not elevated" or inject it.
- Outbound HTTPS goes through the agent proxy.
  - PyPI, GitHub release downloads, PSGallery and python.org all answered.
  - `gh` works with **REST only** (`gh api repos/...`). GraphQL is blocked, so `gh issue view` fails.
  - GitHub MCP tools also work.
- **No device network.** There are no Cisco devices and the DevNet CML sandbox is unreachable (it needs a VPN the operator books).
  - Every test uses hand-written synthetic fixtures (#28): RFC 5737 IPs, fake hostnames, canary secrets.
  - Nothing captured from a lab is ever committed.
  - A fake SSH server is deferred by #28, so gateway tests are unit tests on `send()` / identification / policy, with Netmiko and Paramiko mocked at the seam.

## 2. Python and dependencies: verified
- Installed: system Python is 3.13.18; uv is 0.11.32.
- `uv python install 3.14` gives **3.14.6** (python-build-standalone).
  - #32 pins **3.14.10**, which uv 0.11.32 cannot download.
  - `uvx --from uv@0.13.9 uv python install 3.14.10` can.
  - *Proposal:* set `[tool.uv] required-version = ">=0.13"` and use `uvx --from uv@0.13.9 uv …` here, or `uv self update`.
- Tests here run on uv's own CPython, not the python.org build. That is acceptable for tests; `build.ps1` (on Windows) enforces python.org.
- A throwaway venv (`scratchpad/envtest/.venv`, 3.14.6) installed cleanly in about 2 s:
  - runtime: netmiko 4.8.0, paramiko 5.1.0, textfsm 2.1.1, ntc-templates 9.3.0, pyrage 1.4.0, cryptography 50.0.2, pyyaml 6.0.3
  - build: pyinstaller 6.22.3, pip-licenses 5.5.5
  - lint and test: ruff 0.17.5, mypy 2.4.1, pyright 1.1.414, pytest 9.2.0, types-paramiko 5.1.0.20261030
  - netmiko also pulls in rich, scp, pyserial and invoke.
- **Windows cp314 is binary-only resolvable.** This command succeeded for the whole set:
  `uv pip compile --python-platform x86_64-pc-windows-msvc --python-version 3.14 --only-binary :all: --generate-hashes`
  - Windows adds colorama, pefile and pywin32-ctypes.
  - pyrage, cryptography, bcrypt and pynacl ship abi3 win_amd64 wheels; pyyaml and cffi ship cp314 win_amd64 wheels.
- **Gotcha, verified: `uv sync --locked --no-build` fails for a packaged project.** The error is "`<proj> @ editable+.` can't be installed because it is marked as `--no-build`". There are two ways round it:
  - `[tool.uv] package = false`. The literal command from #32/#44/#47 then works, but there is no console-script entry point and no installed metadata: run with `python -m network_analyser`, and keep the version in code (see guardrails.md).
  - Or `uv sync --locked --no-build --no-install-project`, which departs from the ticket text.
- **Typing:**
  - netmiko ships `py.typed`.
  - paramiko is covered by `types-paramiko`.
  - pyrage, textfsm and ntc_templates have **no types**: add a tiny local `stubs/pyrage/` (`passphrase.encrypt(bytes, str)->bytes`, `decrypt`, `DecryptError`) and per-module `ignore_missing_imports` for the other two.
- **Licences** (from pip-licenses):
  - paramiko is LGPL-2.1, and so is **scp** (pulled in by netmiko). Keep both as plain files in the one-folder build.
  - **pyrage reports `UNKNOWN`** and needs an explicit override; it is MIT upstream.
  - PyInstaller is GPL with a bootloader exception (a build tool only).
  - Everything else is MIT, BSD, Apache or PSF.

## 3. pyrage / age: verified
- `pyrage.passphrase.encrypt(data, pw)` and `decrypt(ct, pw)`. A wrong passphrase raises `pyrage.DecryptError("Decryption failed")`.
- The header line looks like `-> scrypt <salt> 20`, and the last token is log2 N (#51 reads it).
- Timing here: lock about **2.5 s**, unlock about 2.3 s, at level 20. A wrong-passphrase attempt also costs about 2 s.
  - Tests that use real pyrage are slow. Use it only where the promise needs it (security test 6, check-file round trip) and put the cipher behind a seam (`lock(bytes, Secret) -> bytes`) for other unit tests.
  - **Never** lower the work factor in product code (ADR 0004). pyrage can't anyway.
- **pyrage holds the GIL.** A 10 ms ticker thread got 1 tick during a 2.5 s lock. Progress (#56) can't redraw during a lock.
- The `age` 1.1.1 CLI is installed (`/usr/bin/age`). `age -d` of a pyrage file works through a pty (it reads the passphrase from the TTY), so story 103 can be checked here. Helper: `/tmp/claude-0/-home-user-network-analyser/7e9dc9da-55e5-5512-b270-d983f4f0e97f/scratchpad/age_pty.py <file> <passphrase>`.
  - It is not a committed test dependency, because the operator's PC won't have `age`.

## 4. PowerShell
- `pwsh` is **not installed**.
- The portable tarball (`github.com/PowerShell/PowerShell/releases/download/v7.4.6/powershell-7.4.6-linux-x64.tar.gz`, 72 MB) downloads, extracts and runs. A copy is at `/tmp/claude-0/-home-user-network-analyser/7e9dc9da-55e5-5512-b270-d983f4f0e97f/scratchpad/pwsh/bin/pwsh`; the scratchpad may be cleared.
  - `Install-Module PSScriptAnalyzer -Scope CurrentUser` worked (1.25.0).
  - packages.microsoft.com is also reachable, so an apt install is possible.
- **pwsh 7 is not Windows PowerShell 5.1.** It accepts `&&`, `??` and ternaries, so running build.ps1 under pwsh proves nothing about 5.1. Check with:
  `Invoke-ScriptAnalyzer -Path build.ps1 -Settings @{Rules=@{PSUseCompatibleSyntax=@{Enable=$true;TargetVersions=@('5.1')}}}`
  plus a grep that bans `&&` and `||`.
- build.ps1 still can't run end to end here: it needs the python.org Windows interpreter, the Windows PyInstaller, and the version resource.

## 5. PyInstaller
- Here it builds a **Linux** one-folder build only. That is useful for checking the hidden-import / `--collect-data ntc_templates` / diagram-asset collection and that `python -m network_analyser --version` works when frozen.
- It can't check:
  - the Windows exe
  - the version resource (`--version-file` is Windows-only)
  - SmartScreen
  - cold start on Windows
  - long paths
- A real Windows build needs a `windows-2025` Actions runner (#47). Note the push-trigger conflict in guardrails.md §CI.

## 6. Windows-only behaviour: seam and fake
Put every item behind `_winsys` (one module). On Linux, tests inject a fake. CI-free v1 means these are checked **by hand on Windows** (lab checklist).

| Behaviour | Windows API | Fake for tests |
|---|---|---|
| Per-user folder | `%LOCALAPPDATA%` (or `SHGetKnownFolderPath(FOLDERID_LocalAppData)`) → `NetworkAnalyser\` | inject a base `Path` (pytest `tmp_path`); never read the env outside `_winsys`/`paths` |
| Masked prompt | `msvcrt.getwch()`. `\r` ends input, `\x08` is Backspace, `\x03` is Ctrl+C, a `\x00`/`\xe0` prefix means swallow the next code (prototype `ccr-ca84f00b-wqls0w`) | inject a key iterator; output goes to a fake stream. Non-TTY fallback uses `sys.stdin.isatty()` |
| Crash-dump guard | `ctypes.windll.kernel32.SetErrorMode(0x0002)`; `winreg` read-only on `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps` (+ `\<exe name>` subkey) and `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug` (`Auto`, `Debugger`). Also check the `WOW6432Node` view | an injected reader returning dicts; assert no write API is ever called (`winreg` import absent on Linux) |
| Elevation warning | `ctypes.windll.shell32.IsUserAnAdmin()` (or token elevation) | an injected bool |
| Single-instance lock | open + `msvcrt.locking(fd, LK_NBLCK, 1)`, released when the process dies | `fcntl.flock` on Linux, so the behaviour is the same and testable |
| Long paths | `\\?\` prefix on absolute paths (#26). Don't rely on the `LongPathsEnabled` registry flag | a pure function that adds/strips the prefix, unit-testable |
| Permissions warning | `GetNamedSecurityInfoW` + walk the DACL for write/modify ACEs by SIDs other than the user, SYSTEM (S-1-5-18) or Administrators (S-1-5-32-544), via ctypes (no pywin32 dep) | inject an ACL list |
| Location notice | `GetDriveTypeW` (DRIVE_REMOTE / DRIVE_REMOVABLE), UNC prefix, OneDrive env/sync roots (best-effort) | inject a classifier |
| Windows account, PC | `GetUserNameExW` / `os.environ['USERDOMAIN']`, `COMPUTERNAME` (report + audit, #30) | inject strings |
| Ctrl+C | console SIGINT → `KeyboardInterrupt` on the main thread; workers need a stop token | call the stop-token API directly |

Typing tip: write Windows code under `if sys.platform == "win32":` so mypy narrows it. Run mypy with `--platform win32` as well as the default, because typeshed has `msvcrt` and `winreg` stubs.

## 7. GitHub / process facts (2026-11-18)
- Integration branch: `claude/lucid-shannon-8xewst`. Ticket branches are local worktrees under `.claude/worktrees/` (docs/wiki).
- Chained `git … &&` commands may be refused in worktrees; run one git command per call (wiki).
- The repo has no Actions workflows yet.
