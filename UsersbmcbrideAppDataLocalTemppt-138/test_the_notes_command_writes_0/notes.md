# Network Analyser 0.4.0

## Breaking changes

- The Run folder layout changed: Backups now sit under `backups/`.

## Allow-list and Device Role

- Added `show inventory`.

**Re-apply the Device Role:** the allow-list changed, so before the first Run with this version, run `network-analyser role-snippet` and apply its output on every device the tool logs into.

## Fixed

- A parser fix.

## Before you install

- **System requirements:** Windows 11 64-bit, 8 GiB of RAM and 4 logical cores. Windows 10 and Windows Server are not supported; below that spec the tool still starts, but nothing is promised.
- **Unsigned build:** this build is not code-signed (decision #32). SmartScreen warns about an unknown publisher for every new version, and Smart App Control or an IT policy (AppLocker, WDAC) may block the exe or its DLL and `.pyd` files.
- **Check the download** before you unzip it: in PowerShell run `Get-FileHash -Algorithm SHA256 .\network-analyser-0.4.0-win-x64.zip` and compare the hash with the SHA-256 in the [workflow run summary](https://github.com/example/network-analyser/actions/runs/1), which cannot be edited after the run. It should be `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
- **Size:** 0.0 MB zip, 0.0 MB unpacked.

## Install

1. Unzip into a folder of its own, never over an older version: `%LOCALAPPDATA%\Programs\NetworkAnalyser\0.4.0\`. For example: `Expand-Archive -Path .\network-analyser-0.4.0-win-x64.zip -DestinationPath "$env:LOCALAPPDATA\Programs\NetworkAnalyser\0.4.0"`.
2. There is no installer, no PATH change and no admin rights. Run the exe by its full path, or from a shortcut, as a standard user. To check it starts: `& "$env:LOCALAPPDATA\Programs\NetworkAnalyser\0.4.0\network-analyser.exe" --version`.
3. Every version shares the Trust Store, Run register and Run folders in your per-user data folder. Older version folders stay until you delete them.
