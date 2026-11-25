# WinINET AutoDetect (WPAD) parsing (2026-11-25)

Ticket [#192](https://github.com/b-git-hub/network-analyser/issues/192); follows [#150](https://github.com/b-git-hub/network-analyser/issues/150).

- As of `b-git-hub/network-analyser@ad9563c`, 2026-11-25, operator decision: #192 is scoped to the parser only. `_winsys.proxy.connection_settings` reads the AutoDetect flag (0x8) and the auto-config URL (flag 0x4) from `HKCU\...\Internet Settings\Connections\DefaultConnectionSettings`, tested with synthetic bytes only.
- Layout used: DWORD version, DWORD counter, DWORD flags at offset 8, then three length-prefixed ASCII strings (proxy, bypass list, auto-config URL). Microsoft does not formally document it; the flag values are wininet.h's `PROXY_TYPE_*`.
- As of `b-git-hub/network-analyser@ad9563c`, 2026-11-25, operator decision: WPAD alone is not refused. The Run connects directly as before and prints a notice; a PAC URL from the binary value goes through the #150 refusal. No WPAD or PAC fetch was added, and no Audit field.
- Stays with the operator: whether the bypass list is honoured for Cisco egress (still ignored), and the by-hand Windows check of the registry read, to be recorded on #192.
