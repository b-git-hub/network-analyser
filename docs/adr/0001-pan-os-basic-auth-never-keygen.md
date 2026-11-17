# PAN-OS: Basic auth on every request, never keygen

The tool authenticates to the PAN-OS XML API with HTTP Basic auth on every request and never calls `type=keygen`. On PAN-OS 9.1/10.0, generating a key ends the admin's existing sessions and deletes earlier API keys, which is a device state change that breaks the read-only rule; on 10.1 and later the docs no longer say whether that still happens. Any key generated is also a long-lived credential (no expiry by default) that would have to be guarded like a password. Basic auth is documented from 9.1 to 12.2 and leaves nothing behind on the firewall.

## Consequences

- `pan-python`, chosen on [Python network automation libraries and packaging as a Windows exe](https://github.com/b-git-hub/network-analyser/issues/2), cannot be used as-is. With a username and password it runs keygen on every call, has no Basic-auth support, skips certificate checks unless given a context, and reads `.panrc` credential files. The tool uses a thin HTTPS client of its own (certificate checks on) or a patched `pan-python` that never generates keys.
- Whether each Basic-auth request opens an admin session or writes a log entry on the firewall is unconfirmed; it is checked on a test device ([Get devices to test against](https://github.com/b-git-hub/network-analyser/issues/8)).

## Considered Options

- **keygen once per firewall per Run:** fewer password transmissions, but a device state change on some versions and a long-lived key in memory.
- **Operator-supplied API key:** a second secret per firewall, and a key the operator must create with keygen anyway.
