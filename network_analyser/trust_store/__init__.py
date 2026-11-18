"""The `trust_store` module: the operator's trusted SSH host keys, kept between Runs.

Owns the per-user `known_hosts` (OpenSSH format) keyed by IP and port, trust on first use,
the changed-key hard stop, key-type pinning, strict mode, the read-only `--known-hosts`
import and the `accept` behind `trust-key` (ADR 0002, ticket #46). It works on plain data
(an IP, a port and an offered `records.HostKey`), never on a live session, and calls no
other module but `records`.

How `device_gateway` uses it, per connection:
1. `key_types(ip, port)`: ask a known device only for these key types (story 44).
2. `check(ip, port, offered)`: KNOWN or NEW may log in; CHANGED and NOT_TRUSTED never do.
3. `password_sent(check)`: only once a password was actually sent, which is when a NEW key
   is written to the Trust Store (story 76).
"""

from network_analyser.trust_store.store import (
    AcceptOutcome,
    PreloadIsTrustStoreError,
    TrustStore,
    load,
)

__all__ = ["AcceptOutcome", "PreloadIsTrustStoreError", "TrustStore", "load"]
