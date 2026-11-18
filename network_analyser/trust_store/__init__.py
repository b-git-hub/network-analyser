"""The `trust_store` module: the operator's trusted SSH host keys, kept between Runs.

Owns the per-user `known_hosts` (OpenSSH format) keyed by IP and port, trust on first
use, the changed-key hard stop, key-type pinning, strict mode, the read-only
`--known-hosts` import and `trust-key` (ADR 0002). Calls no other module.
"""
