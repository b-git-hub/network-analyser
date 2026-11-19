"""The `device_gateway` module: the single gatekeeper between the tool and any device.

The only module that opens a socket to a device and the only one that imports Netmiko
or Paramiko (security test 3; inside it, only `ssh.py` imports those libraries). Sockets
are opened only in `ssh.py` (a full SSH session) and `probe.py` (a TCP 22 banner read
that closes before key exchange). It checks the Scope where each socket opens, checks
the Trust Store before sending a password, sends every command through one allow-list
gate, drops the session on a config-mode prompt and keeps library session logs off. It
hands back plain device records, never a live session (ADR 0003).

- `probe(ip, ...)`: open TCP 22, read the SSH identification string, close before key
  exchange. No password. The Scope is checked in the function that opens the socket (#55).
- `visit(ip, ...)`: log into one device, identify it, capture its running config for
  the Backup sink, read its CDP and LLDP Neighbours, leave; returns a `DeviceRecord`, or an
  `Alias` for a device already examined this Run.
- `trust_key(ip, fingerprint, ...)`: read a device's host key and save it only if it
  matches the fingerprint the operator checked (`trust-key`, story 45). No password.
- `DeviceSession.send(platform, command)`: the allow-list gate itself (security test 1).
"""

from network_analyser.device_gateway.gate import (
    CONFIG_MODE,
    CommandRefusedError,
    DeviceSession,
    SessionDroppedError,
)
from network_analyser.device_gateway.identity import Identity
from network_analyser.device_gateway.probe import probe
from network_analyser.device_gateway.trust_key import NOT_A_TARGET, TrustKeyResult, trust_key
from network_analyser.device_gateway.visit import (
    SSH_PORT,
    TRUST_STORE_UNWRITABLE,
    BackupSink,
    visit,
)

__all__ = [
    "CONFIG_MODE",
    "NOT_A_TARGET",
    "SSH_PORT",
    "TRUST_STORE_UNWRITABLE",
    "BackupSink",
    "CommandRefusedError",
    "DeviceSession",
    "Identity",
    "SessionDroppedError",
    "TrustKeyResult",
    "probe",
    "trust_key",
    "visit",
]
