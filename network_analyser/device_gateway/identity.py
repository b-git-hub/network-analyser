"""The Run's one-record-per-device checks, as `visit` asks them (story 73; decided on #10).

`discovery` keeps the register of what this Run has seen and hands it to each visit; the
gateway asks it at the two points where only the gateway can: after the Trust Store check
and before any password (the host key), and after `show version`, before anything else is
collected (the chassis serials). Both claims are atomic across the pool's threads, so two
IPs of one device visited at once are still examined once.
"""

from ipaddress import IPv4Address
from typing import Protocol

from network_analyser.records import HostKey


class Identity(Protocol):
    """Who, this Run, already holds a host key or a chassis serial."""

    def claim_host_key(self, ip: IPv4Address, key: HostKey) -> IPv4Address:
        """Claim `key` for `ip`; return the IP that holds it now (`ip` if it was free)."""
        ...

    def claim_serials(self, ip: IPv4Address, serials: tuple[str, ...]) -> IPv4Address:
        """Claim `serials` for `ip`; return the IP already holding any of them, else `ip`."""
        ...
