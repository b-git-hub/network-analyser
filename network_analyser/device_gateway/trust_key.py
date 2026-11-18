"""`trust-key`: accept a device's host key after the operator checked it (story 45; ADR 0002).

The device is connected to and its host key read, and the key is saved only if its SHA-256
fingerprint is the one the operator typed. No password is ever sent. A device may hold keys
of several types and offers only one per connection, so each type the tool accepts is asked
for in turn, one connection each, until one matches. The address is a one-address Scope, so
the same fence as a Run applies: never a loopback, multicast or reserved address.
"""

from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Final

from network_analyser import scope
from network_analyser.device_gateway import ssh
from network_analyser.device_gateway.link import Dial, DialFailed
from network_analyser.records import ScopeRecord
from network_analyser.records.run_request import Timeouts
from network_analyser.trust_store import AcceptOutcome, TrustStore

_PORT: Final = 22
NOT_A_TARGET: Final = "the address is never a login target (loopback, multicast or reserved)"
UNREACHABLE: Final = "the device could not be reached over SSH"
NO_ACCEPTED_KEY: Final = "the device offered no host key the tool accepts"


@dataclass(frozen=True, slots=True)
class TrustKeyResult:
    """What `trust-key` did.

    Attributes:
        outcome: what the Trust Store did; None when no key was compared.
        presented: the fingerprints the device presented, in the order read.
        failure: why no key was compared, as fixed text; None when one was.
    """

    outcome: AcceptOutcome | None
    presented: tuple[str, ...] = ()
    failure: str | None = None


def trust_key(
    ip: IPv4Address,
    fingerprint: str,
    *,
    trust: TrustStore,
    timeouts: Timeouts = Timeouts(),  # noqa: B008 (a frozen record)
    dial: Dial | None = None,
) -> TrustKeyResult:
    """Save the key `ip` presents if its fingerprint is `fingerprint`; send no password."""
    fence = scope.parse([str(ip)], [])
    if not isinstance(fence, ScopeRecord) or not fence.contains(ip):
        return TrustKeyResult(None, failure=NOT_A_TARGET)
    dial = dial or ssh.dial
    wanted = fingerprint.strip().rstrip("=")
    presented: list[str] = []
    for key_type in ssh.HOST_KEY_ALGORITHMS:
        link = dial(fence, ip, _PORT, key_types=(key_type,), timeouts=timeouts)
        if isinstance(link, DialFailed):
            if link.algorithms_too_old:
                continue  # it holds no key of this type
            return TrustKeyResult(None, tuple(presented), failure=UNREACHABLE)
        key = link.host_key
        link.close()
        presented.append(key.fingerprint)
        if key.fingerprint == wanted:
            return TrustKeyResult(trust.accept(ip, fingerprint, key), tuple(presented))
    if not presented:
        return TrustKeyResult(None, failure=NO_ACCEPTED_KEY)
    return TrustKeyResult(AcceptOutcome.FINGERPRINT_MISMATCH, tuple(presented))
