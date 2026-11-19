"""The opt-in Sweep: probe the Scope on TCP 22, then log in only where the banner matches.

Ticket #55 (stories 69-72). No ICMP. At most 100 probes in flight (`--sweep-inflight` may
lower that, never raise it). Each probe has a 2 second budget and runs through
`device_gateway`, which checks the Scope where the socket opens and closes before key
exchange. Addresses are probed in ascending order. A Sweep larger than 65,536 addresses
is refused; one larger than 4,096 is warned about by `cli` before anything is contacted.

The NX-OS banner is provisional (`platforms.hints.sweep_platform`, lab checklist A2).
"""

import threading
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address
from typing import Final, Protocol

from network_analyser.device_gateway.probe import probe as gateway_probe
from network_analyser.platforms.hints import sweep_platform
from network_analyser.records import ScopeRecord
from network_analyser.records.events import AuditEvent
from network_analyser.records.sweep import ProbeResult, SweepResult

ADDRESS_LIMIT: Final = 65_536
"""A Sweep of more addresses than this is refused (story 72)."""

ADDRESS_WARNING: Final = 4_096
"""A Sweep of more addresses than this is warned about, and still allowed (story 72)."""

IN_FLIGHT_MAX: Final = 100
"""The most probes in flight. A caller may ask for fewer, never more (story 70)."""

PROBE_TIMEOUT_S: Final = 2.0
"""The probe budget, in seconds. Matches `device_gateway.probe.PROBE_TIMEOUT_S`."""


class SweepTooLargeError(Exception):
    """The Scope is larger than a Sweep may cover. Nothing was probed."""


class _Probe(Protocol):
    """`device_gateway.probe`: one address, audited, no socket left open."""

    def __call__(
        self,
        scope: ScopeRecord,
        ip: IPv4Address,
        /,
        *,
        emit: Callable[[AuditEvent], None],
    ) -> ProbeResult:
        """Probe one address. The address is positional; the audit callback is keyword-only."""
        ...


def addresses(scope: ScopeRecord) -> tuple[IPv4Address, ...]:
    """Return every address the Scope allows a probe to touch, in ascending order.

    Exclusions, network and broadcast edges, and addresses that are never targets are
    left out: `ScopeRecord.contains` is the only check.
    """
    found: list[IPv4Address] = []
    for span in scope.ranges:
        current = span.first
        while current <= span.last:
            if scope.contains(current):
                found.append(current)
            if current == span.last:
                break
            current += 1
    return tuple(found)


def combine_seeds(
    operator: Sequence[IPv4Address], found: Sequence[IPv4Address]
) -> tuple[IPv4Address, ...]:
    """Return the operator's Seeds first, then Sweep Seeds not already among them.

    The operator's order is kept (story 64: a Seed is logged into whatever its banner
    says). `found` is already in ascending order.
    """
    seen = set(operator)
    return (*dict.fromkeys(operator), *(ip for ip in found if ip not in seen))


def sweep(
    scope: ScopeRecord,
    *,
    inflight: int,
    emit: Callable[[AuditEvent], None],
    probe: _Probe | None = None,
) -> SweepResult:
    """Probe every in-Scope address and return the banners a login may follow.

    Args:
        scope: the Run's Scope. The probe checks it again where the socket opens.
        inflight: probes in flight. Values above 100 are treated as 100.
        emit: records each probe on the Audit log.
        probe: one address. The default is `device_gateway.probe`. Tests pass a fake.

    Raises:
        SweepTooLargeError: `scope` holds more than 65,536 addresses. Nothing is probed.
    """
    if scope.address_count > ADDRESS_LIMIT:
        msg = "a Sweep larger than 65,536 addresses is refused"
        raise SweepTooLargeError(msg)
    targets = addresses(scope)
    if not targets:
        return SweepResult((), ())
    prober = gateway_probe if probe is None else probe
    workers = _workers(inflight)
    # The pool pulls tasks in submission order, and `workers` equals the cap, so the
    # gate can start probes in ascending order without the pool deadlocking on itself.
    gate = _Gate(workers)

    def one(index: int, address: IPv4Address) -> ProbeResult:
        gate.enter(index)
        try:
            return prober(scope, address, emit=emit)
        finally:
            gate.leave()

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sweep") as pool:
        futures = [pool.submit(one, index, address) for index, address in enumerate(targets)]
        try:
            probed = tuple(future.result() for future in futures)
        except Exception, KeyboardInterrupt:
            for future in futures:
                future.cancel()
            raise
    return SweepResult(probed, _login_seeds(probed))


def _workers(inflight: int) -> int:
    """Return how many probes may run at once: at least 1, at most 100."""
    if inflight < 1:
        return 1
    return min(inflight, IN_FLIGHT_MAX)


def _login_seeds(probed: tuple[ProbeResult, ...]) -> tuple[IPv4Address, ...]:
    return tuple(
        item.ip
        for item in probed
        if item.ssh_id is not None and sweep_platform(item.ssh_id) is not None
    )


class _Gate:
    """Starts probe `index` only after the earlier ones have started, at most N at once."""

    def __init__(self, inflight: int) -> None:
        self._limit = inflight
        self._next = 0
        self._running = 0
        self._lock = threading.Condition()

    def enter(self, index: int) -> None:
        """Wait until `index` is the next probe and a slot is free, then take the slot."""
        with self._lock:
            while self._next != index or self._running >= self._limit:
                self._lock.wait()
            self._next += 1
            self._running += 1

    def leave(self) -> None:
        """Free the slot this probe held."""
        with self._lock:
            self._running -= 1
            self._lock.notify_all()
