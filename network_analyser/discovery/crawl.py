"""The crawl: from the Seeds through CDP and LLDP, inside the Scope (ticket #50; decided on #10).

- The Seeds are queued first, in the order given, and are always logged into (story 64).
- Each Visited Device's CDP and LLDP Neighbours are checked against the Scope, then their
  Platform hint, then queued first-in, first-out, de-duplicated by IP. There is no hop
  limit: the Scope is the only fence (stories 60-61). Only CDP and LLDP advertisements are
  followed: ARP and MAC entries are never login targets (story 68).
- A Neighbour with no in-Scope address is `outside Scope`, `excluded by operator` or `IPv6
  only`; one advertised as a known unsupported Platform is `unsupported Platform
  (advertised)`. Neither is ever dialled (stories 62, 66-67). One with no hint, or one not
  recognised, is logged into only if its SSH identification string looks supported (63).
- Its first in-Scope management address is tried first, then any other in-Scope address it
  advertised, at most 3, moving on only after a connection failure (story 65).
- A pool of `parallel` threads visits the queue, one session per device (story 49). Each
  device is examined once, whichever of its IPs is reached first (story 73).
- If a visit stops the Run (the Trust Store cannot be written), no new visit starts; the
  queued devices are `not attempted (Run stopped)`.
"""

import dataclasses
import threading
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Final, Protocol

from network_analyser import device_gateway, platforms
from network_analyser.device_gateway.identity import Identity
from network_analyser.platforms import Unsupported
from network_analyser.records import HostKey, Placement, ScopeRecord
from network_analyser.records.crawl import CrawlResult, Sighting, UnvisitedDevice
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.events import AuditEvent, NeighbourNotVisited
from network_analyser.records.identity import Alias

MAX_ADDRESSES: Final = 3
"""The most addresses tried for one Neighbour (story 65)."""

type Address = IPv4Address | IPv6Address
type Emit = Callable[[AuditEvent], None]


class Visit(Protocol):
    """`device_gateway.visit` with the Run's Scope, Trust Store and sets bound by `cli`."""

    def __call__(
        self, ip: IPv4Address, *, id_gate: bool, identity: Identity
    ) -> DeviceRecord | Alias:
        """Visit one address; `id_gate` for a Neighbour with no Platform hint."""
        ...


@dataclass(frozen=True, slots=True)
class _Target:
    """One device to visit: its addresses in the order to try, and who told of it."""

    addresses: tuple[IPv4Address, ...]
    id_gate: bool
    sightings: tuple[Sighting, ...]


class IdentityRegister:
    """Who, this Run, holds each host key and chassis serial. Safe across threads."""

    def __init__(self) -> None:
        """Start empty: nothing has been seen yet this Run."""
        self._lock = threading.Lock()
        self._keys: dict[HostKey, IPv4Address] = {}
        self._serials: dict[str, IPv4Address] = {}

    def claim_host_key(self, ip: IPv4Address, key: HostKey) -> IPv4Address:
        """Claim `key` for `ip`; return the IP that holds it now."""
        with self._lock:
            return self._keys.setdefault(key, ip)

    def claim_serials(self, ip: IPv4Address, serials: tuple[str, ...]) -> IPv4Address:
        """Claim `serials` for `ip`; return the IP already holding any of them, else `ip`."""
        with self._lock:
            holder = next((self._serials[s] for s in serials if s in self._serials), ip)
            for serial in serials:
                self._serials.setdefault(serial, holder)
            return holder


def crawl(
    seeds: Sequence[IPv4Address],
    visit: Visit,
    *,
    scope: ScopeRecord,
    parallel: int,
    emit: Emit,
) -> CrawlResult:
    """Crawl from `seeds` through CDP and LLDP; return every device found.

    Args:
        seeds: the Seeds, inside the Scope, in the order given.
        visit: visits one address (`device_gateway.visit`, bound by `cli`).
        scope: the Run's Scope: the only fence.
        parallel: devices worked on at once (10 by default, 50 at most).
        emit: takes the Audit log event of each device never dialled.
    """
    return _Crawl(visit, scope, emit).run(seeds, parallel)


class _Crawl:
    """The queue, what has been seen, and what has been found. Used by the main thread."""

    def __init__(self, visit: Visit, scope: ScopeRecord, emit: Emit) -> None:
        self.visit = visit
        self.scope = scope
        self.emit = emit
        self.identity = IdentityRegister()
        self.queue: deque[_Target] = deque()
        self.seen: set[IPv4Address] = set()
        self.devices: list[DeviceRecord] = []
        self.aliases: list[Alias] = []
        self.unvisited: list[UnvisitedDevice] = []
        self.stopped: str | None = None

    def run(self, seeds: Sequence[IPv4Address], parallel: int) -> CrawlResult:
        for seed in dict.fromkeys(seeds):
            self.seen.add(seed)
            self.queue.append(_Target((seed,), id_gate=False, sightings=()))
        with ThreadPoolExecutor(max_workers=parallel, thread_name_prefix="visit") as pool:
            running: dict[Future[DeviceRecord | Alias], _Target] = {}
            while True:
                while self.queue and self.stopped is None and len(running) < parallel:
                    target = self.queue.popleft()
                    running[pool.submit(self.visit_target, target)] = target
                if not running:
                    break
                done, _ = wait(running, return_when=FIRST_COMPLETED)
                for future in done:
                    del running[future]
                    self.found(future.result())
        while self.queue:
            target = self.queue.popleft()
            self.not_visited(UnvisitedReason.RUN_STOPPED, target.addresses, target.sightings)
        return CrawlResult(
            devices=tuple(self.with_aliases(d) for d in self.devices),
            unvisited=tuple(self.unvisited),
            stopped=self.stopped,
        )

    def visit_target(self, target: _Target) -> DeviceRecord | Alias:
        """Visit one device, moving to its next address only after a connection failure."""
        *earlier, last = target.addresses
        for address in earlier:
            result = self.visit(address, id_gate=target.id_gate, identity=self.identity)
            if not _connection_failed(result):
                return result
        return self.visit(last, id_gate=target.id_gate, identity=self.identity)

    def found(self, result: DeviceRecord | Alias) -> None:
        if isinstance(result, Alias):
            self.aliases.append(result)
            return
        self.devices.append(result)
        if result.unvisited_reason is UnvisitedReason.RUN_STOPPED:
            self.stopped = device_gateway.TRUST_STORE_UNWRITABLE
        for table in (result.cdp_neighbours, result.lldp_neighbours):
            if isinstance(table, tuple):
                for neighbour in table:
                    self.consider(Sighting(result.ip, neighbour))

    def consider(self, sighting: Sighting) -> None:
        """Gate one advertised Neighbour: queue it, record it as Unvisited, or skip it."""
        neighbour = sighting.neighbour
        addresses = neighbour.addresses
        inside = [a for a in addresses if isinstance(a, IPv4Address) and self.scope.contains(a)]
        if any(a in self.seen for a in inside):
            return  # a device already queued or visited (de-duplicated by IP)
        if not inside:
            self.not_visited(_beyond_the_fence(self.scope, addresses), addresses, (sighting,))
            return
        hint = platforms.neighbour_hint(neighbour)
        self.seen.update(inside)
        if isinstance(hint, Unsupported):
            self.not_visited(UnvisitedReason.UNSUPPORTED_ADVERTISED, addresses, (sighting,))
            return
        self.queue.append(
            _Target(tuple(inside[:MAX_ADDRESSES]), id_gate=hint is None, sightings=(sighting,))
        )

    def not_visited(
        self,
        reason: UnvisitedReason,
        addresses: tuple[Address, ...],
        sightings: tuple[Sighting, ...],
    ) -> None:
        """Record an Unvisited Device never dialled, merged with one already recorded."""
        for index, known in enumerate(self.unvisited):
            if known.reason is reason and _same_device(known, addresses, sightings):
                merged = tuple(dict.fromkeys((*known.addresses, *addresses)))
                self.unvisited[index] = UnvisitedDevice(
                    reason, merged, (*known.sightings, *sightings)
                )
                return
        self.unvisited.append(UnvisitedDevice(reason, addresses, sightings))
        reporter = sightings[0].reported_by if sightings else None
        v4 = tuple(a for a in addresses if isinstance(a, IPv4Address))
        self.emit(NeighbourNotVisited(reporter, v4, reason.value))

    def with_aliases(self, record: DeviceRecord) -> DeviceRecord:
        found = tuple(a for a in self.aliases if a.same_as == record.ip)
        return dataclasses.replace(record, aliases=found) if found else record


def _connection_failed(result: DeviceRecord | Alias) -> bool:
    """Say whether no SSH session was reached at all: only then is another address tried."""
    return (
        isinstance(result, DeviceRecord)
        and result.unvisited_reason is UnvisitedReason.UNREACHABLE
        and result.ssh_id is None
    )


def _beyond_the_fence(scope: ScopeRecord, addresses: Iterable[Address]) -> UnvisitedReason:
    """Why a Neighbour with no in-Scope address is not visited (stories 66-67)."""
    listed = list(addresses)
    if any(scope.placement(a) is Placement.EXCLUDED for a in listed):
        return UnvisitedReason.EXCLUDED
    if listed and not any(isinstance(a, IPv4Address) for a in listed):
        return UnvisitedReason.IPV6_ONLY
    return UnvisitedReason.OUTSIDE_SCOPE


def _same_device(
    known: UnvisitedDevice, addresses: tuple[Address, ...], sightings: tuple[Sighting, ...]
) -> bool:
    """Two advertisements tell of one device when they share an address or LLDP Chassis id."""
    if set(known.addresses) & set(addresses):
        return True
    chassis = {s.neighbour.chassis_id for s in known.sightings} - {None}
    return any(s.neighbour.chassis_id in chassis for s in sightings)
