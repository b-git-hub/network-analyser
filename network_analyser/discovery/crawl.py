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
- Ctrl+C (#56, stories 82-83) presses the Run's `RunStop`. After the first press no new
  visit starts and the queued devices are `not attempted (Run stopped)`, while sessions
  already open finish. Each press is audited with the sessions still running; after the
  second the crawl closes every open connection at once. The crawl waits for visits in
  short slices, so it sees a press at once (on Windows too) and calls `tick` with the
  number queued, for the live progress.
- A Neighbour's Platform hint goes to its visit, where it decides with the SSH
  identification string which Platform-limited Credential Sets fit (#54, story 32). Once
  every set is retired, no new visit starts and the queued devices are `not attempted
  (Credential Sets retired)` (story 37).

Each advertised IPv4 address the crawl chooses not to dial becomes an Unvisited
`DeviceRecord` with its reason, handed to `skipped` as soon as it is decided, so
`topology.json` written after Ctrl+C still holds it (docs/topology-json.md).
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
from network_analyser.records import HostKey, Placement, Platform, ScopeRecord
from network_analyser.records.collected import Neighbour, Reading
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.events import (
    AuditEvent,
    CtrlCPressed,
    DeviceOutcome,
    NeighbourNotVisited,
)
from network_analyser.records.identity import Alias

MAX_ADDRESSES: Final = 3
"""The most addresses tried for one Neighbour (story 65)."""
ALL_SETS_RETIRED: Final = "every Credential Set is retired"
"""Why the crawl stopped when no Credential Set is left to log in with (story 37)."""
STOPPED_BY_CTRL_C: Final = "stopped by the operator (Ctrl+C)"
"""Why the crawl stopped when the operator pressed Ctrl+C (story 82)."""
POLL_S: Final = 0.2
"""How long the crawl waits for a visit before it looks at Ctrl+C and the progress again."""

type Emit = Callable[[AuditEvent], None]
type Skipped = Callable[[DeviceRecord], object]
type Tick = Callable[[int], object]


class Visit(Protocol):
    """`device_gateway.visit` with the Run's Scope, Trust Store and sets bound by `cli`."""

    def __call__(
        self,
        ip: IPv4Address,
        *,
        id_gate: bool,
        neighbour_hint: Platform | None,
        identity: Identity,
    ) -> DeviceRecord | Alias:
        """Visit one address; `id_gate` for a Neighbour with no Platform hint.

        `neighbour_hint` is the Platform the Neighbour advertised (None for a Seed).
        """
        ...


@dataclass(frozen=True, slots=True)
class _Target:
    """One device to visit: its addresses in the order to try, and who told of it."""

    addresses: tuple[IPv4Address, ...]
    id_gate: bool
    reported_by: IPv4Address | None
    hint: Platform | None = None


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


def crawl(  # noqa: PLR0913 (the Seeds, the visit and the Run's settings, all by name)
    seeds: Sequence[IPv4Address],
    visit: Visit,
    *,
    scope: ScopeRecord,
    parallel: int,
    emit: Emit,
    skipped: Skipped | None = None,
    all_retired: Callable[[], bool] | None = None,
    stop: device_gateway.RunStop | None = None,
    tick: Tick | None = None,
) -> CrawlResult:
    """Crawl from `seeds` through CDP and LLDP; return every device found.

    Args:
        seeds: the Seeds, inside the Scope, in the order given.
        visit: visits one address (`device_gateway.visit`, bound by `cli`).
        scope: the Run's Scope: the only fence.
        parallel: devices worked on at once (10 by default, 50 at most).
        emit: takes the Audit log event of each Neighbour never dialled.
        skipped: takes each Unvisited record of an address never dialled, as it is decided.
        all_retired: says whether every Credential Set is retired
            (`CredentialSets.all_retired`, bound by `cli`); None never stops for that.
        stop: the Run's Ctrl+C state, the same one `visit` is bound to (#56); None for
            a crawl only a visit can stop.
        tick: called on the crawl's thread at least every `POLL_S` seconds with how many
            devices are queued, for the live progress (#56).
    """
    return _Crawl(
        visit,
        scope,
        emit,
        skipped or (lambda _record: None),
        all_retired or (lambda: False),
        stop or device_gateway.RunStop(),
        tick or (lambda _queued: None),
    ).run(seeds, parallel)


class _Crawl:
    """The queue, what has been seen, and what has been found. Used by the main thread."""

    def __init__(  # noqa: PLR0913, PLR0917 (see `crawl`)
        self,
        visit: Visit,
        scope: ScopeRecord,
        emit: Emit,
        skipped: Skipped,
        all_retired: Callable[[], bool],
        stop: device_gateway.RunStop,
        tick: Tick,
    ) -> None:
        self.visit = visit
        self.scope = scope
        self.emit = emit
        self.skipped = skipped
        self.all_retired = all_retired
        self.stop = stop
        self.tick = tick
        self.closed = False
        self.identity = IdentityRegister()
        self.queue: deque[_Target] = deque()
        self.seen: set[IPv4Address] = set()
        self.not_dialled: dict[IPv4Address, DeviceRecord] = {}
        self.devices: list[DeviceRecord] = []
        self.aliases: list[Alias] = []
        self.stopped: str | None = None

    def run(self, seeds: Sequence[IPv4Address], parallel: int) -> CrawlResult:
        for seed in dict.fromkeys(seeds):
            self.seen.add(seed)
            self.queue.append(_Target((seed,), id_gate=False, reported_by=None))
        with ThreadPoolExecutor(max_workers=parallel, thread_name_prefix="visit") as pool:
            running: dict[Future[DeviceRecord | Alias], _Target] = {}
            while True:
                while self.queue and not self.stopping() and len(running) < parallel:
                    target = self.queue.popleft()
                    running[pool.submit(self.visit_target, target)] = target
                if not running:
                    break
                # Short waits: on Windows a wait with no timeout never sees Ctrl+C.
                done, _ = wait(running, timeout=POLL_S, return_when=FIRST_COMPLETED)
                self.watch_stop(len(running))
                for future in done:
                    del running[future]
                    self.found(future.result())
                if self.stopped is None and self.all_retired():
                    self.stopped = ALL_SETS_RETIRED
                self.tick(len(self.queue))
        self.watch_stop(0)
        why = (
            UnvisitedReason.SETS_RETIRED
            if self.stopped == ALL_SETS_RETIRED
            else UnvisitedReason.RUN_STOPPED
        )
        while self.queue:
            target = self.queue.popleft()
            self.not_visited(why, target.addresses, target.reported_by)
        return CrawlResult(
            devices=tuple(self.with_aliases(d) for d in self.devices),
            unvisited=tuple(self.not_dialled.values()),
            stopped=self.stopped,
        )

    def stopping(self) -> bool:
        return self.stopped is not None or self.stop.requested

    def watch_stop(self, sessions_running: int) -> None:
        """Audit each new Ctrl+C, close every session after the second, note why it stopped."""
        for press in self.stop.presses_to_audit():
            self.emit(CtrlCPressed(press=press, sessions_running=sessions_running))
        if self.stop.closing and not self.closed:
            self.closed = True
            self.stop.close_now()
        if self.stop.requested and self.stopped is None:
            self.stopped = self.stop.reason or STOPPED_BY_CTRL_C

    def visit_target(self, target: _Target) -> DeviceRecord | Alias:
        """Visit one device, moving to its next address only after a connection failure."""
        *earlier, last = target.addresses
        for address in earlier:
            result = self.visit_one(address, target)
            if not _connection_failed(result):
                return result
        return self.visit_one(last, target)

    def visit_one(self, address: IPv4Address, target: _Target) -> DeviceRecord | Alias:
        return self.visit(
            address,
            id_gate=target.id_gate,
            neighbour_hint=target.hint,
            identity=self.identity,
        )

    def found(self, result: DeviceRecord | Alias) -> None:
        if isinstance(result, Alias):
            self.aliases.append(result)
            return
        self.devices.append(result)
        stopped_by_its_visit = result.unvisited_reason is UnvisitedReason.RUN_STOPPED
        if stopped_by_its_visit and not self.stop.requested and self.stopped is None:
            # A visit bound to another `RunStop` (or none) can only stop the Run this way.
            self.stopped = device_gateway.TRUST_STORE_UNWRITABLE
        collected = result.collected
        if collected is None:
            return
        for table in (collected.cdp, collected.lldp):
            if isinstance(table, Reading):
                for neighbour in table.value:
                    self.consider(neighbour, result.ip)

    def consider(self, neighbour: Neighbour, reported_by: IPv4Address) -> None:
        """Gate one advertised Neighbour: queue it, record it as Unvisited, or skip it."""
        inside = [a for a in neighbour.addresses if self.scope.contains(a)]
        if any(a in self.seen for a in inside):
            return  # a device already queued or visited (de-duplicated by IP)
        if not inside:
            reason = _beyond_the_fence(self.scope, neighbour.addresses, neighbour.ipv6_addresses)
            self.not_visited(reason, neighbour.addresses, reported_by)
            return
        hint = platforms.neighbour_hint(neighbour)
        self.seen.update(inside)
        if isinstance(hint, Unsupported):
            self.not_visited(UnvisitedReason.UNSUPPORTED_ADVERTISED, tuple(inside), reported_by)
            return
        self.queue.append(
            _Target(
                tuple(inside[:MAX_ADDRESSES]),
                id_gate=hint is None,
                reported_by=reported_by,
                hint=hint,
            )
        )

    def not_visited(
        self,
        reason: UnvisitedReason,
        addresses: tuple[IPv4Address, ...],
        reported_by: IPv4Address | None,
    ) -> None:
        """Record each address never dialled, once, and audit the decision."""
        new = [a for a in addresses if a not in self.not_dialled]
        if addresses and not new:
            return  # already recorded from another advertisement
        for address in new:
            record = DeviceRecord(address, DeviceOutcome.UNVISITED, unvisited_reason=reason)
            self.not_dialled[address] = record
            self.skipped(record)
        self.emit(NeighbourNotVisited(reported_by, addresses, reason.value))

    def with_aliases(self, record: DeviceRecord) -> DeviceRecord:
        found = tuple(a.ip for a in self.aliases if a.same_as == record.ip)
        return dataclasses.replace(record, aliases=(*record.aliases, *found)) if found else record


def _connection_failed(result: DeviceRecord | Alias) -> bool:
    """Say whether no SSH session was reached at all: only then is another address tried."""
    return (
        isinstance(result, DeviceRecord)
        and result.unvisited_reason is UnvisitedReason.UNREACHABLE
        and result.ssh_id is None
    )


def _beyond_the_fence(
    scope: ScopeRecord, addresses: Iterable[IPv4Address], ipv6: Iterable[IPv6Address]
) -> UnvisitedReason:
    """Why a Neighbour with no in-Scope address is not visited (stories 66-67)."""
    listed = list(addresses)
    if any(scope.placement(a) is Placement.EXCLUDED for a in listed):
        return UnvisitedReason.EXCLUDED
    if not listed and any(True for _ in ipv6):
        return UnvisitedReason.IPV6_ONLY
    return UnvisitedReason.OUTSIDE_SCOPE
