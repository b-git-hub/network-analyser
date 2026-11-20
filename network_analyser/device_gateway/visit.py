"""Visit one device: log in, identify its Platform, read its Neighbours, and leave (#49, #50).

The order is the safety (ADR 0002, ADR 0003, stories 38-52, 57-59, 63-64, 73):

1. The Scope, before any socket. An address it does not allow is never dialled.
2. One SSH connection per password attempt; a connection failure is retried once, after
   a wait. Its identification string is a hint only, and `CISCO_WLC` is rejected before
   login. A Neighbour with no Platform hint must also show a supported identification
   string, or it gets no password; a Seed is always logged into.
3. The Trust Store, before any password. A changed key, or strict mode with an untrusted
   one, is never logged into. A known device is asked only for the key type trusted for it.
4. The host-key alias check: a key already seen this Run at another IP is the same device,
   so the connection is closed before any password.
5. One password attempt, with a Credential Set leased from `credentials` (#54): the lease
   is the only way to the password, keeps probation and the failure budget across the
   pool, and is always given back. A wait for a set's turn happens with no link open. A
   NEW key is written once a password was sent; if it cannot be written, the device is
   left at once and the Run stops.
6. In the same session: the prompt, `terminal length 0`, `terminal width 511`, then
   `show version` decides the Platform. An unsupported one is left at once.
7. The landing privilege; then the chassis serial check (a serial already seen this Run is
   the same device, left before anything else is collected); then the CDP and LLDP tables;
   then the running config (#51); then the Platform's collection commands (#59, #60).
   A collection command that is denied or not understood leaves only its data unknown;
   one that drops the session leaves the device partial, keeping the Backup and what
   was collected before it.
8. Leave. Nothing is sent to end the session. No command runs past the per-device timeout,
   and a command that times out leaves the device partial; it is never retried. A whole
   config goes to the Backup sink once the session is closed, and to nothing else; one that
   is not a whole config leaves the device partial.

Ctrl+C (#56, `RunStop`): after the first press no new connection is opened (no connection
retry, no next Credential Set), so the device is `not attempted (Run stopped)`, while a
session already open finishes. The second press closes the session at once: a device
already identified is left partial, any other is `not attempted (Run stopped)`.

Every step is an Audit log event; no event holds device output.
"""

import dataclasses
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import Final, Protocol

from network_analyser import platforms
from network_analyser.credentials import CredentialSets, LoginLease
from network_analyser.device_gateway import link as link_seam
from network_analyser.device_gateway import ssh
from network_analyser.device_gateway.gate import (
    DROP_REASONS,
    ClosedByOperatorError,
    CommandRefusedError,
    DeviceSession,
    Emit,
    SessionDroppedError,
)
from network_analyser.device_gateway.identity import Identity
from network_analyser.device_gateway.link import Dial, DialFailed, Link, LoginResult
from network_analyser.device_gateway.stop import CLOSED_BY_OPERATOR, RunStop
from network_analyser.device_gateway.text import printable
from network_analyser.platforms import Hint, NeighbourProtocol, Unsupported
from network_analyser.records import (
    CredentialSetView,
    HostKeyCheck,
    HostKeyVerdict,
    Placement,
    Platform,
    ScopeRecord,
)
from network_analyser.records import events as ev
from network_analyser.records.backup import BackupCapture
from network_analyser.records.collected import NOT_COLLECTED, Collected, Neighbour, Reading
from network_analyser.records.device import (
    DeviceRecord,
    LandingPrivilege,
    Unknown,
    UnvisitedReason,
    VersionFacts,
)
from network_analyser.records.identity import Alias, AliasEvidence
from network_analyser.records.run_request import Timeouts
from network_analyser.trust_store import TrustStore

SSH_PORT: Final = 22
_SSH_ID_LIMIT: Final = 255  # RFC 4253 4.2: the whole line is at most 255 characters
REFUSED_COMMAND: Final = "a command was refused by the allow-list gate (a bug in the tool)"
NO_SHELL: Final = "logged in, but the device's CLI could not be opened"
TRUST_STORE_UNWRITABLE: Final = "the Trust Store could not be written"
"""The fixed message when a NEW key could not be saved: the device is left and the Run stops."""
_NOT_READ: Final = "not read, the session was dropped"
_USERNAME_DOES_NOT_FIT: Final = "the username does not fit the privilege command's pattern"
_PARSER: Final = {
    Platform.IOS_XE: "ntc-templates cisco_ios",
    Platform.NX_OS: "ntc-templates cisco_nxos",
}
_HOST_KEY_STOPS: Final = {
    HostKeyVerdict.CHANGED: UnvisitedReason.HOST_KEY_CHANGED,
    HostKeyVerdict.NOT_TRUSTED: UnvisitedReason.HOST_KEY_NOT_TRUSTED,
}
_TRUST_STORE_ERRORS: Final[Mapping[type[BaseException], str]] = {OSError: TRUST_STORE_UNWRITABLE}
_LOGGED: Final = {
    LoginResult.SUCCEEDED: ev.LoginResult.SUCCEEDED,
    LoginResult.FAILED: ev.LoginResult.FAILED,
    LoginResult.LOST: ev.LoginResult.LOST,
}

type Neighbours = Reading[tuple[Neighbour, ...]] | Unknown


class BackupSink(Protocol):
    """Takes a captured running config: `backup_store`'s locking queue (spec-37 call 4)."""

    def __call__(self, capture: BackupCapture, config: str, /) -> None:
        """Take `config`, the device's running config exactly as sent, to be locked."""
        ...


def visit(  # noqa: PLR0913 (the device and everything the rules need, all by name)
    ip: IPv4Address,
    *,
    scope: ScopeRecord,
    trust: TrustStore,
    sets: CredentialSets,
    emit: Emit,
    failure_budget: int,
    backup_sink: BackupSink,
    timeouts: Timeouts = Timeouts(),  # noqa: B008 (a frozen record)
    dial: Dial | None = None,
    id_gate: bool = False,
    neighbour_hint: Platform | None = None,
    identity: Identity | None = None,
    wait_before_retry: Callable[[], None] | None = None,
    stop: RunStop | None = None,
) -> DeviceRecord | Alias:
    """Log into the device at `ip`, identify it, read its Neighbours and leave.

    Args:
        ip: the device's address. Always an IP, never a name (story 40).
        scope: the Run's Scope: an address outside it is never dialled.
        trust: the Trust Store, checked before any password.
        sets: the Run's Credential Sets, tried in order, one password per connection, each
            through a lease (#54).
        emit: takes each Audit log event, in order.
        failure_budget: failed logins a set may spend before it is retired.
        backup_sink: takes the running config of a Visited Device, and nothing else does.
        timeouts: how long each step may take.
        dial: opens SSH connections; the real one (`ssh.dial`) unless a test fakes it.
        id_gate: True for a Neighbour with no Platform hint: log in only when the SSH
            identification string looks like a supported Platform (story 63). False for a
            Seed, which is always logged into (story 64).
        neighbour_hint: the Platform the Neighbour advertised, if any: with the
            identification string's, it decides which Platform-limited sets fit (story 32).
        identity: the Run's register of host keys and serials already seen (story 73);
            None checks no aliases.
        wait_before_retry: waits before the one connection retry; `link.wait_before_retry`
            unless a test replaces it.
        stop: the Run's Ctrl+C state (#56); None for a visit nothing can stop.

    Returns:
        The device record, or an `Alias` when `ip` is a device already examined this Run.
    """
    visitor = _Visitor(
        ip=ip,
        scope=scope,
        trust=trust,
        sets=sets,
        emit=emit,
        failure_budget=failure_budget,
        backup_sink=backup_sink,
        timeouts=timeouts,
        dial=dial or ssh.dial,
        id_gate=id_gate,
        neighbour_hint=neighbour_hint,
        identity=identity,
        wait=wait_before_retry,
        stop=stop or RunStop(),
    )
    result = visitor.run()
    if isinstance(result, Alias):
        emit(ev.AliasFound(result.ip, result.same_as, result.evidence.value))
        return result
    reason = result.unvisited_reason.value if result.unvisited_reason else result.partial_reason
    emit(ev.DeviceFinished(ip, result.outcome, reason))
    return result


class _Visitor:
    """The state of one visit: which sets were tried and what the device presented."""

    def __init__(  # noqa: PLR0913 (see `visit`)
        self,
        *,
        ip: IPv4Address,
        scope: ScopeRecord,
        trust: TrustStore,
        sets: CredentialSets,
        emit: Emit,
        failure_budget: int,
        backup_sink: BackupSink,
        timeouts: Timeouts,
        dial: Dial,
        id_gate: bool,
        neighbour_hint: Platform | None,
        identity: Identity | None,
        wait: Callable[[], None] | None,
        stop: RunStop,
    ) -> None:
        self.ip = ip
        self.scope = scope
        self.trust = trust
        self.sets = sets
        self.emit = emit
        self.failure_budget = failure_budget
        self.backup_sink = backup_sink
        self.timeouts = timeouts
        self.dial = dial
        self.id_gate = id_gate
        self.neighbour_hint = neighbour_hint
        self.identity = identity
        self.wait = wait or (lambda: link_seam.wait_before_retry(stop))
        self.stop = stop
        self.deadline = time.monotonic() + timeouts.device
        self.tried: set[int] = set()
        self.ssh_id: str | None = None
        self.check: HostKeyCheck | None = None
        self.hint: Platform | None = None
        self.facts: VersionFacts | None = None
        self.privilege: LandingPrivilege | Unknown | None = None
        self.neighbours: dict[NeighbourProtocol, Neighbours] = {}
        self.collection: Collected | None = None

    def run(self) -> DeviceRecord | Alias:
        placement = self.scope.placement(self.ip)
        if placement is not Placement.INSIDE:
            self.emit(ev.OutOfScopeRefused(self.ip, SSH_PORT, placement))
            excluded = placement is Placement.EXCLUDED
            return self.unvisited(
                UnvisitedReason.EXCLUDED if excluded else UnvisitedReason.OUTSIDE_SCOPE
            )
        while True:
            lease: LoginLease | None = None
            if self.ssh_id is not None:  # presented before: choose the set before dialling
                chosen = self.next_lease()
                if isinstance(chosen, DeviceRecord):
                    return chosen
                lease = chosen
            elif self.sets.all_retired():
                return self.unvisited(UnvisitedReason.SETS_RETIRED)
            try:
                found = self.attempt(lease)
            finally:
                if lease is not None:
                    lease.release()  # a lease never finished spends nothing
            if found is not None:
                return found

    def attempt(self, lease: LoginLease | None) -> DeviceRecord | Alias | None:
        """One connection, with at most one password; None when the next set may be tried.

        On the first connection the set is chosen only once the identification string is
        read; if it may not log in now, the link is closed and the wait for its turn comes
        later, with no link open.
        """
        link = self.connect()
        if isinstance(link, DeviceRecord | Alias):
            return link
        try:
            if lease is not None:
                return self.log_in_and_examine(link, lease)
            taken = self.lease_now()
            if not isinstance(taken, LoginLease):
                return taken
            with taken:
                return self.log_in_and_examine(link, taken)
        finally:
            self.stop.release(link)

    def log_in_and_examine(self, link: Link, lease: LoginLease) -> DeviceRecord | Alias | None:
        if lease.view.number not in {v.number for v in self.untried()}:
            # It presented itself differently this time and the set no longer fits it:
            # count the set as used here rather than choose round in circles.
            self.tried.add(lease.view.number)
            return None
        outcome = self.log_in(link, lease)
        if isinstance(outcome, CredentialSetView):
            return self.examine(link, outcome)
        return outcome

    # -- Connecting, and what the device presents before any password -----------------------

    def connect(self) -> Link | DeviceRecord | Alias:
        """Dial (with the one retry), read the identification string, check the host key."""
        if self.stop.requested:  # #56: no new connection once the Run is stopping
            return self.unvisited(UnvisitedReason.RUN_STOPPED)
        link = self.dial_with_retry()
        if isinstance(link, DeviceRecord):
            return link
        refused = self.read_presented(link)
        if refused is not None:
            self.stop.release(link)
            return self.unvisited(refused)
        holder = (
            None if self.identity is None else self.identity.claim_host_key(self.ip, link.host_key)
        )
        if holder is not None and holder != self.ip:
            self.stop.release(link)  # story 73: the same device, already examined: no password
            return Alias(self.ip, holder, AliasEvidence.HOST_KEY)
        return link

    def dial_with_retry(self) -> Link | DeviceRecord:
        """Dial, retrying once after a wait (story 51); say why not, if no link was made."""
        pinned = self.trust.key_types(self.ip, SSH_PORT)
        link = self.dial_once(pinned, retry=False)
        if isinstance(link, DialFailed) and not link.algorithms_too_old:
            self.wait()  # story 51: a connection failure is retried once, after a wait
            if self.stop.requested:
                return self.unvisited(UnvisitedReason.RUN_STOPPED)
            link = self.dial_once(pinned, retry=True)
        if isinstance(link, DialFailed) and link.algorithms_too_old and pinned:
            # Story 44: it would not offer the key type trusted for it. Look once more,
            # asking for any type, only to read what it offers now: never a password.
            link = self.dial_once((), retry=False)
            if not isinstance(link, DialFailed):
                self.read_presented(link)
                self.stop.release(link)
                return self.unvisited(UnvisitedReason.HOST_KEY_CHANGED)
        if isinstance(link, DialFailed):
            return self.unvisited(
                UnvisitedReason.ALGORITHMS_TOO_OLD
                if link.algorithms_too_old
                else UnvisitedReason.UNREACHABLE
            )
        return link

    def dial_once(self, key_types: tuple[str, ...], *, retry: bool) -> Link | DialFailed:
        result = self.dial(
            self.scope, self.ip, SSH_PORT, key_types=key_types, timeouts=self.timeouts
        )
        connection = (
            result.connection if isinstance(result, DialFailed) else ev.ConnectionResult.CONNECTED
        )
        self.emit(ev.ConnectionAttempted(self.ip, SSH_PORT, connection, retry=retry))
        if isinstance(result, DialFailed):
            if result.error is not None:
                self.emit(result.error)
        else:
            self.stop.track(result)  # closed at once by the second Ctrl+C
        return result

    def read_presented(self, link: Link) -> UnvisitedReason | None:
        """Check the identification string and host key; say why to stop, if it must."""
        self.ssh_id = printable(link.ssh_id, _SSH_ID_LIMIT)
        hint = platforms.ssh_id_hint(link.ssh_id)
        self.hint = hint if isinstance(hint, Platform) else None
        if hint is Hint.REJECT or (self.id_gate and not isinstance(hint, Platform)):
            return UnvisitedReason.UNSUPPORTED_ADVERTISED
        check = self.trust.check(self.ip, SSH_PORT, link.host_key)
        self.check = check
        self.emit(
            ev.HostKeyChecked(
                self.ip,
                SSH_PORT,
                link.host_key.key_type,
                link.host_key.fingerprint,
                check.verdict,
                check.trusted_fingerprints[0] if check.trusted_fingerprints else None,
            )
        )
        return _HOST_KEY_STOPS.get(check.verdict)

    # -- The one password attempt -----------------------------------------------------------

    def untried(self) -> list[CredentialSetView]:
        """The eligible sets not yet tried on this device, in order (stories 31-33)."""
        order = self.sets.login_order(self.hint, self.neighbour_hint)
        return [v for v in order if v.number not in self.tried]

    def next_lease(self) -> LoginLease | DeviceRecord:
        """Lease the next set to try, waiting for its turn; call with no link open (story 35)."""
        while True:
            order = self.untried()
            if not order:
                return self.no_set_left()
            number = order[0].number
            lease = self.sets.try_lease(number, failure_budget=self.failure_budget)
            if lease is not None:
                return lease
            self.sets.wait_for_turn(number, failure_budget=self.failure_budget)

    def lease_now(self) -> LoginLease | DeviceRecord | None:
        """Lease the next set to try if it may log in now; never waits (a link is open)."""
        order = self.untried()
        if not order:
            return self.no_set_left()
        return self.sets.try_lease(order[0].number, failure_budget=self.failure_budget)

    def no_set_left(self) -> DeviceRecord:
        """Why no set is left to try: all tried, or the only ones that fit it are retired."""
        if not self.tried:
            hints = (self.hint, self.neighbour_hint)
            fits = any(v.platform_limit in (None, *hints) for v in self.sets.views())
            if fits:
                return self.unvisited(UnvisitedReason.SETS_RETIRED)
        return self.unvisited(UnvisitedReason.AUTHENTICATION_FAILED)

    def log_in(self, link: Link, lease: LoginLease) -> CredentialSetView | DeviceRecord | None:
        """The one password attempt; None means it failed and the next set may be tried.

        The lease is finished at once, before anything else, so the set's next login
        elsewhere in the pool is not held up. A connection lost once the password was sent
        counts as a failed login: the device may have counted it too (AAA lockout).
        """
        view = lease.view
        self.tried.add(view.number)
        result = link.log_in(view.username, lease.password_for_login())
        retired = lease.finish(succeeded=result is LoginResult.SUCCEEDED)
        self.emit(ev.LoginAttempted(self.ip, view.number, view.username, _LOGGED[result]))
        if retired:
            failures = self.sets.failures(view.number)
            self.emit(ev.CredentialSetRetired(view.number, view.username, failures))
        if result is LoginResult.LOST:
            stopped = self.stop.closing  # the second Ctrl+C closed the connection
            return self.unvisited(
                UnvisitedReason.RUN_STOPPED if stopped else UnvisitedReason.UNREACHABLE
            )
        succeeded = result is LoginResult.SUCCEEDED
        if not self.trust_new_key():
            return self.unvisited(UnvisitedReason.RUN_STOPPED, view if succeeded else None)
        return view if succeeded else None

    def trust_new_key(self) -> bool:
        """Write a NEW key now a password was sent; False when the Trust Store can't be written.

        A key trusted on first use but never saved would be trusted on first use again next
        Run, so the secure choice is to stop: leave this device before any command, and let
        no further login start (#49 follow-up).
        """
        if self.check is None:
            return True
        try:
            self.trust.password_sent(self.check)
        except OSError as error:
            self.emit(
                ev.error_event(
                    error, step="write the Trust Store", ip=self.ip, messages=_TRUST_STORE_ERRORS
                )
            )
            return False
        return True

    # -- Inside the session -----------------------------------------------------------------

    def examine(self, link: Link, view: CredentialSetView) -> DeviceRecord | Alias:
        """Identify the Platform, read the facts the crawl needs, then leave."""
        session = DeviceSession(
            self.ip,
            self.emit,
            self.timeouts,
            deadline=self.deadline,
            closing=lambda: self.stop.closing,
        )
        shell = link.open_shell(session.permits)
        if isinstance(shell, ev.ErrorRaised):
            self.emit(shell)
            if self.stop.closing:
                return self.unvisited(UnvisitedReason.RUN_STOPPED, view)
            return self.partial(view, NO_SHELL)
        session.attach(shell)
        try:
            found = self.work(session, view)
        finally:
            session.close()
        if isinstance(found, DeviceRecord | Alias):
            return found
        backup, dropped_by = found
        if not isinstance(backup, str):
            self.backup_sink(*backup)  # the session is closed first: the sink may wait its turn
        reason = backup if isinstance(backup, str) else dropped_by
        if reason is not None:
            return self.partial(view, reason, session)
        return self.record(ev.DeviceOutcome.VISITED, view, session.platform)

    def work(
        self, session: DeviceSession, view: CredentialSetView
    ) -> tuple[tuple[BackupCapture, str] | str, str | None] | DeviceRecord | Alias:
        """Every command of the session: the Backup (or why none) and why it dropped, if so."""
        try:
            found = self.identify(session, view)
            if isinstance(found, DeviceRecord | Alias):
                return found
            platform, facts = found
            self.read_neighbours(session, platform)
            backup = self.capture_backup(session, platform, facts)
            dropped_by = self.collect(session, platform, facts)
        except ClosedByOperatorError:
            if session.platform is None:  # story 83: only an identified device is partial
                return self.unvisited(UnvisitedReason.RUN_STOPPED, view)
            return self.partial(view, CLOSED_BY_OPERATOR, session)
        except SessionDroppedError as dropped:
            return self.partial(view, DROP_REASONS[type(dropped)], session)
        except CommandRefusedError:
            return self.partial(view, REFUSED_COMMAND, session)
        return backup, dropped_by

    def identify(
        self, session: DeviceSession, view: CredentialSetView
    ) -> tuple[Platform, VersionFacts] | DeviceRecord | Alias:
        """Identify the Platform and the device; say why to leave, if it must.

        Raises:
            SessionDroppedError: a command failed or a configuration-mode prompt appeared.
            CommandRefusedError: a command was not on the allow-list (a bug in the tool).
        """
        session.check_prompt()
        for command in platforms.SESSION_SETUP:
            session.send(None, command)
        shown = session.send(None, platforms.SHOW_VERSION)
        found = platforms.identify(shown)
        if isinstance(found, Unsupported):
            return self.unvisited(UnvisitedReason.UNSUPPORTED_IDENTIFIED, view)
        session.identified(found)
        facts = self.read_version(found, shown)
        self.facts = facts
        self.privilege = Unknown("not read: the session was dropped")
        self.privilege = self.read_privilege(session, found, view.username)
        holder = self.serials_holder()
        return (found, facts) if holder is None else Alias(self.ip, holder, AliasEvidence.SERIAL)

    def capture_backup(
        self, session: DeviceSession, platform: Platform, facts: VersionFacts
    ) -> tuple[BackupCapture, str] | str:
        """Read the running config; return it with its identity, or why it is no Backup.

        The config goes only to the Backup sink (spec-37 call 4), never into a record or
        an event. The prompt line was removed with the reply's last line break, so that
        line break is put back: the Backup is the config exactly as the device sent it.
        """
        command = platforms.backup_command(platform)
        config = session.send(platform, command, timeout=self.timeouts.backup)
        captured_at = datetime.now(UTC)
        problem = platforms.backup_problem(platform, config)
        if problem is not None:
            return problem
        capture = BackupCapture(
            self.ip, platform, facts.hostname, facts.serials, command, captured_at
        )
        return capture, f"{config}\n"

    def read_version(self, platform: Platform, shown: str) -> VersionFacts:
        facts = platforms.read_version(platform, shown)
        for value in (facts.hostname, facts.model, facts.software_version, facts.serials):
            if isinstance(value, Unknown):
                self.parse_failed(platforms.SHOW_VERSION, _PARSER[platform], value)
        return facts

    def read_privilege(
        self, session: DeviceSession, platform: Platform, username: str
    ) -> LandingPrivilege | Unknown:
        command = platforms.privilege_command(platform, username)
        if command is None:
            privilege: LandingPrivilege | Unknown = Unknown(_USERNAME_DOES_NOT_FIT)
        else:
            try:
                privilege = platforms.read_privilege(platform, session.send(platform, command))
            except SessionDroppedError:
                self.identified(platform, Unknown("the session was dropped"))
                raise
            if isinstance(privilege, Unknown):
                self.parse_failed(command, _PARSER[platform], privilege)
        self.identified(platform, privilege)
        return privilege

    def serials_holder(self) -> IPv4Address | None:
        """Return the IP already examined with one of this device's serials, if any."""
        serials = None if self.facts is None else self.facts.serials
        if self.identity is None or not isinstance(serials, tuple):
            return None  # no serial read: only the host key can tell an alias (story 73)
        holder = self.identity.claim_serials(self.ip, serials)
        return None if holder == self.ip else holder

    def read_neighbours(self, session: DeviceSession, platform: Platform) -> None:
        """Read the CDP, then the LLDP, table (stories 60-65)."""
        for protocol, command in platforms.neighbour_commands(platform):
            found = platforms.read_neighbours(platform, protocol, session.send(platform, command))
            if isinstance(found, Unknown):
                self.parse_failed(command, platforms.NEIGHBOUR_PARSER, found)
                self.neighbours[protocol] = found
            else:
                self.neighbours[protocol] = Reading((command,), found)

    def collect(
        self, session: DeviceSession, platform: Platform, facts: VersionFacts
    ) -> str | None:
        """Send the Platform's collection commands (#59, #60); return why the session dropped.

        A command that drops the session leaves it and every later one unknown, and its
        reason makes the device partial. Each denied or unreadable command is audited.
        """
        dropped: list[str] = []

        def send(command: str) -> str | Unknown:
            if not dropped:
                try:
                    return session.send(platform, command)
                except SessionDroppedError as error:
                    dropped.append(DROP_REASONS[type(error)])
            return Unknown(f"{command}: {_NOT_READ}")

        collection = platforms.collect(platform, send, facts)
        if collection is not None:
            self.collection = collection.collected
            for problem in collection.problems:
                self.emit(
                    ev.ParseFailed(self.ip, problem.command, collection.parser, problem.reason)
                )
        return dropped[0] if dropped else None

    def identified(self, platform: Platform, privilege: LandingPrivilege | Unknown) -> None:
        shown = privilege.shown if isinstance(privilege, LandingPrivilege) else "unknown"
        self.emit(ev.DeviceIdentified(self.ip, platform, shown))

    def parse_failed(self, command: str, parser: str, unknown: Unknown) -> None:
        self.emit(ev.ParseFailed(self.ip, command, parser, unknown.reason))

    # -- Records ----------------------------------------------------------------------------

    def unvisited(
        self, reason: UnvisitedReason, view: CredentialSetView | None = None
    ) -> DeviceRecord:
        return DeviceRecord(
            self.ip,
            ev.DeviceOutcome.UNVISITED,
            unvisited_reason=reason,
            ssh_id=self.ssh_id,
            host_key=self.check,
            credential_set=view,
        )

    def partial(
        self, view: CredentialSetView, reason: str, session: DeviceSession | None = None
    ) -> DeviceRecord:
        platform = None if session is None else session.platform
        record = self.record(ev.DeviceOutcome.PARTIAL, view, platform)
        return dataclasses.replace(record, partial_reason=reason)

    def record(
        self, outcome: ev.DeviceOutcome, view: CredentialSetView, platform: Platform | None
    ) -> DeviceRecord:
        return DeviceRecord(
            self.ip,
            outcome,
            ssh_id=self.ssh_id,
            host_key=self.check,
            credential_set=view,
            platform=platform,
            landing_privilege=self.privilege,
            version=self.facts,
            collected=self.collected() if platform is not None else None,
        )

    def collected(self) -> Collected:
        """The CDP and LLDP tables (#50) on top of the Platform's collection (#59, #60)."""
        return dataclasses.replace(
            self.collection or Collected.nothing(NOT_COLLECTED),
            cdp=self._table(NeighbourProtocol.CDP),
            lldp=self._table(NeighbourProtocol.LLDP),
        )

    def _table(self, protocol: NeighbourProtocol) -> Neighbours:
        """The table read, or unknown when the session ended before it."""
        return self.neighbours.get(protocol) or Unknown(
            f"{protocol.value} not read: the session ended first"
        )
