"""Visit one device: log in, identify its Platform, record what it is, and leave (#49).

The order is the safety (ADR 0002, ADR 0003, stories 38-48, 57-59):

1. The Scope, before any socket. An address it does not allow is never dialled.
2. One SSH connection per password attempt. Its identification string is a hint only,
   and `CISCO_WLC` is rejected before login.
3. The Trust Store, before any password. A changed key, or strict mode with an untrusted
   one, is never logged into. A known device is asked only for the key type trusted for it.
4. One password attempt. A NEW key is written once a password was sent.
5. In the same session: the prompt, `terminal length 0`, `terminal width 511`, then
   `show version` decides the Platform. An unsupported one is left at once.
6. The landing privilege, then the running config (#51), then the Platform's collection
   commands (#59), then leave. Nothing is sent to end the session. A whole config goes to
   the Backup sink once the session is closed, and to nothing else; one that is not a
   whole config leaves the device partial. A denied collection command leaves its data
   unknown; a drop during collection keeps the Backup and the data already read.

Every step is an Audit log event; no event holds device output.
"""

import dataclasses
from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import Final, Protocol

from network_analyser import platforms
from network_analyser.credentials import CredentialSets
from network_analyser.device_gateway import ssh
from network_analyser.device_gateway.gate import (
    DROP_REASONS,
    CommandRefusedError,
    DeviceSession,
    Emit,
    SessionDroppedError,
)
from network_analyser.device_gateway.link import Dial, DialFailed, Link, LoginResult
from network_analyser.device_gateway.text import printable
from network_analyser.platforms import Hint, Unsupported
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
from network_analyser.records.collected import Collected
from network_analyser.records.device import (
    DeviceRecord,
    LandingPrivilege,
    Unknown,
    UnvisitedReason,
    VersionFacts,
)
from network_analyser.records.run_request import Timeouts
from network_analyser.trust_store import TrustStore

SSH_PORT: Final = 22
_SSH_ID_LIMIT: Final = 255  # RFC 4253 4.2: the whole line is at most 255 characters
REFUSED_COMMAND: Final = "a command was refused by the allow-list gate (a bug in the tool)"
NO_SHELL: Final = "logged in, but the device's CLI could not be opened"
_USERNAME_DOES_NOT_FIT: Final = "the username does not fit the privilege command's pattern"
_PARSER: Final = {
    Platform.IOS_XE: "ntc-templates cisco_ios",
    Platform.NX_OS: "ntc-templates cisco_nxos",
}
_HOST_KEY_STOPS: Final = {
    HostKeyVerdict.CHANGED: UnvisitedReason.HOST_KEY_CHANGED,
    HostKeyVerdict.NOT_TRUSTED: UnvisitedReason.HOST_KEY_NOT_TRUSTED,
}


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
) -> DeviceRecord:
    """Log into the device at `ip`, identify it and leave; return what was learned.

    Args:
        ip: the device's address. Always an IP, never a name (story 40).
        scope: the Run's Scope: an address outside it is never dialled.
        trust: the Trust Store, checked before any password.
        sets: the Run's Credential Sets, tried in order, one password per connection.
        emit: takes each Audit log event, in order.
        failure_budget: failed logins a set may spend before it is retired.
        backup_sink: takes the running config of a Visited Device, and nothing else does.
        timeouts: how long each step may take.
        dial: opens SSH connections; the real one (`ssh.dial`) unless a test fakes it.
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
    )
    record = visitor.run()
    reason = record.unvisited_reason.value if record.unvisited_reason else record.partial_reason
    emit(ev.DeviceFinished(ip, record.outcome, reason))
    return record


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
        self.tried: set[int] = set()
        self.ssh_id: str | None = None
        self.check: HostKeyCheck | None = None
        self.hint: Platform | None = None

    def run(self) -> DeviceRecord:
        placement = self.scope.placement(self.ip)
        if placement is not Placement.INSIDE:
            self.emit(ev.OutOfScopeRefused(self.ip, SSH_PORT, placement))
            excluded = placement is Placement.EXCLUDED
            return self.unvisited(
                UnvisitedReason.EXCLUDED if excluded else UnvisitedReason.OUTSIDE_SCOPE
            )
        while True:
            if self.sets.all_retired():
                return self.unvisited(UnvisitedReason.SETS_RETIRED)
            if self.tried and not self.untried():
                return self.unvisited(UnvisitedReason.AUTHENTICATION_FAILED)
            link = self.connect()
            if isinstance(link, DeviceRecord):
                return link
            try:
                outcome = self.log_in(link)
                if isinstance(outcome, DeviceRecord):
                    return outcome
                if outcome is not None:
                    return self.examine(link, outcome)
            finally:
                link.close()

    # -- Connecting, and what the device presents before any password -----------------------

    def connect(self) -> Link | DeviceRecord:
        """Dial, read the identification string and check the host key."""
        pinned = self.trust.key_types(self.ip, SSH_PORT)
        link = self.dial_once(pinned)
        if isinstance(link, DialFailed) and link.algorithms_too_old and pinned:
            # Story 44: it would not offer the key type trusted for it. Look once more,
            # asking for any type, only to read what it offers now: never a password.
            link = self.dial_once(())
            if not isinstance(link, DialFailed):
                self.read_presented(link)
                link.close()
                return self.unvisited(UnvisitedReason.HOST_KEY_CHANGED)
        if isinstance(link, DialFailed):
            return self.unvisited(
                UnvisitedReason.ALGORITHMS_TOO_OLD
                if link.algorithms_too_old
                else UnvisitedReason.UNREACHABLE
            )
        stop = self.read_presented(link)
        if stop is not None:
            link.close()
            return self.unvisited(stop)
        return link

    def dial_once(self, key_types: tuple[str, ...]) -> Link | DialFailed:
        result = self.dial(
            self.scope, self.ip, SSH_PORT, key_types=key_types, timeouts=self.timeouts
        )
        connection = (
            result.connection if isinstance(result, DialFailed) else ev.ConnectionResult.CONNECTED
        )
        self.emit(ev.ConnectionAttempted(self.ip, SSH_PORT, connection, retry=False))
        if isinstance(result, DialFailed) and result.error is not None:
            self.emit(result.error)
        return result

    def read_presented(self, link: Link) -> UnvisitedReason | None:
        """Check the identification string and host key; say why to stop, if it must."""
        self.ssh_id = printable(link.ssh_id, _SSH_ID_LIMIT)
        if platforms.ssh_id_hint(link.ssh_id) is Hint.REJECT:
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
        """The eligible sets not yet tried on this device, in order."""
        return [v for v in self.sets.login_order(self.hint) if v.number not in self.tried]

    def log_in(self, link: Link) -> CredentialSetView | DeviceRecord | None:
        """Try the next eligible set; None means it failed and the next one may be tried."""
        hint = platforms.ssh_id_hint(link.ssh_id)
        self.hint = hint if isinstance(hint, Platform) else None
        order = self.untried()
        if not order:
            return self.unvisited(
                UnvisitedReason.SETS_RETIRED
                if self.sets.all_retired()
                else UnvisitedReason.AUTHENTICATION_FAILED
            )
        view = order[0]
        self.tried.add(view.number)
        result = link.log_in(view.username, self.sets.password_for_login(view.number))
        if result is LoginResult.LOST:
            return self.unvisited(UnvisitedReason.UNREACHABLE)
        succeeded = result is LoginResult.SUCCEEDED
        self.emit(
            ev.LoginAttempted(
                self.ip,
                view.number,
                view.username,
                ev.LoginResult.SUCCEEDED if succeeded else ev.LoginResult.FAILED,
            )
        )
        if self.check is not None:
            self.trust.password_sent(self.check)  # a password was sent: trust a NEW key now
        if self.sets.record_login(
            view.number, succeeded=succeeded, failure_budget=self.failure_budget
        ):
            self.emit(
                ev.CredentialSetRetired(view.number, view.username, self.sets.failures(view.number))
            )
        return view if succeeded else None

    # -- Inside the session -----------------------------------------------------------------

    def examine(self, link: Link, view: CredentialSetView) -> DeviceRecord:
        """Identify the Platform, read `show version` and the landing privilege, then leave."""
        session = DeviceSession(self.ip, self.emit, self.timeouts)
        shell = link.open_shell(session.permits)
        if not isinstance(shell, ev.ErrorRaised):
            session.attach(shell)
        else:
            self.emit(shell)
            return self.partial(view, NO_SHELL)
        facts: VersionFacts | None = None
        privilege: LandingPrivilege | Unknown | None = None
        backup: tuple[BackupCapture, str] | str | None = None
        collection: platforms.Collection | None = None
        stop: str | None = None
        try:
            session.check_prompt()
            for command in platforms.SESSION_SETUP:
                session.send(None, command)
            shown = session.send(None, platforms.SHOW_VERSION)
            found = platforms.identify(shown)
            if isinstance(found, Unsupported):
                return self.unvisited(UnvisitedReason.UNSUPPORTED_IDENTIFIED, view)
            session.identified(found)
            facts = self.read_version(found, shown)
            privilege = Unknown("not read: the session was dropped")
            privilege = self.read_privilege(session, found, view.username)
            backup = self.capture_backup(session, found, facts)
            asking = _Asking(session, found)
            collection = platforms.collect(found, asking.send, shown)
            stop = asking.dropped
        except SessionDroppedError as dropped:
            return self.partial(view, DROP_REASONS[type(dropped)], session, facts, privilege)
        except CommandRefusedError:
            stop = REFUSED_COMMAND
        finally:
            session.close()
        for problem in collection.parse_problems if collection else ():
            self.emit(ev.ParseFailed(self.ip, problem.command, problem.parser, problem.reason))
        if isinstance(backup, tuple):
            self.backup_sink(*backup)  # the session is closed first: the sink may wait its turn
        reason = backup if isinstance(backup, str) else stop
        collected = collection.collected if collection else None
        if reason is not None:
            return self.partial(view, reason, session, facts, privilege, collected=collected)
        return self.record(
            ev.DeviceOutcome.VISITED, view, session.platform, facts, privilege, collected=collected
        )

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
                self.parse_failed(platforms.SHOW_VERSION, platform, value)
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
                self.parse_failed(command, platform, privilege)
        self.identified(platform, privilege)
        return privilege

    def identified(self, platform: Platform, privilege: LandingPrivilege | Unknown) -> None:
        shown = privilege.shown if isinstance(privilege, LandingPrivilege) else "unknown"
        self.emit(ev.DeviceIdentified(self.ip, platform, shown))

    def parse_failed(self, command: str, platform: Platform, unknown: Unknown) -> None:
        self.emit(ev.ParseFailed(self.ip, command, _PARSER[platform], unknown.reason))

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

    def partial(  # noqa: PLR0913 (everything a partial record holds)
        self,
        view: CredentialSetView,
        reason: str,
        session: DeviceSession | None = None,
        facts: VersionFacts | None = None,
        privilege: LandingPrivilege | Unknown | None = None,
        *,
        collected: Collected | None = None,
    ) -> DeviceRecord:
        platform = None if session is None else session.platform
        record = self.record(
            ev.DeviceOutcome.PARTIAL, view, platform, facts, privilege, collected=collected
        )
        return dataclasses.replace(record, partial_reason=reason)

    def record(  # noqa: PLR0913 (everything the record holds)
        self,
        outcome: ev.DeviceOutcome,
        view: CredentialSetView,
        platform: Platform | None,
        facts: VersionFacts | None,
        privilege: LandingPrivilege | Unknown | None,
        *,
        collected: Collected | None = None,
    ) -> DeviceRecord:
        return DeviceRecord(
            self.ip,
            outcome,
            ssh_id=self.ssh_id,
            host_key=self.check,
            credential_set=view,
            platform=platform,
            landing_privilege=privilege,
            version=facts,
            collected=collected,
        )


NOT_SENT: Final = "not sent: the session was dropped"


class _Asking:
    """Sends the collection commands for one session; after a drop, sends nothing more.

    A drop ends the session but not the visit: the data already read is kept, every later
    command's data is unknown, and the device is left partial with the drop's reason (#59).
    """

    def __init__(self, session: DeviceSession, platform: Platform) -> None:
        self._session = session
        self._platform = platform
        self.dropped: str | None = None

    def send(self, command: str) -> str | Unknown:
        """Send one command through the gate; `Unknown` once the session was dropped."""
        if self.dropped is not None:
            return Unknown(NOT_SENT)
        try:
            return self._session.send(self._platform, command)
        except SessionDroppedError as error:
            self.dropped = DROP_REASONS[type(error)]
            return Unknown(self.dropped)
