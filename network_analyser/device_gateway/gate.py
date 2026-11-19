"""The one gate every command passes: `DeviceSession.send(platform, command)` (stories 53-56).

A command reaches a device only if it is on that Platform's compiled-in allow-list, exactly
(`platforms.permits`). Before the Platform is identified, only the commands every Platform
allows may go. The library's own writes pass the same gate (`DeviceSession.permits`, given
to `Link.open_shell`), so Netmiko's session set-up cannot slip past it. Every command sent
is in `audit.log` as its exact string, with its duration, size and result, but never its
output (story 162).

The session is dropped at once if a configuration-mode prompt appears (story 55).
"""

import time
from collections.abc import Callable
from ipaddress import IPv4Address
from typing import Final

from network_analyser import platforms
from network_analyser.device_gateway.link import Shell
from network_analyser.device_gateway.text import clean_output
from network_analyser.records import Platform
from network_analyser.records.events import AuditEvent, CommandResult, CommandSent
from network_analyser.records.run_request import Timeouts

type Emit = Callable[[AuditEvent], None]


class CommandRefusedError(Exception):
    """A command is not on the Platform's allow-list, so it was never sent.

    Always a bug in the tool, never the device's doing. The message is fixed text.
    """


class SessionDroppedError(Exception):
    """The session must be dropped at once. Each subclass names why."""


class ConfigModeError(SessionDroppedError):
    """A configuration-mode prompt appeared."""


class OutputTooLargeError(SessionDroppedError):
    """A reply passed the output cap."""


class CommandTimedOutError(SessionDroppedError):
    """A command did not finish in time."""


class NoReplyError(SessionDroppedError):
    """A command, or the prompt, got no complete reply."""


class DeviceTimedOutError(SessionDroppedError):
    """The per-device timeout ran out (story 50)."""


CONFIG_MODE: Final = "a configuration-mode prompt appeared, so the session was dropped"
DROP_REASONS: Final = {
    ConfigModeError: CONFIG_MODE,
    OutputTooLargeError: "a reply was larger than the output cap, so the session was dropped",
    CommandTimedOutError: "a command timed out, so the session was dropped",
    NoReplyError: "a command got no complete reply, so the session was dropped",
    DeviceTimedOutError: "the per-device timeout ran out, so the session was dropped",
}
"""The fixed reason a device record gives for each kind of drop."""


class DeviceSession:
    """One logged-in CLI session, behind the allow-list gate. Used by one thread."""

    def __init__(
        self, ip: IPv4Address, emit: Emit, timeouts: Timeouts, *, deadline: float | None = None
    ) -> None:
        """Make the gate for the device at `ip`; `attach` the shell once it is open.

        `deadline` is when the per-device timeout runs out, on `time.monotonic()`'s clock;
        no command starts after it, and none may run past it. None for no deadline.
        """
        self._ip = ip
        self._emit = emit
        self._timeouts = timeouts
        self._deadline = deadline
        self._platform: Platform | None = None
        self._shell: Shell | None = None

    @property
    def platform(self) -> Platform | None:
        """The Platform identified on this session; None until then."""
        return self._platform

    def permits(self, line: str) -> bool:
        """The gate for any line the library sends on its own: the same allow-list."""
        return platforms.permits(self._platform, line)

    def attach(self, shell: Shell) -> None:
        """Use `shell`, opened with this session's `permits` as its gate."""
        self._shell = shell

    def identified(self, platform: Platform) -> None:
        """Record the Platform `show version` named: its allow-list now applies."""
        self._platform = platform

    def send(self, platform: Platform | None, command: str) -> str:
        """Send one allow-listed command and return its cleaned output, prompt removed.

        Args:
            platform: the Platform the command is meant for; None before identification.
                It must be the session's own, so a command for one Platform can never
                reach a device of another.
            command: the exact command.

        Raises:
            CommandRefusedError: not permitted; nothing was sent.
            SessionDroppedError: the command failed or a configuration-mode prompt
                appeared; the caller closes the session.
        """
        shell = self._shell
        if (
            shell is None
            or platform is not self._platform
            or not platforms.permits(platform, command)
        ):
            msg = "the command is not on the Platform's allow-list, so it was not sent"
            raise CommandRefusedError(msg)
        started = time.monotonic()
        timeout = self._timeouts.command
        if self._deadline is not None:
            if started >= self._deadline:
                raise DeviceTimedOutError
            timeout = min(timeout, self._deadline - started)
        reply = shell.run(command, timeout)
        took = round((time.monotonic() - started) * 1000)
        if reply.error is not None:
            self._emit(reply.error)
        size = 0 if reply.text is None else len(reply.text)
        result = CommandResult.ERROR if reply.too_large else reply.result
        self._emit(CommandSent(self._ip, command, took, size, result))
        if reply.too_large:
            raise OutputTooLargeError
        if reply.result is CommandResult.TIMEOUT:
            raise CommandTimedOutError
        if reply.result is not CommandResult.OK or reply.text is None:
            raise NoReplyError
        body, _, prompt = clean_output(reply.text).rstrip("\n").rpartition("\n")
        if platforms.is_config_prompt(prompt):
            raise ConfigModeError
        return body

    def check_prompt(self) -> None:
        """Read the prompt; drop the session if it is a configuration-mode prompt.

        Raises:
            SessionDroppedError: no prompt came, or it is a configuration-mode prompt.
        """
        if self._shell is None:
            raise NoReplyError
        prompt = self._shell.prompt()
        if not isinstance(prompt, str):
            self._emit(prompt)
            raise NoReplyError
        if platforms.is_config_prompt(clean_output(prompt)):
            raise ConfigModeError

    def close(self) -> None:
        """Leave at once."""
        if self._shell is not None:
            self._shell.close()
