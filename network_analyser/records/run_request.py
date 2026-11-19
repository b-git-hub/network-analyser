"""The Run request: what `cli` hands `discovery`, with where each setting came from.

The Ready-to-start block says where the Scope, Seeds and options came from (spec #37
story 3; decision #31), so every setting the operator can give more than one way carries
its `Source`. Later tickets add the settings they own.
"""

from dataclasses import dataclass
from enum import Enum, unique
from ipaddress import IPv4Address

from network_analyser.records.scope import ScopeRecord


@unique
class Source(Enum):
    """Where a setting came from. Flags win over the run file (story 3)."""

    COMMAND_LINE = "command line"
    RUN_FILE = "run file"
    PROMPT = "asked"
    DEFAULT = "default"


@dataclass(frozen=True, slots=True)
class Sourced[T]:
    """A setting's value and where it came from."""

    value: T
    source: Source


@dataclass(frozen=True, slots=True)
class Timeouts:
    """How long each step with a device may take, in seconds (story 50).

    Attributes:
        connect: opening the TCP connection.
        login: from the SSH handshake to the end of the password login.
        command: one command's output.
        backup: the running config's output (#51): it can be far longer than any other.
        device: everything done with one device, from the first connection (#50).
    """

    connect: float = 10
    login: float = 20
    command: float = 60
    backup: float = 300
    device: float = 15 * 60


@dataclass(frozen=True, slots=True)
class RunRequest:
    """Everything a Run needs that is not a secret, checked.

    Attributes:
        scope: the checked Scope; its source is where the include entries came from.
        exclusions_source: where the exclusions came from; None when there are none.
        seeds: the checked Seeds, every one inside the Scope, in the order given.
        label: added to the Run folder name; None for no label.
        parallel: devices worked on at once.
        failure_budget: failed logins a Credential Set may spend before it is retired.
        sweep: whether the Scope is swept on TCP 22 for more Seeds.
        timeouts: how long each step with a device may take.
    """

    scope: Sourced[ScopeRecord]
    exclusions_source: Source | None
    seeds: Sourced[tuple[IPv4Address, ...]]
    label: Sourced[str | None]
    parallel: Sourced[int]
    failure_budget: Sourced[int]
    sweep: Sourced[bool]
    timeouts: Timeouts = Timeouts()
