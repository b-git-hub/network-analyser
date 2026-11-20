"""What the Run report is built from (#66, stories 156-160).

Plain records only: the crawl's device records, its Backups, the Topology, and the facts
the summary does not already hold (when the Run ran, how it ended, the flags, the notices).
No password, no running config and no command output.
"""

from dataclasses import dataclass
from datetime import datetime

from network_analyser.records.backup import BackupResults
from network_analyser.records.device import DeviceRecord
from network_analyser.records.events import RunEnding
from network_analyser.records.platform import CredentialSetResult
from network_analyser.records.sweep import SweepResult
from network_analyser.records.topology import Topology


@dataclass(frozen=True, slots=True)
class RunReportFacts:
    """The Run's own facts, beside what the crawl and the Topology already hold.

    Attributes:
        started_at: when the Run folder was named, UTC. That is the time in its name.
        ended_at: when the report was written, UTC.
        ending: completed, stopped or crashed.
        stop_reason: why a stopped Run stopped, as fixed text; None otherwise.
        tool_version: the version that made the Run.
        windows_account: the Windows account, or None when Windows did not say.
        pc_name: the PC's name; None when Windows did not say.
        folder: the Run folder's full path.
        scope: the Scope ranges, as shown to the operator.
        exclusions: the exclusions; empty when there are none.
        seeds: the Seeds, in the order given.
        flags: each flag as one line of fixed text, including where it came from.
        notices: location, permissions and Trust Store warnings; empty when there are none.
        secret_scan_hits: stretches already blocked before the report was rendered.
    """

    started_at: datetime
    ended_at: datetime
    ending: RunEnding
    stop_reason: str | None
    tool_version: str
    windows_account: str | None
    pc_name: str | None
    folder: str
    scope: tuple[str, ...]
    exclusions: tuple[str, ...]
    seeds: tuple[str, ...]
    flags: tuple[str, ...]
    notices: tuple[str, ...]
    secret_scan_hits: int


@dataclass(frozen=True, slots=True)
class RunReport:
    """Everything `run-report.html` is drawn from. Never a secret or device output.

    Attributes:
        facts: when, where and how the Run ended, and the flags and notices.
        devices: every device record the crawl kept, dialled or skipped.
        backups: what became of each captured config. An empty result when none was taken.
        topology: the Topology built from `devices`, so ids match `diagram.html`.
        credential_sets: how each Credential Set fared. Never a password.
        sweep: the Sweep, or None when this Run did not sweep.
        attention: what the operator should fix, one item each, as the summary words it.
    """

    facts: RunReportFacts
    devices: tuple[DeviceRecord, ...]
    backups: BackupResults
    topology: Topology
    credential_sets: tuple[CredentialSetResult, ...]
    sweep: SweepResult | None
    attention: tuple[str, ...]
