"""The Run folder: its name, its exclusive creation, and the checks made before any prompt.

Decided on #26 (spec #37 stories 104 and 117-123). Every Run gets a new folder named
`<UTC start>[_<label>]`, created exclusively and never reused, overwritten or deleted.
"""

import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath

from network_analyser import _winsys
from network_analyser.records.safe_names import safe_name_problem

LABEL_MAX = 32
_MAX_SUFFIX = 999
_PROBE_PREFIX = ".network-analyser-probe-"

# Accounts whose ability to modify the Run folder raises no warning (#26), nor their access
# to the Trust Store folder (#69): SYSTEM and Administrators, plus CREATOR OWNER and OWNER
# RIGHTS, which stand for whoever creates or owns an item. To create one inside the folder
# an account needs a right of its own, which is warned about. The operator's own SID is
# added at the check.
TRUSTED_SIDS = frozenset({"S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-3-4"})

_PLACES = {
    _winsys.DriveKind.NETWORK: "a network location",
    _winsys.DriveKind.REMOVABLE: "a removable drive",
}
_SYNCED = "a cloud-synced folder"


@dataclass(frozen=True, slots=True)
class FolderFacts:
    """What Windows says about a folder: a seam, so tests can give the answers."""

    drive_kind: Callable[[str], _winsys.DriveKind] = field(default=_winsys.drive_kind)
    sync_roots: Callable[[], tuple[str, ...]] = field(default=_winsys.sync_roots)
    modify_grants: Callable[[str], tuple[_winsys.Grant, ...] | None] = field(
        default=_winsys.modify_grants
    )
    user_sid: Callable[[], str | None] = field(default=_winsys.current_user_sid)
    read_grants: Callable[[str], tuple[_winsys.Grant, ...] | None] = field(
        default=_winsys.read_grants
    )


@dataclass(frozen=True, slots=True)
class RunsParentCheck:
    """The result of checking where the Run folder will go, before any prompt (story 119).

    The notice and the warning are printed at once and kept for the Run report.
    """

    parent: Path
    """The absolute parent the Run folder will be created in."""
    location_notice: str | None
    """One line when the parent is a network, cloud-synced or removable location (story 120)."""
    permissions_warning: str | None
    """One line when others than the operator, SYSTEM and Administrators can modify it, or
    when that could not be read (story 121)."""

    @property
    def notices(self) -> tuple[str, ...]:
        """The notice and the warning that apply, in the order they are shown."""
        return tuple(n for n in (self.location_notice, self.permissions_warning) if n)


def check_runs_parent(parent: Path, *, facts: FolderFacts | None = None) -> RunsParentCheck:
    """Check that a Run folder can be created and written under `parent` (story 119).

    Creates `parent` if it is missing. Then makes a probe folder there, writes a file in it
    and reads the probe folder's permissions, which it inherits just as the Run folder will
    (the tool sets none, #26). The probe is the tool's own and is removed again; no Run
    folder is created, so none is ever left behind for a Run that is not started.

    Raises:
        RunFolderError: a folder cannot be created or written under `parent`.
    """
    facts = facts if facts is not None else FolderFacts()
    parent = Path(os.path.abspath(parent))  # noqa: PTH100 (normalises `..` too)
    probe = parent / f"{_PROBE_PREFIX}{secrets.token_hex(8)}"
    io_probe = _winsys.os_path(probe)
    try:
        _winsys.os_path(parent).mkdir(parents=True, exist_ok=True)
        io_probe.mkdir()
    except OSError as error:
        msg = "a Run folder cannot be created there"
        raise RunFolderError(msg) from error
    try:
        _write_probe_file(io_probe / "probe")
        grants = facts.modify_grants(str(io_probe))
    finally:
        _remove_probe(io_probe)
    return RunsParentCheck(
        parent=parent,
        location_notice=_location_notice(parent, facts),
        permissions_warning=_permissions_warning(grants, facts.user_sid()),
    )


def _write_probe_file(path: Path) -> None:
    try:
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(handle, b"probe")
        finally:
            os.close(handle)
    except OSError as error:
        msg = "a Run folder cannot be written there"
        raise RunFolderError(msg) from error


def _remove_probe(io_probe: Path) -> None:
    """Remove the probe file and folder: the tool's own, never a Run folder (story 104)."""
    try:
        (io_probe / "probe").unlink(missing_ok=True)
        io_probe.rmdir()
    except OSError:
        pass  # an empty probe folder left behind is harmless


def _location_notice(parent: Path, facts: FolderFacts) -> str | None:
    place = _PLACES.get(facts.drive_kind(str(parent)))
    windows_parent = PureWindowsPath(str(parent))
    if any(windows_parent.is_relative_to(PureWindowsPath(r)) for r in facts.sync_roots()):
        place = _SYNCED
    if place is None:
        return None
    return (
        f"Notice: the Run folder will be on {place}. Its plaintext files (Topology, "
        "diagrams, Run report, Audit log) can be read there, and synced or copied Backups "
        "stay locked with the old passphrase after change-passphrase."
    )


def _permissions_warning(
    grants: tuple[_winsys.Grant, ...] | None, operator_sid: str | None
) -> str | None:
    if grants is None or operator_sid is None:
        return (
            "Warning: could not read who can modify the Run folder. Anyone who can modify "
            "it could swap in a booby-trapped diagram.html or plant a fake Backup; check "
            "its permissions."
        )
    trusted = TRUSTED_SIDS | {operator_sid}
    others = list(dict.fromkeys(shown_name(g.name) for g in grants if g.sid not in trusted))
    if not others:
        return None
    return (
        "Warning: accounts other than you, SYSTEM and Administrators can modify the Run "
        f"folder: {', '.join(others)}. They could swap in a booby-trapped diagram.html or "
        "plant a fake Backup. The Run goes on; the tool does not change permissions."
    )


def shown_name(name: str) -> str:
    """Return a Windows account name as printable ASCII, anything else escaped as hex."""
    return "".join(
        c if " " <= c <= "~" else c.encode("unicode_escape").decode("ascii") for c in name
    )


def label_problem(label: str) -> str | None:
    """Return why `label` cannot go in a Run folder name, or None when it can (story 118).

    The reason is fixed text and never quotes the label.
    """
    return safe_name_problem(label, LABEL_MAX)


class RunFolderError(Exception):
    """The Run folder could not be created. The message is fixed and holds no path text."""


@dataclass(frozen=True, slots=True)
class RunFolder:
    """A Run folder that now exists."""

    path: Path
    """Its absolute path, as shown to the operator and kept in the Run register."""
    io_path: Path
    r"""The same path in the form to hand to file calls (`\\?\` on Windows, story 122)."""


def run_folder_name(started: datetime, label: str | None) -> str:
    """Return `<UTC start>` or `<UTC start>_<label>`, e.g. `20261118T101530Z_dc1-core`."""
    stamp = started.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return stamp if label is None else f"{stamp}_{label}"


def create_run_folder(parent: Path, started: datetime, label: str | None) -> RunFolder:
    """Create a new Run folder under `parent`, adding `-2`, `-3`... if the name is taken.

    The folder is created exclusively, so an existing folder is never reused (story 118).
    `parent` must be absolute and already exist (`check_runs_parent` makes sure of both).

    Raises:
        RunFolderError: no new folder could be created, or the label is not safe.
    """
    if label is not None and label_problem(label) is not None:
        msg = "the label is not a safe name"
        raise RunFolderError(msg)
    base = run_folder_name(started, label)
    for number in range(1, _MAX_SUFFIX + 1):
        name = base if number == 1 else f"{base}-{number}"
        path = parent / name
        io_path = _winsys.os_path(path)
        try:
            io_path.mkdir()
        except FileExistsError:
            continue
        except OSError as error:
            msg = "the Run folder could not be created"
            raise RunFolderError(msg) from error
        return RunFolder(path=path, io_path=io_path)
    msg = "every Run folder name for this start time is taken"
    raise RunFolderError(msg)
