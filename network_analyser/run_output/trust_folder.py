r"""Check that only the operator can reach the tool's data folder and Trust Store (#69; #150).

#7 decided that `%LOCALAPPDATA%\NetworkAnalyser\trust\` is readable and writable only by the
operator's Windows user, and the folder holds the stored Cisco API Key file as well (#150). The
Trust Store's 0o700/0o600 modes do nothing on Windows, so permissions are read here through
`_winsys` before any prompt: the data folder, `cisco-key.age`, the `trust\` folder and
`known_hosts`. The tool never changes them.

Anyone else who can change the Trust Store could make the tool trust an impostor's host key and
so send it a password; anyone else who can read or change the data folder could read or replace
the stored Cisco API Key. Either refuses (CLAUDE.md: security comes first). So do permissions
Windows will not give, since an account that can change them could also hide them. Only where
the operator's account cannot be known at all (not Windows) does the check merely warn. SYSTEM
and Administrators, who can reach every file anyway, raise nothing.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from network_analyser import _winsys
from network_analyser.run_output.data_folder import DataFolder
from network_analyser.run_output.folder import TRUSTED_SIDS, FolderFacts, shown_name


@dataclass(frozen=True, slots=True)
class TrustFolderCheck:
    """The result of checking who can read or change the data folder and Trust Store.

    A refusal stops the Run (or `trust-key`) before any prompt. A warning is printed and
    kept for the Run report. Both are fixed ASCII text, safe to print.
    """

    refusal: str | None
    warning: str | None


_CANNOT_TELL = (
    "Warning: could not read who can read or change the tool's data folder or Trust Store. "
    "Check that only you can: anyone who can change them could make the tool trust an "
    "impostor's host key, or read or replace the stored Cisco API key."
)
_TRUST_RISK: Final = (
    "Anyone who can change it could make the tool trust an impostor's host key and send it "
    "your password."
)
_KEY_RISK: Final = "Anyone who can change it could read or replace the Cisco API key kept there."


@dataclass(frozen=True, slots=True)
class _Place:
    """One path whose permissions are read, and what is at risk when someone else can reach it.

    Attributes:
        path: where to read the permissions.
        shown: how the refusal names it to the operator.
        at_risk: what cannot be relied on when the permissions cannot be read.
        risk: why another account's access refuses the Run.
    """

    path: Path
    shown: str
    at_risk: str
    risk: str


def check_trust_folder(data: DataFolder, *, facts: FolderFacts | None = None) -> TrustFolderCheck:
    """Check that no account but the operator, SYSTEM and Administrators can reach the data.

    Reads the data folder, the Cisco API key file once it exists, the `trust` folder and
    `known_hosts` once they exist. Before the first Run a folder does not exist yet, so the
    nearest folder it will inherit permissions from is read instead. Nothing is created or
    changed.
    """
    facts = facts if facts is not None else FolderFacts()
    operator = facts.user_sid()
    if operator is None:
        return TrustFolderCheck(refusal=None, warning=_CANNOT_TELL)
    for place in _places(data):
        grants: list[_winsys.Grant] = []
        for reader in (facts.modify_grants, facts.read_grants):
            found = reader(str(_winsys.os_path(place.path)))
            if found is None:
                return TrustFolderCheck(refusal=_unread_refusal(place), warning=None)
            grants.extend(found)
        trusted = TRUSTED_SIDS | {operator}
        others = list(dict.fromkeys(shown_name(g.name) for g in grants if g.sid not in trusted))
        if others:
            return TrustFolderCheck(refusal=_others_refusal(place, others), warning=None)
    return TrustFolderCheck(refusal=None, warning=None)


def _places(data: DataFolder) -> tuple[_Place, ...]:
    """Every path to read, once each, the data folder first.

    A path that does not exist yet is replaced by the nearest folder it will inherit from, so
    the check still says who could read what will be written there.
    """
    places: list[_Place] = []
    root = data.root
    if _winsys.os_path(root).exists():
        places.append(
            _Place(
                root,
                f"the tool's data folder, {shown_name(str(root))}",
                "the Cisco API key kept in it",
                _KEY_RISK,
            )
        )
    else:
        parent = _nearest_existing(root)
        places.append(
            _Place(
                parent,
                f"{shown_name(str(parent))}, where the tool's data folder will be made",
                "the Cisco API key kept in it",
                _KEY_RISK,
            )
        )
    if _winsys.os_path(data.cisco_key_file).exists():
        places.append(
            _Place(
                data.cisco_key_file,
                f"the Cisco API key file, {shown_name(str(data.cisco_key_file))}",
                "the Cisco API key in it",
                _KEY_RISK,
            )
        )
    folder = data.trust_store.parent
    if _winsys.os_path(folder).exists():
        places.append(
            _Place(
                folder,
                f"the Trust Store folder, {shown_name(str(folder))}",
                "the host keys in it",
                _TRUST_RISK,
            )
        )
    else:
        parent = _nearest_existing(folder)
        places.append(
            _Place(
                parent,
                f"{shown_name(str(parent))}, where the Trust Store folder will be made",
                "the host keys in it",
                _TRUST_RISK,
            )
        )
    if _winsys.os_path(data.trust_store).exists():
        places.append(
            _Place(
                data.trust_store,
                f"the Trust Store folder, {shown_name(str(folder))}",
                "the host keys in it",
                _TRUST_RISK,
            )
        )
    return _once(places)


def _once(places: list[_Place]) -> tuple[_Place, ...]:
    """The places once each by path, keeping the first (the data folder's) wording."""
    seen: set[Path] = set()
    kept: list[_Place] = []
    for place in places:
        if place.path in seen:
            continue
        seen.add(place.path)
        kept.append(place)
    return tuple(kept)


def _nearest_existing(folder: Path) -> Path:
    while not _winsys.os_path(folder).exists() and folder.parent != folder:
        folder = folder.parent
    return folder


def _unread_refusal(place: _Place) -> str:
    return (
        f"could not read who can read or change {place.shown}, so {place.at_risk} cannot be "
        "relied on. Check its permissions (only you should have access), then run again."
    )


def _others_refusal(place: _Place, others: list[str]) -> str:
    return (
        "accounts other than you, SYSTEM and Administrators can read or change "
        f"{place.shown}: {', '.join(others)}. {place.risk} Remove their access, then run "
        "again; the tool does not change permissions."
    )
