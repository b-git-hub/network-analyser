r"""Check that only the operator can read or change the Trust Store folder (#69; decided on #7).

#7 decided that `%LOCALAPPDATA%\NetworkAnalyser\trust\` is readable and writable only by the
operator's Windows user. The Trust Store's 0o700/0o600 modes do nothing on Windows, so the
folder's permissions, and those of `known_hosts` in it, are read here through `_winsys`
before any prompt. The tool never changes them.

Anyone else who can change the folder could make the tool trust an impostor's host key and
so send it a password, and anyone else who can read it learns which devices the operator
reaches. Either refuses (CLAUDE.md: security comes first). So do permissions Windows will not
give, since an account that can change them could also hide them. Only where the operator's
account cannot be known at all (not Windows) does the check merely warn. SYSTEM and
Administrators, who can reach every file anyway, raise nothing.
"""

from dataclasses import dataclass
from pathlib import Path

from network_analyser import _winsys
from network_analyser.run_output.data_folder import DataFolder
from network_analyser.run_output.folder import TRUSTED_SIDS, FolderFacts, shown_name


@dataclass(frozen=True, slots=True)
class TrustFolderCheck:
    """The result of checking who can read or change the Trust Store folder.

    A refusal stops the Run (or `trust-key`) before any prompt. A warning is printed and
    kept for the Run report. Both are fixed ASCII text, safe to print.
    """

    refusal: str | None
    warning: str | None


_CANNOT_TELL = (
    "Warning: could not read who can read or change the Trust Store folder. Check that "
    "only you can: anyone who can change it could make the tool trust an impostor's host key."
)


def check_trust_folder(data: DataFolder, *, facts: FolderFacts | None = None) -> TrustFolderCheck:
    """Check that no account but the operator, SYSTEM and Administrators can reach it.

    Reads the `trust` folder and, once it exists, `known_hosts`. Before the first Run the
    folder does not exist yet, so the nearest folder it will inherit permissions from is read
    instead. Nothing is created or changed.
    """
    facts = facts if facts is not None else FolderFacts()
    operator = facts.user_sid()
    if operator is None:
        return TrustFolderCheck(refusal=None, warning=_CANNOT_TELL)
    folder = data.trust_store.parent
    targets = [p for p in (folder, data.trust_store) if _winsys.os_path(p).exists()]
    place = f"the Trust Store folder, {shown_name(str(folder))}"
    if not targets:
        # Not made yet: the Trust Store makes it on first write, and it inherits from here.
        parent = _nearest_existing(folder)
        targets = [parent]
        place = f"{shown_name(str(parent))}, where the Trust Store folder will be made"
    grants: list[_winsys.Grant] = []
    for target in targets:
        for reader in (facts.modify_grants, facts.read_grants):
            found = reader(str(_winsys.os_path(target)))
            if found is None:
                return TrustFolderCheck(refusal=_unread_refusal(place), warning=None)
            grants.extend(found)
    trusted = TRUSTED_SIDS | {operator}
    others = list(dict.fromkeys(shown_name(g.name) for g in grants if g.sid not in trusted))
    if others:
        return TrustFolderCheck(refusal=_others_refusal(place, others), warning=None)
    return TrustFolderCheck(refusal=None, warning=None)


def _nearest_existing(folder: Path) -> Path:
    while not _winsys.os_path(folder).exists() and folder.parent != folder:
        folder = folder.parent
    return folder


def _unread_refusal(place: str) -> str:
    return (
        f"could not read who can read or change {place}, so the host keys in it cannot be "
        "relied on. Check its permissions (only you should have access), then run again."
    )


def _others_refusal(place: str, others: list[str]) -> str:
    return (
        "accounts other than you, SYSTEM and Administrators can read or change "
        f"{place}: {', '.join(others)}. Anyone who can change it could make the tool trust "
        "an impostor's host key and send it your password. Remove their access, then run "
        "again; the tool does not change permissions."
    )
