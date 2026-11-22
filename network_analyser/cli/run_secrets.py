"""The secret steps of Run start: the Backup Passphrase, then the Credential Sets.

Decided on #15 (flow A, step by step), #12 and ADR 0004; spec #37 stories 20-24 and 27. They
come after the crash-dump check, and the passphrase comes first, so a wrong passphrase stops
the Run before any device password is typed. Every secret is a `Secret` from the masked
reader on: this file never sees a value. It checks secrets only through `same_as` and
`is_empty`, and the passphrase's length through `backup_store`.

A refusal here prints why and returns exit code 2 (#31: nothing was contacted).
"""

import sys
from collections.abc import Callable
from pathlib import Path

from network_analyser import backup_store
from network_analyser.backup_store import BackupPassphrase, CheckFileError
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import PROG
from network_analyser.cli.prompts import Prompter
from network_analyser.cli.run_folder import console_text, fixed_message
from network_analyser.cli.text import escape_controls
from network_analyser.credentials import (
    MAX_SETS,
    CredentialSet,
    CredentialSets,
    Secret,
    SecretScan,
)
from network_analyser.records import Platform

TRIES = 3
NOTHING_CONTACTED = "Nothing was contacted."
_NO_DEVICE_PASSWORD = f"No device password was typed. {NOTHING_CONTACTED}"
_USERNAME_SHOWN_AT_MOST = 40

_PLATFORM_CHOICES = {"1": Platform.IOS_XE, "2": Platform.NX_OS, "": None}


# -- Backup Passphrase -------------------------------------------------------------------


def backup_passphrase(
    check_file: Path,
    ask: Prompter,
    *,
    key_file: Path | None = None,
    on_start_over: Callable[[], None] | None = None,
) -> BackupPassphrase | ExitCode:
    """Set the Backup Passphrase on a first Run, or check it on a later one (stories 20-22)."""
    try:
        if check_file.exists():
            return _unlock(check_file, ask)
        return _choose(check_file, ask, key_file, on_start_over)
    except CheckFileError as error:
        _stop(f"Refused: {fixed_message(error)} ({console_text(str(check_file))}).")
        return ExitCode.REFUSED


def _choose(
    check_file: Path,
    ask: Prompter,
    key_file: Path | None,
    on_start_over: Callable[[], None] | None,
) -> BackupPassphrase | ExitCode:
    ask.say(
        "First Run: choose the Backup Passphrase. It locks every Backup this tool takes.\n"
        f"  It must be at least {backup_store.PASSPHRASE_MIN} characters. It cannot be "
        "recovered: if you forget it,\n"
        "  every Backup it locked is lost. Keep it in your password manager."
    )
    for attempt in range(1, TRIES + 1):
        first = ask.secret("New Backup Passphrase: ")
        problem = backup_store.passphrase_problem(first)
        if problem is not None:
            ask.say(f"  Refused: {problem}. (try {attempt} of {TRIES})")
            continue
        if not ask.secret("Type it again: ").same_as(first):
            ask.say(f"  The two entries differ. (try {attempt} of {TRIES})")
            continue
        ask.say("Creating the check file (about a second)...")
        passphrase = backup_store.create_check_file(check_file, first)
        ask.say(f"Backup Passphrase set. Check file created: {console_text(str(check_file))}")
        # Starting over (a check file deleted by hand) also deletes the key file: a key
        # locked with the forgotten passphrase is an orphaned secret (story 39). This happens
        # even with `--cisco-lookups off`: story 39 wins over story 9, recorded on #143.
        if key_file is not None and key_file.is_file():
            removed = True
            try:
                backup_store.remove_key_file(key_file)
            except OSError:
                removed = False
                ask.say(
                    "  Warning: a leftover Cisco API key file could not be removed. Remove "
                    f"{console_text(str(key_file))} by hand."
                )
            if removed and on_start_over is not None:
                on_start_over()  # the Run now has no key: say so before the first device prompt
        return passphrase
    _stop(f"Stopped: no Backup Passphrase was set after {TRIES} tries. {_NO_DEVICE_PASSWORD}")
    return ExitCode.REFUSED


def _unlock(check_file: Path, ask: Prompter) -> BackupPassphrase | ExitCode:
    for attempt in range(1, TRIES + 1):
        typed = ask.secret("Backup Passphrase: ")
        passphrase = None
        if backup_store.passphrase_problem(typed) is None:  # a short one cannot unlock it
            ask.say("Checking it against the check file (about a second)...")
            passphrase = backup_store.unlock_check_file(check_file, typed)
        if passphrase is not None:
            ask.say("Backup Passphrase accepted: it unlocked the check file.")
            return passphrase
        ask.say(f"  That does not unlock the check file (try {attempt} of {TRIES}).")
    _stop(
        f"Stopped: the Backup Passphrase did not unlock the check file after {TRIES} tries. "
        f"{_NO_DEVICE_PASSWORD}"
    )
    return ExitCode.REFUSED


# -- Credential Sets ---------------------------------------------------------------------


def credential_sets(
    ask: Prompter, passphrase: BackupPassphrase, scan: SecretScan
) -> CredentialSets | ExitCode:
    """Ask for one to five Credential Sets, one at a time (stories 23-24, 27).

    Each password joins the secret scan the moment it is typed, before anything else is shown.
    """
    ask.say(f"Credential Sets: up to {MAX_SETS}, tried in the order you give them.")
    sets: list[CredentialSet] = []
    while True:
        number = len(sets) + 1
        username = _username(ask, number)
        shown = escape_controls(username, limit=_USERNAME_SHOWN_AT_MOST)
        password = _password(ask, shown)
        scan.watch(password)
        if passphrase.same_as(password):
            _stop(
                f"Refused: the password for {shown} is the same as the Backup Passphrase. "
                "They must differ,\n"
                "so one leaked secret never opens both your devices and your Backups. A "
                "device password\n"
                f'cannot be changed here: change the Backup Passphrase with "{PROG} '
                'change-passphrase",\n'
                f"then start the Run again. {NOTHING_CONTACTED}"
            )
            return ExitCode.REFUSED
        sets.append(CredentialSet(username, password, _platform_limit(ask, shown)))
        if len(sets) == MAX_SETS:
            ask.say(f"That is {MAX_SETS} Credential Sets, the most a Run takes.")
            return CredentialSets(sets)
        if not ask.yes_no("Add another Credential Set? [y/N] ", default=False):
            return CredentialSets(sets)


def _username(ask: Prompter, number: int) -> str:
    while True:
        username = ask.line(f"Set {number} username: ").strip()
        if username:
            return username
        ask.say("  A username is needed.")


def _password(ask: Prompter, shown_username: str) -> Secret:
    while True:
        password = ask.secret(f"Password for {shown_username}: ")
        if not password.is_empty():
            return password
        ask.say("  A Credential Set needs a password. Type it again (Ctrl+C cancels the Run).")


def _platform_limit(ask: Prompter, shown_username: str) -> Platform | None:
    ask.say(f"Limit {shown_username} to a Platform?  1) IOS/IOS-XE  2) NX-OS  Enter) any Platform")
    while True:
        choice = ask.line("Platform: ").strip()
        if choice in _PLATFORM_CHOICES:
            return _PLATFORM_CHOICES[choice]
        ask.say("  Not a choice: type 1 or 2, or press Enter for any Platform.")


def label_is_a_secret(
    label: str | None, passphrase: BackupPassphrase, sets: CredentialSets
) -> bool:
    """Say whether the label is the Backup Passphrase or a set's password (#42 follow-up).

    The label goes into the Run folder name and the Run register, which are never scanned
    for secrets, so a secret typed as the label must stop the Run.
    """
    if label is None:
        return False
    as_secret = Secret(label)
    return passphrase.same_as(as_secret) or sets.password_same_as(as_secret)


def _stop(message: str) -> None:
    print(message, file=sys.stderr)
