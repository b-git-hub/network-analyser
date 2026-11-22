"""`network-analyser cisco-key set|show|remove` (ticket #103; ADR 0008; stories 23-33, 38).

    set     ask the Backup Passphrase (checked against the check file, 3 tries), then the
            client ID and secret at masked prompts, lock them into `cisco-key.age`, and
            send one token-only request to Cisco unless `--no-check`; `--proxy host:port`
            picks the proxy for that one request.
    show    say whether a key is stored and when it was set, without asking for the
            passphrase; with `--last-4`, ask for it and show the client ID's last 4
            characters.
    remove  delete the key file after a [y/N] confirmation.

All three hold the data folder's single-instance lock and check that only the operator can
reach the Trust Store folder, so none can run during a Run (story 32). The client ID, the
client secret and the bearer token are `Secret`s from the moment they exist and join the
command's secret scan; only `advisories` reveals them (to make Cisco's request), plus
`backup_store` to lock or unlock the file. `set` refuses when no check file exists yet
(story 25), and `show` reports a key file the passphrase cannot open once (story 38).
"""

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from network_analyser import advisories, backup_store, run_output
from network_analyser.cli.console import scanned_console
from network_analyser.cli.crash_dump_guard import guard_crash_dumps
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import PROG
from network_analyser.cli.prompts import Prompter
from network_analyser.cli.run_folder import (
    RefusedError,
    console_text,
    find_data_folder,
    fixed_message,
    hold_instance_lock,
    refuse,
)
from network_analyser.cli.trust_folder import check_trust_folder
from network_analyser.credentials import Secret, SecretScan
from network_analyser.records.cisco import TokenOutcome, TokenResult

TRIES: Final = 3
_NO_CHECK_FILE: Final = "no Backup Passphrase has been set yet: the first Run sets it"
_HELP_FOR_FORGOTTEN: Final = f'If you have forgotten it, see "{PROG} change-passphrase --help".'
_NO_KEY: Final = "No Cisco API key is stored. Add one with `cisco-key set`."
_KEY_NOT_WRITTEN: Final = "the Cisco API key file could not be written"
_KEY_NOT_REMOVED: Final = "the Cisco API key file could not be removed"

_LEAST_PRIVILEGE: Final = (
    "Before you store the key, set Cisco's side up with least privilege (the tool cannot\n"
    "check any of this; it is on you):\n"
    "  - one Service app with the client-credentials grant, and only the three APIs ticked\n"
    "    (openVuln, EoX and Software Suggestion);\n"
    "  - an end date on the API Developer role;\n"
    "  - the registration email deleted once the secret is in your password manager."
)


def cisco_key(args: argparse.Namespace) -> ExitCode:
    """Run one of `set`, `show` or `remove`, under the single-instance lock."""
    scan = SecretScan()  # empty until the first secret is typed
    with scanned_console(scan):
        try:
            data = find_data_folder()
            with hold_instance_lock(data):
                check_trust_folder(data)  # #69: only the operator may reach the Trust Store
                return _dispatch(args, data, scan)
        except RefusedError as error:
            refuse(args.command, fixed_message(error))
            return ExitCode.REFUSED
        finally:
            _warn_of_scan_hits(scan)
            scan.forget()  # no secret typed here outlives the command (#143)


def _dispatch(args: argparse.Namespace, data: run_output.DataFolder, scan: SecretScan) -> ExitCode:
    action = args.cisco_key_command
    if action == "set":
        return _set(args, data, scan)
    if action == "show":
        return _show(data, scan, last_four=args.last_4)
    return _remove(data)


# -- set (stories 24-29) ---------------------------------------------------------------------


def _set(args: argparse.Namespace, data: run_output.DataFolder, scan: SecretScan) -> ExitCode:
    if not data.check_file.exists():
        raise RefusedError(_NO_CHECK_FILE)
    ask = Prompter.for_this_process()
    if not guard_crash_dumps(ask):
        return ExitCode.REFUSED
    passphrase = _checked(ask, data.check_file, "Backup Passphrase: ", "Nothing was stored.")
    if isinstance(passphrase, ExitCode):
        return passphrase
    passphrase.add_to_scan(scan)
    try:
        ask.say(_LEAST_PRIVILEGE)
        client_id = _secret(ask, "Cisco API client ID: ", scan)
        client_secret = _secret(ask, "Cisco API client secret: ", scan)
        try:
            return _store_and_check(args, data, ask, scan, passphrase, client_id, client_secret)
        finally:
            client_id.wipe()
            client_secret.wipe()
    finally:
        passphrase.wipe()  # ADR 0008: set wipes all three, whatever the check did


def _store_and_check(  # noqa: PLR0913, PLR0917 (set's whole state, each part named)
    args: argparse.Namespace,
    data: run_output.DataFolder,
    ask: Prompter,
    scan: SecretScan,
    passphrase: backup_store.BackupPassphrase,
    client_id: Secret,
    client_secret: Secret,
) -> ExitCode:
    """Lock the key, then send the one token-only check unless `--no-check`."""
    ask.say("Locking the key with the Backup Passphrase (about a second)...")
    try:
        backup_store.lock_key_file(
            data.cisco_key_file,
            client_id,
            client_secret,
            passphrase,
            set_at=datetime.now(UTC),
        )
    except OSError as error:
        raise RefusedError(_KEY_NOT_WRITTEN) from error
    ask.say(f"Cisco API key stored: {console_text(str(data.cisco_key_file))}")
    if args.no_check:
        ask.say("Skipped the online check (--no-check).")
        return ExitCode.CLEAN
    ask.say("Checking the key with Cisco (one token request, no device data)...")
    proxy = advisories.ProxyConfig.explicit(args.proxy) if args.proxy else None
    return _report_token(
        ask, advisories.check_api_key(client_id, client_secret, scan=scan, proxy=proxy)
    )


def _secret(ask: Prompter, prompt: str, scan: SecretScan) -> Secret:
    """Ask for the client ID or secret at a masked prompt; refuse an empty answer."""
    while True:
        secret = ask.secret(prompt)
        if not secret.is_empty():
            scan.watch(secret)
            return secret
        ask.say("  It cannot be empty. Type it again (Ctrl+C cancels).")


def _report_token(ask: Prompter, result: TokenResult) -> ExitCode:
    if result.outcome is TokenOutcome.OK:
        ask.say("Cisco accepted the API key: the token was issued.")
        return ExitCode.CLEAN
    if result.outcome is TokenOutcome.REJECTED:
        ask.say(
            f"Cisco rejected the API key{_token_detail(result)}. The key is still stored; "
            "run `cisco-key set` again with a working key."
        )
        return ExitCode.NEEDS_ATTENTION
    ask.say(
        "Cisco did not answer the key check, so the key could not be verified. The key is "
        "still stored."
    )
    return ExitCode.NEEDS_ATTENTION


def _token_detail(result: TokenResult) -> str:
    parts = [f"HTTP {result.status}"] if result.status is not None else []
    if result.error_code is not None:
        parts.append(result.error_code)
    return f" ({', '.join(parts)})" if parts else ""


# -- show (story 30) -------------------------------------------------------------------------


def _show(data: run_output.DataFolder, scan: SecretScan, *, last_four: bool) -> ExitCode:
    """Say whether a key is stored and when; ask for the passphrase only for the last 4 (#150)."""
    path = data.cisco_key_file
    if not path.is_file():
        print(_NO_KEY)
        return ExitCode.CLEAN
    set_time = backup_store.key_file_set_time(path)
    if set_time is None:
        print("A Cisco API key is stored.")
    else:
        print(f"A Cisco API key is stored, set {_utc_text(set_time)}.")
    if not last_four:
        return ExitCode.CLEAN
    ask = Prompter.for_this_process()
    if not guard_crash_dumps(ask):
        return ExitCode.REFUSED
    passphrase = _checked(ask, data.check_file, "Backup Passphrase: ", "Nothing was shown.")
    if isinstance(passphrase, ExitCode):
        return passphrase
    passphrase.add_to_scan(scan)
    opened = backup_store.open_key_file(path, passphrase)
    if opened.key is None:
        print(opened.problem or backup_store.KEY_LOCKED_ELSEWHERE, file=sys.stderr)  # story 38
        return ExitCode.NEEDS_ATTENTION
    key = opened.key
    key.add_to_scan(scan)
    print(f"  The client ID ends in {key.client_id_suffix()}.")
    return ExitCode.CLEAN


def _utc_text(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


# -- remove (story 31) -----------------------------------------------------------------------


def _remove(data: run_output.DataFolder) -> ExitCode:
    path = data.cisco_key_file
    if not path.is_file():
        print(_NO_KEY)
        return ExitCode.CLEAN
    ask = Prompter.for_this_process()
    question = f"Remove the Cisco API key in {console_text(str(path))}? [y/N] "
    if not ask.yes_no(question, default=False):
        ask.say("Cancelled. Nothing was removed.")
        return ExitCode.STOPPED
    try:
        backup_store.remove_key_file(path)
    except OSError as error:
        raise RefusedError(_KEY_NOT_REMOVED) from error
    ask.say("Cisco API key removed.")
    return ExitCode.CLEAN


# -- shared ----------------------------------------------------------------------------------


def _checked(
    ask: Prompter,
    check_file: Path,
    prompt: str,
    nothing: str,
) -> backup_store.BackupPassphrase | ExitCode:
    """Ask for the Backup Passphrase and check it against the check file (3 tries)."""
    try:
        for attempt in range(1, TRIES + 1):
            typed = ask.secret(prompt)
            held = None
            if backup_store.passphrase_problem(typed) is None:  # a short one cannot unlock it
                ask.say("Checking it against its check file (about a second)...")
                held = backup_store.unlock_check_file(check_file, typed)
            if held is not None:
                ask.say("Backup Passphrase accepted: it unlocked the check file.")
                return held
            ask.say(f"  That does not unlock its check file (try {attempt} of {TRIES}).")
    except backup_store.CheckFileError as error:
        raise RefusedError(fixed_message(error)) from error
    ask.say(
        f"Stopped: it did not unlock its check file after {TRIES} tries. {nothing} "
        f"{_HELP_FOR_FORGOTTEN}"
    )
    return ExitCode.REFUSED


def _warn_of_scan_hits(scan: SecretScan) -> None:
    if scan.hits:
        print(
            f"Warning: the secret scan replaced {_count(scan.hits, 'piece')} of this output "
            "with [blocked],\nbecause they matched a secret typed here. This is a bug in the "
            "tool.",
            file=sys.stderr,
        )


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"
