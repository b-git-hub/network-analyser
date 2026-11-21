"""`network-analyser change-passphrase [--run-folder DIR ...]` (ticket #58; stories 106-116).

Decided on #22 (with #27's correction: one file at a time) and ADR 0004. In order:

    lock -> how far any earlier change went -> crash-dump check -> current passphrase
    -> new passphrase -> find the files -> summary and confirm -> re-lock -> finish

- It holds the single-instance lock throughout, so it never runs alongside a Run or another
  change (story 16).
- Same safeguards as a Run start: the crash-dump check first, then masked prompts. The
  current passphrase must unlock its check file (3 tries). A new passphrase is typed twice,
  is at least 15 characters and differs from the current one (story 109). Both join the
  secret scan the moment they are typed, and everything printed passes through it.
- Files are found through the Run register, plus any `--run-folder`, which is added to the
  register (story 107). A summary of Backups, Runs and folders not found, with a time
  estimate at 3 s per file, comes before the confirm (story 108); nothing is changed before
  it.
- `backup_store` re-locks each file in memory and writes only ciphertext (story 110). Ctrl+C
  finishes the current file and stops; the change stays pending, Runs are refused, and
  running this again resumes, skipping files already done (stories 111-112).
- The end lists what was not re-locked or was flagged, and always shows the fixed warning
  of story 115. A forgotten passphrase has no reset command: the help text documents the
  manual reset, deleting the check file (story 116).

Exit codes: 0 every file re-locked and nothing to look at; 1 the change finished but
something needs attention (a file not re-locked or flagged, a folder not found); 2 refused
before anything was changed; 3 cancelled at the confirm, or stopped by Ctrl+C part way.
"""

import argparse
import signal
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Final

from network_analyser import _winsys, backup_store, run_output
from network_analyser._version import __version__
from network_analyser.backup_store import (
    BackupPassphrase,
    ChangeStage,
    ChangeStatus,
    FileOutcome,
    FileResult,
    PassphraseFiles,
    PendingChange,
    RelockPlan,
    RunResult,
)
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
from network_analyser.credentials import Secret, SecretScan

TRIES: Final = 3
SECONDS_PER_FILE: Final = 3
"""Unlock, lock and check: about a second each at age's default strength (#22, #27)."""

ROTATION_LIMITS: Final = (
    "What re-locking cannot fix:\n"
    "  - Copies made before this change stay locked with the old passphrase: files copied\n"
    "    away, Windows Previous Versions, OneDrive or other sync history, and PC backups.\n"
    "  - Re-locking does not wipe the old file contents from the disk.\n"
    "  - If someone else may know the old passphrase, treat the secrets in these configs as\n"
    "    exposed, and change them on the devices."
)
_HELP_FOR_FORGOTTEN: Final = (
    f'If you have forgotten it, see "{PROG} change-passphrase --help". Nothing was changed.'
)
_PENDING: Final = (
    "A change of the Backup Passphrase was left unfinished. This picks it up where it stopped."
)
_STOPPED: Final = (
    "Stopped. The change is unfinished: Runs are refused until it is done. Run "
    f'"{PROG} change-passphrase" again to resume; files already re-locked are skipped.'
)
_FOLDER_PATH_REFUSED: Final = (
    "a --run-folder path holds text that is the current or new Backup Passphrase, so it "
    "cannot go into the Run register. Nothing was changed."
)
_NOT_STARTED: Final = (
    "the change could not be started: a file in the per-user data folder could not be "
    f'written. Run "{PROG} change-passphrase" again.'
)


def change_passphrase(args: argparse.Namespace) -> ExitCode:
    """Re-lock every Backup and Run manifest under a new Backup Passphrase."""
    scan = SecretScan()  # empty until the first passphrase is typed
    with scanned_console(scan):
        try:
            data = find_data_folder()
            with hold_instance_lock(data):
                return _change(args, data, scan)
        except RefusedError as error:
            refuse(args.command, fixed_message(error))
            return ExitCode.REFUSED
        finally:
            _warn_of_scan_hits(scan)


def _change(args: argparse.Namespace, data: run_output.DataFolder, scan: SecretScan) -> ExitCode:
    files = PassphraseFiles(data.check_file, data.previous_check_file, data.change_pending)
    try:
        status = backup_store.change_status(files)
    except backup_store.CheckFileError as error:
        raise RefusedError(fixed_message(error)) from error
    extras = tuple(Path(folder).absolute() for folder in args.run_folder or ())
    ask = Prompter.for_this_process()
    if status.stage is not ChangeStage.NONE:
        ask.say(_PENDING)
    if not guard_crash_dumps(ask):
        return ExitCode.REFUSED
    passphrases = _passphrases(ask, files, status, scan)
    if isinstance(passphrases, ExitCode):
        return passphrases
    old, new = passphrases
    if any(scan.holds_secret(str(folder)) for folder in extras):
        raise RefusedError(_FOLDER_PATH_REFUSED)
    registered = backup_store.registered_run_folders(data.run_register)
    plan = backup_store.plan_relock([*registered, *extras], io_path=_winsys.os_path)
    _show_summary(ask, plan, status)
    if not ask.yes_no("Re-lock them with the new passphrase? [y/N] ", default=False):
        ask.say("Cancelled. Nothing was changed.")
        return ExitCode.STOPPED
    _register(ask, data.run_register, plan, extras, scan)
    started = _start(files, old, new, scan)
    return _relock_all(files, plan, old, started, scan, data.cisco_key_file)


# -- Passphrases (story 109) ----------------------------------------------------------------


def _passphrases(
    ask: Prompter, files: PassphraseFiles, status: ChangeStatus, scan: SecretScan
) -> tuple[BackupPassphrase, BackupPassphrase | Secret] | ExitCode:
    """The current passphrase, checked; then the new one, checked or chosen.

    Once a change has switched the check file, the new passphrase is the one that change
    chose: it is typed once and checked against the check file.
    """
    old = _checked(ask, status.old_check_file, "Current Backup Passphrase: ")
    if isinstance(old, ExitCode):
        return old
    old.add_to_scan(scan)
    if status.stage is ChangeStage.SWITCHED:
        new = _checked(ask, files.check_file, "New Backup Passphrase (chosen when it started): ")
        if isinstance(new, ExitCode):
            return new
        new.add_to_scan(scan)
        return old, new
    chosen = _choose(ask, old)
    if isinstance(chosen, ExitCode):
        return chosen
    scan.watch(chosen)
    return old, chosen


def _checked(ask: Prompter, check_file: Path, prompt: str) -> BackupPassphrase | ExitCode:
    try:
        for attempt in range(1, TRIES + 1):
            typed = ask.secret(prompt)
            held = None
            if backup_store.passphrase_problem(typed) is None:  # a short one cannot unlock it
                ask.say("Checking it against its check file (about a second)...")
                held = backup_store.unlock_check_file(check_file, typed)
            if held is not None:
                return held
            ask.say(f"  That does not unlock its check file (try {attempt} of {TRIES}).")
    except backup_store.CheckFileError as error:
        raise RefusedError(fixed_message(error)) from error
    ask.say(f"Stopped: it did not unlock its check file after {TRIES} tries. {_HELP_FOR_FORGOTTEN}")
    return ExitCode.REFUSED


def _choose(ask: Prompter, old: BackupPassphrase) -> Secret | ExitCode:
    ask.say(
        f"Choose the new Backup Passphrase: at least {backup_store.PASSPHRASE_MIN} characters,\n"
        "  different from the current one. It cannot be recovered: keep it in your password\n"
        "  manager."
    )
    for attempt in range(1, TRIES + 1):
        first = ask.secret("New Backup Passphrase: ")
        problem = backup_store.passphrase_problem(first)
        if problem is None and old.same_as(first):
            problem = "it is the same as the current one"
        if problem is not None:
            ask.say(f"  Refused: {problem}. (try {attempt} of {TRIES})")
            continue
        if not ask.secret("Type it again: ").same_as(first):
            ask.say(f"  The two entries differ. (try {attempt} of {TRIES})")
            continue
        return first
    ask.say(f"Stopped: no new Backup Passphrase was chosen after {TRIES} tries. Nothing changed.")
    return ExitCode.REFUSED


# -- Summary and confirm (stories 107-108) --------------------------------------------------


def _show_summary(ask: Prompter, plan: RelockPlan, status: ChangeStatus) -> None:
    runs = plan.runs_with_files
    to_do = max(plan.files - status.done, 0)
    lines = [
        "Ready to change the Backup Passphrase. Found through the Run register and --run-folder:",
        (
            f"  {_count(plan.backups, 'Backup')} and "
            f"{_count(plan.files - plan.backups, 'manifest')} in {_count(runs, 'Run')}"
        ),
    ]
    if plan.not_found:
        lines.append(
            f"  Not found: {_count(len(plan.not_found), 'Run folder')}. Their Backups stay under "
            "the old passphrase; if a folder moved, name it with --run-folder."
        )
        lines.extend(f"    {console_text(str(folder))}" for folder in plan.not_found)
    if status.done:
        lines.append(f"  {_count(status.done, 'file')} already re-locked: skipped")
    lines.append(
        f"  Time: {_duration(to_do * SECONDS_PER_FILE)} ({SECONDS_PER_FILE} s per file, "
        f"{_count(to_do, 'file')})"
    )
    lines.append("  Ctrl+C finishes the current file and stops; running this again resumes.")
    ask.say("\n".join(lines))


def _duration(seconds: int) -> str:
    if seconds < 120:  # noqa: PLR2004 (under two minutes is shown in seconds)
        return f"about {seconds} s"
    return f"about {round(seconds / 60)} minutes"


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def _register(
    ask: Prompter, register: Path, plan: RelockPlan, extras: tuple[Path, ...], scan: SecretScan
) -> None:
    """Add each `--run-folder` that was found to the Run register (#22)."""
    found = {run.folder for run in plan.runs}
    for folder in extras:
        if folder not in found:
            continue
        try:
            backup_store.register_run_folder(register, folder, scan=scan)
        except OSError:
            ask.say(
                f"  Warning: {console_text(str(folder))} could not be added to the Run "
                "register. It is re-locked all the same."
            )


# -- The change (stories 110-115) -------------------------------------------------------------


def _start(
    files: PassphraseFiles,
    old: BackupPassphrase,
    new: BackupPassphrase | Secret,
    scan: SecretScan,
) -> tuple[BackupPassphrase, PendingChange]:
    now = datetime.now(UTC)
    if isinstance(new, BackupPassphrase):  # stage SWITCHED: the check file holds it already
        return new, backup_store.resume_change(files, scan=scan, now=now)
    # Stage NONE or CHOOSING: the change starts (again) from the beginning.
    try:
        return backup_store.start_change(files, old, new, scan=scan, now=now)
    except OSError as error:
        raise RefusedError(_NOT_STARTED) from error


def _relock_all(  # noqa: PLR0913, PLR0917 (the call's whole state, each part named)
    files: PassphraseFiles,
    plan: RelockPlan,
    old: BackupPassphrase,
    started: tuple[BackupPassphrase, PendingChange],
    scan: SecretScan,
    key_file: Path,
) -> ExitCode:
    new, pending = started
    relocker = backup_store.Relocker(
        old=old, new=new, pending=pending, scan=scan, tool_version=__version__
    )
    total = plan.files
    done = 0

    def each(result: FileResult) -> None:
        nonlocal done
        done += 1
        print(f"  [{done}/{total}] {_said(result)}: {_short(result.path)}", flush=True)

    results: list[RunResult] = []
    with _ctrl_c_finishes_the_file() as stop:
        for run in plan.runs:
            result = relocker.relock_run(run, each=each, stop=stop)
            if result is None:
                print(_STOPPED, file=sys.stderr)
                return ExitCode.STOPPED
            results.append(result)
    key_outcome = backup_store.relock_key_file(key_file, old, new)  # the Cisco API key (story 37)
    backup_store.finish_change(files)
    return _report(plan, results, key_outcome)


def _said(result: FileResult) -> str:
    if result.outcome is FileOutcome.SKIPPED:
        return "NOT re-locked"
    return "re-locked" if result.outcome is FileOutcome.RELOCKED else "done earlier"


def _short(path: str) -> str:
    """`<Run folder name>/backups/<file>`: enough to tell files apart in the progress."""
    parts = Path(path).parts[-3:]
    return console_text("/".join(parts))


def _report(
    plan: RelockPlan, results: list[RunResult], key_outcome: backup_store.KeyOutcome
) -> ExitCode:
    files = [f for run in results for f in run.files]
    backups = [f for f in files if f.path.endswith(backup_store.locker.BACKUP_SUFFIX)]
    relocked = [f for f in backups if f.outcome is not FileOutcome.SKIPPED]
    runs = sum(1 for run in results if any(f.outcome is not FileOutcome.SKIPPED for f in run.files))
    lines = [
        (
            f"Re-locked {_count(len(relocked), 'Backup')} in {_count(runs, 'Run')} under the "
            "new Backup Passphrase. The change is finished."
        )
    ]
    skipped = [f for f in files if f.outcome is FileOutcome.SKIPPED]
    flagged = [f for f in files if f.flag is not None]
    unrecorded = [run for run in results if run.record_problem is not None]
    if skipped:
        lines.append("Not re-locked (listed in each Run folder's re-lock record):")
        lines.extend(f"  {console_text(f.path)}: {f.problem}" for f in skipped)
    if flagged:
        lines.append("Flagged (re-locked unchanged):")
        lines.extend(f"  {console_text(f.path)}: {f.flag}" for f in flagged)
    if plan.not_found:
        lines.append("Run folders not found (their Backups stay under the old passphrase):")
        lines.extend(f"  {console_text(str(folder))}" for folder in plan.not_found)
    if unrecorded:
        lines.append("Re-lock record not written:")
        lines.extend(f"  {console_text(str(run.folder))}" for run in unrecorded)
    if key_outcome.problem is not None:
        lines.append(f"{key_outcome.problem}.")
    lines.append(ROTATION_LIMITS)
    print("\n".join(lines))
    attention = (
        skipped or flagged or plan.not_found or unrecorded or key_outcome.problem is not None
    )
    return ExitCode.NEEDS_ATTENTION if attention else ExitCode.CLEAN


@contextmanager
def _ctrl_c_finishes_the_file() -> Iterator[Callable[[], bool]]:
    """While re-locking, Ctrl+C asks to stop after the current file instead of at once.

    A file is always left wholly old or wholly new either way; stopping between files keeps
    the marker and each Run folder's record in step.
    """
    pressed = threading.Event()

    def press(_signal: int, _frame: FrameType | None) -> None:
        if not pressed.is_set():
            pressed.set()
            print("Ctrl+C: stopping after the current file...", file=sys.stderr, flush=True)

    previous = signal.signal(signal.SIGINT, press)
    try:
        yield pressed.is_set
    finally:
        signal.signal(signal.SIGINT, previous)


def _warn_of_scan_hits(scan: SecretScan) -> None:
    if scan.hits:
        print(
            f"Warning: the secret scan replaced {_count(scan.hits, 'piece')} of this output "
            "with [blocked],\nbecause they matched a Backup Passphrase typed here. This is a "
            "bug in the tool.",
            file=sys.stderr,
        )
