"""`network-analyser run`: start a Run, in the decided order (spec #37 "Run-start order").

    lock and folder checks -> Scope and Seeds -> crash-dump check -> Backup Passphrase
    -> Credential Sets -> Ready to start -> Run folder created and registered -> crawl

Before any prompt it takes the single-instance lock, checks a Run folder can be made where
it will go (#42) and refuses while a `change-passphrase` is unfinished (story 112) or while
anyone but the operator can read or change the Trust Store folder (#69); the lock
is held until `run` ends. Every refusal before the confirm exits 2, and Ctrl+C, input that
ends, or `n` at the confirm exits 3, with nothing contacted (stories 15, 29).

From the first prompt on, everything printed passes through the Run's secret scan (#48):
each secret joins the scan the moment it is typed, and a match shows as `[blocked]`, with one
warning at the end. Once the Run folder is created and registered, `audit.log` records the
Run's start and end (`cli.run_trail`).

The Trust Store (and any `--known-hosts` file) is read before the first secret prompt, so a
bad `--known-hosts` refuses the Run with exit 2 before anything is typed. Once the Run folder
is created, the crawl spreads from the Seeds through CDP and LLDP inside the Scope (#50),
and the Run ends with a summary of every device found.
"""

import argparse
import sys
from datetime import UTC, datetime
from ipaddress import IPv4Address

from network_analyser import backup_store, device_gateway, discovery, run_output
from network_analyser._version import __version__
from network_analyser.cli import ready, run_file, run_secrets, run_start, run_topology, run_trail
from network_analyser.cli.console import scanned_console
from network_analyser.cli.crash_dump_guard import guard_crash_dumps
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import PROG
from network_analyser.cli.prompts import Prompter
from network_analyser.cli.run_folder import (
    RefusedError,
    check_where_run_folder_goes,
    console_text,
    create_and_register,
    find_data_folder,
    fixed_message,
    hold_instance_lock,
    refuse,
)
from network_analyser.cli.text import escape_controls
from network_analyser.cli.trust_folder import check_trust_folder
from network_analyser.cli.trust_keys import load_trust_store
from network_analyser.credentials import CredentialSets, SecretScan
from network_analyser.records import RunRequest, Source, Sourced
from network_analyser.records.backup import BackupResults
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.device import DeviceRecord
from network_analyser.records.identity import Alias

_CHANGE_PENDING = (
    "a change of the Backup Passphrase is unfinished, so Backups may be under either "
    f'passphrase. Finish it with "{PROG} change-passphrase", then start the Run again.'
)
_LABEL_IS_A_SECRET = (
    "Refused: the label is the same as a password or the Backup Passphrase you typed. The "
    "label goes\ninto the Run folder name and the Run register, so it must never be a "
    f"secret. {run_secrets.NOTHING_CONTACTED}"
)
_FOLDER_HOLDS_A_SECRET = (
    "Refused: the Run folder's path would hold text that is a password or the Backup "
    "Passphrase you typed.\nThe path goes into the Run register and audit.log, so it must "
    "never hold a secret. Choose another\n--runs-dir or --label; if a Credential Set "
    f"password is common text, change it. {run_secrets.NOTHING_CONTACTED}"
)


def run(args: argparse.Namespace) -> ExitCode:
    """Start a Run from flags, a run file and prompts; return its exit code."""
    scan = SecretScan()  # empty until the first secret is typed
    with scanned_console(scan):
        try:
            data = find_data_folder()
            with hold_instance_lock(data):
                check = check_where_run_folder_goes(data, args.runs_dir)
                check_trust_folder(data)  # #69: only the operator may reach the Trust Store
                _refuse_while_a_change_is_pending(data)
                return _after_folder_checks(args, data, check, scan)
        except RefusedError as error:
            refuse(args.command, fixed_message(error))
            return ExitCode.REFUSED
        finally:
            run_trail.warn_of_scan_hits(scan)


def _refuse_while_a_change_is_pending(data: run_output.DataFolder) -> None:
    if backup_store.change_is_pending(data.change_pending):
        raise RefusedError(_CHANGE_PENDING)


def _after_folder_checks(
    args: argparse.Namespace,
    data: run_output.DataFolder,
    check: run_output.RunsParentCheck,
    scan: SecretScan,
) -> ExitCode:
    loaded = _load_run_file(args.run_file)
    if isinstance(loaded, ExitCode):
        return loaded
    ask = Prompter.for_this_process()
    request = run_start.scope_and_seeds(args, loaded, ask)
    if isinstance(request, ExitCode):
        return request
    trust = load_trust_store(data, strict=bool(args.strict_host_keys), known_hosts=args.known_hosts)
    secrets = _secrets(request, data, ask, scan)
    if isinstance(secrets, ExitCode):
        return secrets
    passphrase, sets = secrets
    started = datetime.now(UTC)
    planned = check.parent / run_output.run_folder_name(started, request.label.value)
    if scan.holds_secret(str(planned)):
        print(_FOLDER_HOLDS_A_SECRET, file=sys.stderr)
        return ExitCode.REFUSED
    source = Source.COMMAND_LINE if args.runs_dir is not None else Source.DEFAULT
    print(ready.ready_block(request, sets.views(), Sourced(check.parent, source), started))
    if not ready.confirm_start(ask):
        print("Run cancelled. Nothing was contacted.", file=sys.stderr)
        return ExitCode.STOPPED
    folder = create_and_register(data, check, started, request.label.value, scan)
    print(f"Run folder created: {console_text(str(folder.path))}")

    collected = run_topology.Collector()  # kept as they come, for topology.json (#52)

    def crawl(audit: run_output.AuditLog) -> tuple[CrawlResult, BackupResults]:
        # #50: the crawl. `check.notices` and the Credential Sets' views go to the Run
        # report (#66). #51: each running config goes from the gateway straight to the
        # locking worker, which locks whatever was taken even on Ctrl+C. #52: every record
        # is kept as it comes back, for topology.json.
        locker = backup_store.BackupLocker(
            folder.io_path,
            shown=folder.path,
            passphrase=passphrase,
            capacity=request.parallel.value,
            emit=audit.record,
            scan=scan,
            tool_version=__version__,
        )

        def visit(
            ip: IPv4Address, *, id_gate: bool, identity: device_gateway.Identity
        ) -> DeviceRecord | Alias:
            return device_gateway.visit(
                ip,
                scope=request.scope.value,
                trust=trust,
                sets=sets,
                emit=audit.record,
                failure_budget=request.failure_budget.value,
                backup_sink=locker.take,
                timeouts=request.timeouts,
                id_gate=id_gate,
                identity=identity,
            )

        try:
            result = discovery.crawl(
                request.seeds.value,
                lambda ip, *, id_gate, identity: collected.add(
                    visit(ip, id_gate=id_gate, identity=identity)
                ),
                scope=request.scope.value,
                parallel=request.parallel.value,
                emit=audit.record,
                skipped=collected.add,
            )
        finally:
            backups = locker.finish()
        return result, backups

    return run_topology.then_save(
        folder,
        collected,
        scan,
        lambda: run_trail.run_with_audit_trail(request, sets, folder, scan, crawl),
        scope=request.scope.value,
    )


def _secrets(
    request: RunRequest, data: run_output.DataFolder, ask: Prompter, scan: SecretScan
) -> tuple[backup_store.BackupPassphrase, CredentialSets] | ExitCode:
    """The crash-dump check, the Backup Passphrase, then the Credential Sets (ADR 0004).

    Each secret joins the scan as soon as it is accepted or typed. The passphrase stays in
    its `BackupPassphrase` until it reaches the locking worker (#51).
    """
    if not guard_crash_dumps(ask):
        return ExitCode.REFUSED
    passphrase = run_secrets.backup_passphrase(data.check_file, ask)
    if isinstance(passphrase, ExitCode):
        return passphrase
    passphrase.add_to_scan(scan)
    sets = run_secrets.credential_sets(ask, passphrase, scan)
    if isinstance(sets, ExitCode):
        return sets
    if run_secrets.label_is_a_secret(request.label.value, passphrase, sets):
        print(_LABEL_IS_A_SECRET, file=sys.stderr)
        return ExitCode.REFUSED
    return passphrase, sets


def _load_run_file(path: str | None) -> run_file.RunFile | ExitCode | None:
    if path is None:
        return None
    loaded = run_file.load(path)
    if isinstance(loaded, run_file.RunFile):
        return loaded
    lines = [f"Refused: run file {escape_controls(loaded.path, limit=200)}:"]
    lines.extend(f"  {problem}" for problem in loaded.problems)
    lines.append(f"{run_start.NOTHING_CONTACTED} Fix the run file and run again.")
    print("\n".join(lines), file=sys.stderr)
    return ExitCode.REFUSED
