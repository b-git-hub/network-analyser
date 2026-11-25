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
is created, the crawl spreads from the Seeds through CDP and LLDP inside the Scope (#50).

While it runs, progress is shown live, as log lines or quietly (`cli.progress`, #56), and
Ctrl+C stops the Run through the shared `RunStop` rather than an exception
(`cli.signals`): the first press starts no new login, the second closes every session.
The Run's outputs are still written, the final summary says what needs attention
(`cli.summary`), and the full paths of the Run folder and its files are printed last.
"""

import argparse
import dataclasses
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from ipaddress import IPv4Address

from network_analyser import _winsys, backup_store, device_gateway, discovery, run_output
from network_analyser._version import __version__
from network_analyser.advisories import ProxyConfig
from network_analyser.cli import (
    progress,
    ready,
    run_end,
    run_file,
    run_report,
    run_secrets,
    run_start,
    run_topology,
    run_trail,
    signals,
    summary,
)
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
from network_analyser.records import Platform, RunRequest, Source, Sourced
from network_analyser.records.backup import BackupCapture, BackupResults
from network_analyser.records.crawl import CrawlResult
from network_analyser.records.device import DeviceRecord
from network_analyser.records.events import AuditEvent, CtrlCPressed, RunEnding
from network_analyser.records.identity import Alias
from network_analyser.records.sweep import SweepResult
from network_analyser.trust_store import TrustStore

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
                trust_warning = check_trust_folder(data)  # #69; the warning goes in the report
                _refuse_while_a_change_is_pending(data)
                return _after_folder_checks(args, data, check, scan, trust_warning)
        except RefusedError as error:
            refuse(args.command, fixed_message(error))
            return ExitCode.REFUSED
        finally:
            run_trail.warn_of_scan_hits(scan)
            scan.forget()


def _refuse_while_a_change_is_pending(data: run_output.DataFolder) -> None:
    if backup_store.change_is_pending(data.change_pending):
        raise RefusedError(_CHANGE_PENDING)


def _after_folder_checks(
    args: argparse.Namespace,
    data: run_output.DataFolder,
    check: run_output.RunsParentCheck,
    scan: SecretScan,
    trust_warning: str | None,
) -> ExitCode:
    loaded = _load_run_file(args.run_file)
    if isinstance(loaded, ExitCode):
        return loaded
    lookups = _lookups_enabled(args, loaded)
    _print_missing_key_notice(data, lookups=lookups)
    _print_wpad_notice(args, lookups=lookups)
    ask = Prompter.for_this_process()
    request = run_start.scope_and_seeds(args, loaded, ask)
    if isinstance(request, ExitCode):
        return request
    trust = load_trust_store(data, strict=bool(args.strict_host_keys), known_hosts=args.known_hosts)
    secrets = _secrets(request, data, ask, scan, lookups=lookups)
    if isinstance(secrets, ExitCode):
        return secrets
    passphrase, sets = secrets
    try:
        return _confirmed(
            args,
            data,
            check,
            scan,
            trust_warning,
            ask,
            request=request,
            trust=trust,
            passphrase=passphrase,
            sets=sets,
        )
    finally:
        # The Run end wipes before Cisco is asked; this covers every path that never got
        # there (a refused audit log, Ctrl+C during the crawl, a crash) (#143).
        run_end.wipe(sets, passphrase)


def _confirmed(  # noqa: PLR0913, PLR0917 (everything the confirmed Run needs, each named)
    args: argparse.Namespace,
    data: run_output.DataFolder,
    check: run_output.RunsParentCheck,
    scan: SecretScan,
    trust_warning: str | None,
    ask: Prompter,
    *,
    request: RunRequest,
    trust: TrustStore,
    passphrase: backup_store.BackupPassphrase,
    sets: CredentialSets,
) -> ExitCode:
    """Everything from the Run folder name to the summary, once the secrets are typed."""
    started = datetime.now(UTC)
    planned = check.parent / run_output.run_folder_name(started, request.label.value)
    if scan.holds_secret(str(planned)):
        print(_FOLDER_HOLDS_A_SECRET, file=sys.stderr)
        return ExitCode.REFUSED
    source = Source.COMMAND_LINE if args.runs_dir is not None else Source.DEFAULT
    block = ready.ready_block(
        request,
        sets.views(),
        Sourced(check.parent, source),
        started,
        key_stored=data.cisco_key_file.is_file(),
    )
    print(block)
    if not ready.confirm_start(ask):
        print("Run cancelled. Nothing was contacted.", file=sys.stderr)
        return ExitCode.STOPPED
    folder = create_and_register(data, check, started, request.label.value, scan)
    print(f"Run folder created: {console_text(str(folder.path))}")

    collected = run_topology.Collector()  # kept as they come, for topology.json (#52)
    notices = check.notices if trust_warning is None else (*check.notices, trust_warning)
    draft = run_report.Draft(
        folder=folder,
        scan=scan,
        started_at=started,
        request=request,
        strict_host_keys=bool(args.strict_host_keys),
        notices=notices,
    )
    crawl = _crawler(
        args,
        request=request,
        trust=trust,
        passphrase=passphrase,
        sets=sets,
        folder=folder,
        collected=collected,
        scan=scan,
        draft=draft,
    )

    def end(audit: run_output.AuditLog, result: CrawlResult) -> run_end.EndOutcome:
        outcome = run_end.finish(
            audit=audit,
            folder=folder,
            collected=collected,
            scan=scan,
            scope=request.scope.value,
            passphrase=passphrase,
            sets=sets,
            key_file=data.cisco_key_file,
            lookups_enabled=request.cisco_lookups.value and not result.stopped,
            proxy=ProxyConfig.explicit(args.proxy) if args.proxy else None,
        )
        draft.analysis_results = outcome.results
        draft.cisco_lookups = outcome.lookups
        draft.extra_attention = outcome.attention
        return outcome

    try:
        code = run_topology.then_save(
            folder,
            collected,
            scan,
            lambda: run_trail.run_with_audit_trail(request, sets, folder, scan, crawl, end),
            scope=request.scope.value,
        )
    except KeyboardInterrupt:
        draft.ending = RunEnding.STOPPED
        draft.ctrl_c = True
        raise
    else:
        stopped = draft.captured is not None and draft.captured.stopped is not None
        if stopped or code == ExitCode.STOPPED:
            draft.ending = RunEnding.STOPPED
        else:
            draft.ending = RunEnding.COMPLETED
        return code
    finally:
        run_report.publish(draft)  # also after Ctrl+C, and best-effort when the Run crashed
        print(summary.where_to_look(folder))


def _secrets(
    request: RunRequest,
    data: run_output.DataFolder,
    ask: Prompter,
    scan: SecretScan,
    *,
    lookups: bool,
) -> tuple[backup_store.BackupPassphrase, CredentialSets] | ExitCode:
    """The crash-dump check, the Backup Passphrase, then the Credential Sets (ADR 0004).

    Each secret joins the scan as soon as it is accepted or typed. The passphrase stays in
    its `BackupPassphrase` until it reaches the locking worker (#51). Starting over deletes a
    leftover key file, so the missing-key notice is shown right then, before the Credential
    Set prompts (#143, story 35).
    """
    if not guard_crash_dumps(ask):
        return ExitCode.REFUSED
    passphrase = run_secrets.backup_passphrase(
        data.check_file,
        ask,
        key_file=data.cisco_key_file,
        on_start_over=lambda: _print_missing_key_notice(data, lookups=lookups),
    )
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


def _shown_as_well(
    record: Callable[[AuditEvent], None], shown: progress.Progress
) -> Callable[[AuditEvent], None]:
    """Record each event, then show it: a Retired Credential Set is announced at once.

    Visits run on the pool's threads; `Progress` takes events from any of them.
    """

    def emit(event: AuditEvent) -> None:
        record(event)
        shown.event(event)

    return emit


def _print_missing_key_notice(data: run_output.DataFolder, *, lookups: bool) -> None:
    """Print the one notice a Run with no stored key gives, before the first prompt."""
    notice = run_end.missing_key_notice(lookups_enabled=lookups, key_file=data.cisco_key_file)
    if notice is not None:
        print(notice)


def _print_wpad_notice(args: argparse.Namespace, *, lookups: bool) -> None:
    """Print the WPAD notice once, before the first prompt (#192)."""
    address = getattr(args, "proxy", None)
    config = ProxyConfig.explicit(address) if address else ProxyConfig()
    notice = run_end.wpad_notice(lookups_enabled=lookups, proxy=config)
    if notice is not None:
        print(notice)


def _lookups_enabled(args: argparse.Namespace, run_file: run_file.RunFile | None) -> bool:
    """Whether Cisco is asked: the flag, else the run file, else on (#104, story 8)."""
    if getattr(args, "cisco_lookups", None) is not None:
        return bool(args.cisco_lookups == "on")
    if run_file is not None and run_file.cisco_lookups is not None:
        return run_file.cisco_lookups
    return True


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


def _crawler(  # noqa: PLR0913 (everything the crawl needs, from the steps before it)
    args: argparse.Namespace,
    *,
    request: RunRequest,
    trust: TrustStore,
    passphrase: backup_store.BackupPassphrase,
    sets: CredentialSets,
    folder: run_output.RunFolder,
    collected: run_topology.Collector,
    scan: SecretScan,
    draft: run_report.Draft,
) -> run_trail.Crawl:
    """The crawl of a confirmed Run: Sweep, progress, Ctrl+C handling and Backups."""

    def crawl(audit: run_output.AuditLog) -> tuple[CrawlResult, BackupResults]:
        # #50: the crawl. `check.notices` and the Credential Sets' views go to the Run
        # report (#66); each set's results ride on the crawl result (#54). #51: each
        # running config goes from the gateway straight to the locking worker, which locks
        # whatever was taken even on Ctrl+C. #52: every record is kept as it comes back,
        # for topology.json.
        locker = backup_store.BackupLocker(
            folder.io_path,
            shown=folder.path,
            passphrase=passphrase,
            capacity=request.parallel.value,
            emit=audit.record,
            scan=scan,
            tool_version=__version__,
        )

        live_ok = _winsys.enable_live_output()
        shown = progress.Progress(
            progress.choose_mode(args.progress, live_ok=live_ok),
            sets=sets.views(),
            parallel=request.parallel.value,
            in_place=live_ok,
        )
        stop = device_gateway.RunStop()
        emit = _shown_as_well(audit.record, shown)

        def backup_sink(capture: BackupCapture, config: str, /) -> None:
            shown.backup_taken(capture.ip)
            locker.take(capture, config)

        def visit(
            ip: IPv4Address,
            *,
            id_gate: bool,
            neighbour_hint: Platform | None,
            identity: device_gateway.Identity,
        ) -> DeviceRecord | Alias:
            return collected.add(
                device_gateway.visit(
                    ip,
                    scope=request.scope.value,
                    trust=trust,
                    sets=sets,
                    emit=emit,
                    failure_budget=request.failure_budget.value,
                    backup_sink=backup_sink,
                    timeouts=request.timeouts,
                    id_gate=id_gate,
                    neighbour_hint=neighbour_hint,
                    identity=identity,
                    stop=stop,
                )
            )

        def announce(press: int) -> None:
            sessions = stop.open_count
            audit.record(CtrlCPressed(press=press, sessions_running=sessions))
            shown.ctrl_c(press, sessions=sessions)

        # #55: opt-in Sweep, after the confirm and inside the audit trail. It does not
        # watch the stop token (that decision stays with #55). Ctrl+C here still raises,
        # so a Sweep can be abandoned before any login; the crawl below is #56.
        seeds = request.seeds.value
        swept: SweepResult | None = None
        result: CrawlResult | None = None
        backups: BackupResults | None = None
        try:
            if request.sweep.value:
                swept = discovery.sweep(
                    request.scope.value,
                    inflight=request.sweep_inflight.value,
                    emit=emit,
                )
                seeds = discovery.combine_seeds(seeds, swept.login_seeds)

            with signals.ctrl_c_stops(stop) as ctrl_c:

                def tick(queued: int) -> None:
                    ctrl_c.handle(announce)
                    shown.tick(queued)

                try:
                    result = discovery.crawl(
                        seeds,
                        visit,
                        scope=request.scope.value,
                        parallel=request.parallel.value,
                        emit=emit,
                        skipped=collected.add,
                        all_retired=sets.all_retired,
                        stop=stop,
                        tick=tick,
                    )
                finally:
                    shown.finish()
                    backups = locker.finish()  # what was captured is locked, Ctrl+C or not
                    ctrl_c.handle(announce)
            return (
                dataclasses.replace(result, credential_sets=sets.results(), sweep=swept),
                backups,
            )
        finally:
            # Kept for the report, including when the crawl raises (#66).
            draft.capture(
                run_report.captured_from(
                    collected.records(),
                    backups,
                    sets,
                    swept,
                    None if result is None else result.stopped,
                )
            )

    return crawl
