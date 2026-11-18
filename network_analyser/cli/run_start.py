"""Run start, in the decided order (spec #37 "Run-start order"; decision #31).

    lock and folder checks -> Scope and Seeds -> crash-dump check -> Backup Passphrase
    -> Credential Sets -> Ready to start -> Run folder created and registered -> crawl

This file holds the Scope and Seeds step (ticket #41). It comes before every secret prompt,
so a typo in the Scope or a Seed is caught before any secret is typed (story 11). Each
setting comes from a flag, else the run file, else a prompt or its default (stories 2-4).
A Scope or Seeds given by flag or run file is refused in full on any bad entry (story 8);
at the prompt, a bad line is asked again (story 6).
"""

import argparse
import re
import sys
from collections.abc import Sequence
from ipaddress import IPv4Address

from network_analyser import scope
from network_analyser.cli.exit_codes import ExitCode
from network_analyser.cli.parser import FAILURE_BUDGET_DEFAULT, PARALLEL_DEFAULT
from network_analyser.cli.run_file import RunFile
from network_analyser.cli.text import escape_controls
from network_analyser.records import RunRequest, ScopeRecord, Source, Sourced
from network_analyser.scope import Refusal, ScopeRefused

NOTHING_CONTACTED = "Nothing was contacted."
_SEED_SEPARATORS = re.compile(r"[,\s]+")


class _InputEndedError(Exception):
    """Standard input ended while the tool was still asking."""


def scope_and_seeds(args: argparse.Namespace, run_file: RunFile | None) -> RunRequest | ExitCode:
    """Gather, check and show the Scope, Seeds and run-file options; refuse with exit 2."""
    from_file = run_file or RunFile(path="")
    try:
        fence = _scope(args, from_file)
        if isinstance(fence, ExitCode):
            return fence
        _show_scope(fence.value, args, from_file)
        seeds = _seeds(args, from_file, fence.value)
    except _InputEndedError:
        print(
            f"Input ended before the Scope and Seeds were complete. {NOTHING_CONTACTED}",
            file=sys.stderr,
        )
        return ExitCode.REFUSED
    if isinstance(seeds, ExitCode):
        return seeds
    print(f"Seeds ({seeds.source.value}): {', '.join(str(s) for s in seeds.value)}")
    request = RunRequest(
        scope=fence,
        exclusions_source=_exclusions_source(args, from_file, fence.value),
        seeds=seeds,
        label=_option(args.label, from_file.label, None),
        parallel=_option(args.parallel, from_file.parallel, PARALLEL_DEFAULT),
        failure_budget=_option(
            args.failure_budget, from_file.failure_budget, FAILURE_BUDGET_DEFAULT
        ),
        sweep=_option(args.sweep, from_file.sweep, default=False),
    )
    _show_options(request)
    return request


# -- Scope ---------------------------------------------------------------------------------


def _scope(args: argparse.Namespace, from_file: RunFile) -> Sourced[ScopeRecord] | ExitCode:
    exclusions = _given(args.exclude, from_file.exclude)
    excluded = list(exclusions.value) if exclusions else []
    entries = _given(args.scope, from_file.scope)
    if entries is None:
        return Sourced(_ask_scope(excluded), Source.PROMPT)
    result = scope.parse(entries.value, excluded)
    if isinstance(result, ScopeRefused):
        sources = {entries.source} | ({exclusions.source} if exclusions else set())
        _refuse("the Scope", sources, result, "Fix the Scope and run again.")
        return ExitCode.REFUSED
    return Sourced(result, entries.source)


def _ask_scope(given_exclusions: Sequence[str]) -> ScopeRecord:
    print(
        "No Scope given. Enter the IPv4 ranges this Run may touch, one per line:\n"
        "  CIDR (192.0.2.0/24), range (192.0.2.10-192.0.2.20) or one IP.\n"
        "  Start a line with ! to exclude it (!192.0.2.128/25). Empty line when done."
    )
    entries: list[str] = []
    typed_exclusions: list[str] = []
    while True:
        text = _ask("Scope> ").strip()
        if text:
            exclusion = text.startswith("!")
            entry = text[1:].strip() if exclusion else text
            refusal = scope.check_entry(entry, exclusion=exclusion)
            if refusal is not None:
                print(f"  Refused: {_describe(refusal)}. Enter that line again.")
            else:
                (typed_exclusions if exclusion else entries).append(entry)
            continue
        if not entries:
            print("  At least one Scope entry is needed.")
            continue
        for dropped in scope.unmatched_exclusions(entries, typed_exclusions):
            print(f"  Dropped !{escape_controls(dropped)}: it matches nothing in the Scope.")
            typed_exclusions.remove(dropped)
        result = scope.parse(entries, [*given_exclusions, *typed_exclusions])
        if isinstance(result, ScopeRecord):
            return result
        for refusal in result.refusals:
            print(f"  Refused: {_describe(refusal)}.")
        print("  Add more lines, or press Ctrl+C to cancel.")


def _exclusions_source(
    args: argparse.Namespace, from_file: RunFile, fence: ScopeRecord
) -> Source | None:
    if not fence.exclusions:
        return None
    given = _given(args.exclude, from_file.exclude)
    return given.source if given else Source.PROMPT


def _show_scope(fence: ScopeRecord, args: argparse.Namespace, from_file: RunFile) -> None:
    given = _given(args.scope, from_file.scope)
    source = given.source if given else Source.PROMPT
    count = len(fence.ranges)
    ranges = f"{count} range{'' if count == 1 else 's'}"
    lines = [
        f"Scope ({source.value}): {fence.address_count:,} addresses in {ranges}",
        *(f"  {r}" for r in fence.ranges),
    ]
    exclusions_source = _exclusions_source(args, from_file, fence)
    if exclusions_source is not None:
        lines.append(f"Exclusions ({exclusions_source.value}):")
        lines.extend(f"  {r}" for r in fence.exclusions)
    lines.extend(f"Warning: {escape_controls(w, limit=400)}" for w in fence.warnings)
    print("\n".join(lines))


# -- Seeds ---------------------------------------------------------------------------------


def _seeds(
    args: argparse.Namespace, from_file: RunFile, fence: ScopeRecord
) -> Sourced[tuple[IPv4Address, ...]] | ExitCode:
    given = _given(args.seed, from_file.seeds)
    if given is None:
        return Sourced(_ask_seeds(fence), Source.PROMPT)
    result = scope.check_seeds(given.value, fence)
    if isinstance(result, ScopeRefused):
        _refuse("the Seeds", {given.source}, result, "Fix the Seeds and run again.")
        return ExitCode.REFUSED
    return Sourced(result, given.source)


def _ask_seeds(fence: ScopeRecord) -> tuple[IPv4Address, ...]:
    print(
        "No Seeds given. Enter one or more device IPs to start the crawl from,\n"
        "separated by spaces or commas. Each must be inside the Scope."
    )
    while True:
        texts = [t for t in _SEED_SEPARATORS.split(_ask("Seeds> ").strip()) if t]
        if not texts:
            print("  At least one Seed is needed.")
            continue
        result = scope.check_seeds(texts, fence)
        if not isinstance(result, ScopeRefused):
            return result
        for refusal in result.refusals:
            print(f"  Refused: {_describe(refusal)}.")
        print("  Enter the Seeds again.")


# -- Options -------------------------------------------------------------------------------


def _show_options(request: RunRequest) -> None:
    label = request.label
    parts = [
        (f"label {escape_controls(label.value, limit=40)}" if label.value else "no label")
        + f" ({label.source.value})",
        f"parallel {request.parallel.value} ({request.parallel.source.value})",
        f"failure budget {request.failure_budget.value} ({request.failure_budget.source.value})",
        f"Sweep {'on' if request.sweep.value else 'off'} ({request.sweep.source.value})",
    ]
    print(f"Options: {'; '.join(parts)}")


# -- Helpers -------------------------------------------------------------------------------


def _given[T](flag: T | None, from_file: T | None) -> Sourced[T] | None:
    """Flags win over the run file (story 3). None means neither gave the setting."""
    if flag is not None:
        return Sourced(flag, Source.COMMAND_LINE)
    if from_file is not None:
        return Sourced(from_file, Source.RUN_FILE)
    return None


def _option[T](flag: T | None, from_file: T | None, default: T) -> Sourced[T]:
    return _given(flag, from_file) or Sourced(default, Source.DEFAULT)


def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        raise _InputEndedError from None


def _describe(refusal: Refusal) -> str:
    """Say what was refused and why; the operator's text is escaped (story 6)."""
    if not refusal.entry:
        return refusal.reason
    kind = "Seed " if refusal.seed else "exclusion " if refusal.exclusion else ""
    return f"{kind}{escape_controls(refusal.entry)}: {refusal.reason}"


def _refuse(what: str, sources: set[Source], refused: ScopeRefused, fix: str) -> None:
    where = " and the ".join(s.value for s in sorted(sources, key=lambda s: s.value))
    verb = "have" if what.endswith("s") else "has"
    lines = [f"Refused: {what} from the {where} {verb} problems:"]
    lines.extend(f"  {_describe(r)}" for r in refused.refusals)
    lines.append(f"{NOTHING_CONTACTED} {fix}")
    print("\n".join(lines), file=sys.stderr)
