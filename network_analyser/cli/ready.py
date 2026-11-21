"""The Ready-to-start block and the confirm (spec #37 stories 3, 14-15 and 28; #15, #31).

The last step before any device is contacted: one recap of the Run folder, Scope, Seeds,
each Credential Set's username and Platform limit (passwords only as "held in memory"), the
failure budget and the options, each with where it came from. Then `Start the Run? [Y/n]`.
"""

from datetime import datetime
from pathlib import Path

from network_analyser import run_output
from network_analyser.cli.prompts import Prompter
from network_analyser.cli.run_folder import console_text
from network_analyser.cli.text import escape_controls
from network_analyser.credentials.secret import HELD_IN_MEMORY
from network_analyser.records import CredentialSetView, RunRequest, Sourced

_NAME_WIDTH = 16
_INDENT = " " * (2 + _NAME_WIDTH)
_SHOWN_AT_MOST = 40


def ready_block(
    request: RunRequest,
    sets: tuple[CredentialSetView, ...],
    runs_parent: Sourced[Path],
    started: datetime,
    *,
    key_stored: bool,
) -> str:
    """Return the Ready-to-start block, one line per setting (story 14)."""
    folder = runs_parent.value / run_output.run_folder_name(started, request.label.value)
    fence = request.scope
    count = len(fence.value.ranges)
    lines = [
        "Ready to start",
        _row(
            "Run folder",
            f"{console_text(str(folder))} "
            f"({runs_parent.source.value}; created when you start the Run)",
        ),
        _row(
            "Scope",
            f"{fence.value.address_count:,} addresses in {count} "
            f"range{'' if count == 1 else 's'} ({fence.source.value})",
        ),
        *(f"{_INDENT}  {r}" for r in fence.value.ranges),
    ]
    if request.exclusions_source is not None:
        lines.append(_row("Exclusions", f"({request.exclusions_source.value})"))
        lines.extend(f"{_INDENT}  {r}" for r in fence.value.exclusions)
    lines.extend(_row("Warning", escape_controls(w, limit=400)) for w in fence.value.warnings)
    seeds = request.seeds
    lines.append(_row("Seeds", f"{', '.join(str(s) for s in seeds.value)} ({seeds.source.value})"))
    lines.extend(_row(f"Set {view.number}", _describe_set(view)) for view in sets)
    budget = request.failure_budget
    logins = "failed login" if budget.value == 1 else "failed logins"
    lines.append(
        _row(
            "Failure budget",
            f"{budget.value} {logins} per set, then it is retired ({budget.source.value})",
        )
    )
    lines.append(_row("Cisco lookups", _lookups(request, key_stored=key_stored)))
    lines.append(_row("Options", _options(request)))
    return "\n".join(lines)


def confirm_start(ask: Prompter) -> bool:
    """Ask `Start the Run? [Y/n]`; Enter means yes (story 14).

    Raises:
        KeyboardInterrupt: the operator pressed Ctrl+C.
        EOFError: input ended before an answer was given.
    """
    return ask.yes_no("Start the Run? [Y/n] ", default=True)


def _row(name: str, value: str) -> str:
    return f"  {name:<{_NAME_WIDTH}}{value}"


def _describe_set(view: CredentialSetView) -> str:
    limit = f"{view.platform_limit.value} only" if view.platform_limit else "any Platform"
    username = escape_controls(view.username, limit=_SHOWN_AT_MOST)
    return f"{username}: {limit}; password {HELD_IN_MEMORY}"


def _lookups(request: RunRequest, *, key_stored: bool) -> str:
    """Say whether Cisco lookups are on and whether a key is stored (story 7)."""
    switch = request.cisco_lookups
    state = "on" if switch.value else "off"
    key = "Cisco API key stored" if key_stored else "no Cisco API key stored"
    return f"{state} ({switch.source.value}); {key}"


def _options(request: RunRequest) -> str:
    label = request.label
    shown = (
        f"label {escape_controls(label.value, limit=_SHOWN_AT_MOST)}"
        if label.value
        else ("no label")
    )
    parts = [
        f"{shown} ({label.source.value})",
        f"parallel {request.parallel.value} ({request.parallel.source.value})",
        f"Sweep {'on' if request.sweep.value else 'off'} ({request.sweep.source.value})",
    ]
    return "; ".join(parts)
