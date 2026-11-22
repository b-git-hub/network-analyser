"""The Run's end: go online once, run Analysis, write the outputs, and record what happened.

The decided order (ADR 0007, ADR 0008; ticket #104):

    sessions closed -> Backups locked -> key unlocked -> passwords and passphrase wiped
    -> lookup questions -> Cisco asked -> Checks run -> outputs written -> key, token and
    answers dropped

The crawl this module is handed has already closed every device session and drained the
Backing locking queue (`backup_store.BackupLocker.finish`), so nothing here holds a live
device. The key is unlocked with the Backup Passphrase only when lookups are on and the key
file exists; the password wipe follows at once, before any outbound connection. `--cisco-
lookups off` never opens the key file and never asks Cisco. A stopped Run, or one stopped
during the online step, takes the offline path and still records its `analysis` event (#143).

A source that could not be asked becomes one Needs-attention line, never a per-device
Finding, and the Run still writes its outputs and keeps its Backups (stories 118-120). A Check
that raises on Cisco's answers falls back to offline Analysis, so the Run still writes every
output (story 120, #143).
"""

import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from network_analyser import backup_store
from network_analyser.advisories import LookupInterrupted, ProxyConfig
from network_analyser.advisories.session import REJECTED, TOKEN_EXPIRED
from network_analyser.cli import run_analysis, run_topology
from network_analyser.cli.parser import PROG
from network_analyser.credentials import CredentialSets, SecretScan
from network_analyser.records.analysis import AnalysisInput, CiscoAnswers, SourceUnavailable
from network_analyser.records.cisco import CiscoCallTally, LookupQuestions, TokenOutcome
from network_analyser.records.device import DeviceRecord
from network_analyser.records.events import AnalysisRan
from network_analyser.records.scope import ScopeRecord
from network_analyser.records.topology import (
    AnalysisResults,
    CiscoLookups,
    FindingLevel,
    Topology,
)
from network_analyser.run_output import AuditLog, RunFolder

NO_KEY_NOTICE: Final = (
    "No Cisco API key is stored. This Run will skip Cisco lookups. Add one with "
    f'"{PROG} cisco-key set", or pass --cisco-lookups off.'
)
"""The one notice a Run with no key prints before the first prompt (story 35)."""

NO_KEY_ATTENTION: Final = (
    "No Cisco API key is stored, so Cisco lookups did not run. Add one with "
    f'"{PROG} cisco-key set", or pass --cisco-lookups off.'
)
"""Its one Needs-attention line at the Run's end (story 35)."""

LOOKUPS_FAILED: Final = "Cisco lookups did not finish"
"""Fixed text when the online step raised, so the Run still writes its outputs."""

ANALYSIS_FAILED: Final = (
    "Warning: Analysis could not use Cisco's answers, so the Run's Checks ran offline. "
    "The Backups\nand every other output are unaffected."
)
"""Fixed text when a Check raised on Cisco's answers, so the Run still writes its outputs."""

_SOURCES: Final = (
    ("advisories", "Cisco advisories (openVuln)"),
    ("eox", "Cisco EoX"),
    ("suggestions", "Cisco Software Suggestion"),
    ("compatible", "Cisco Software Suggestion"),
)
"""One Needs-attention line per name, first reason wins: the two Software Suggestion calls share
one name (#131)."""
_REJECTED: Final = REJECTED
_ALL_SOURCES: Final = "Cisco lookups"
"""The subject of the one line a rejected key gives, however many sources it stopped."""
_KEY_STEP: Final = f'Run "{PROG} cisco-key set" to store a working key.'
_EXPIRED_LINE: Final = (
    f"{_ALL_SOURCES} stopped early: {TOKEN_EXPIRED}. "
    "Answers already received were kept; run again for the rest."
)
"""The one line an expired token gives, however many sources it stopped. It does not blame the key
or send the operator to cisco-key set: Cisco's token is issued once a Run (#133)."""
_REJECTED_LINE: Final = f"{_ALL_SOURCES} stopped: {_REJECTED}. {_KEY_STEP}"
"""The one line a rejected key gives, however many sources it stopped. It says the lookups
stopped, never that they did not run: an earlier source may already have answered (#155)."""


@dataclass(frozen=True, slots=True)
class EndOutcome:
    """What the Run's end produced, for the summary, the report and `topology.json`.

    Attributes:
        written: whether every output was written.
        attention: one Needs-attention line per Cisco source that did not run, or the
            missing-key line.
        results: Analysis's Findings, advice and Check list; None when Analysis did not run.
        lookups: what `topology.json` records about Cisco lookups.
        stopped: whether the operator's Ctrl+C ended the online step, so the Run is reported
            stopped and exits 3 (#143).
    """

    written: bool
    attention: tuple[str, ...]
    results: AnalysisResults | None = None
    lookups: CiscoLookups = field(default_factory=lambda: CiscoLookups(ran=False))
    stopped: bool = False


def missing_key_notice(*, lookups_enabled: bool, key_file: Path) -> str | None:
    """Return the notice to print before the first prompt, or None when none is due."""
    if lookups_enabled and not key_file.is_file():
        return NO_KEY_NOTICE
    return None


def wipe(sets: CredentialSets, passphrase: backup_store.BackupPassphrase) -> None:
    """Wipe every Credential Set password and the Backup Passphrase (ADR 0007, step 4)."""
    sets.wipe()
    passphrase.wipe()


def finish(  # noqa: PLR0913 (the Run's end, every dependency explicit)
    *,
    audit: AuditLog,
    folder: RunFolder,
    collected: run_topology.Collector,
    scan: SecretScan,
    scope: ScopeRecord | None,
    passphrase: backup_store.BackupPassphrase,
    sets: CredentialSets,
    key_file: Path,
    lookups_enabled: bool,
    proxy: ProxyConfig | None = None,
    now: datetime | None = None,
) -> EndOutcome:
    """Unlock, wipe, ask Cisco, run every Check, write every output, record the event.

    Called after the crawl has closed every session and locked every Backup, inside the
    Run's audit trail so the `analysis` event lands before the Run-end event. The key, its
    token and Cisco's answers are dropped before this returns, and the `try` starts right
    after the unlock, so a failure in Topology building cannot skip the key wipe (#143).
    """
    key = None
    locked_out = False
    stopped = False
    try:
        if lookups_enabled and key_file.is_file():
            key = backup_store.unlock_key_file(key_file, passphrase)
            if key is not None:
                key.add_to_scan(scan)  # story 40: the key joins the scan as soon as it exists
        locked_out = lookups_enabled and key is None and key_file.is_file()
        wipe(sets, passphrase)

        built = run_topology.build_topology(collected.records(), scope)
        known = AnalysisInput(
            topology=built,
            collected=run_analysis.collected_from(collected.records()),
            inventory=run_analysis.inventories(built, collected.records()),
        )
        answers, lookups, replies, stopped = _ask(known, key, scan=scan, proxy=proxy, now=now)
        results, answers = _analysed(built, answers, lookups, collected.records())
        audit.record(analysis_event(results, lookups, replies))
        written = run_topology.save_all(
            folder,
            collected.records(),
            scan,
            scope=scope,
            results=results,
            lookups=lookups,
        )
    finally:
        if key is not None:
            key.wipe()
    return EndOutcome(
        written=written,
        attention=_attention(
            lookups_enabled=lookups_enabled,
            key=key,
            locked_out=locked_out,
            answers=answers,
            lookups=lookups,
            stopped=stopped,
        ),
        results=results,
        lookups=lookups,
        stopped=stopped,
    )


def _analysed(
    built: Topology,
    answers: CiscoAnswers,
    lookups: CiscoLookups,
    records: tuple[DeviceRecord, ...],
) -> tuple[AnalysisResults, CiscoAnswers]:
    """Run every Check, returning the results and the answers they were run with.

    Cisco's replies are not signed or fully controlled, so odd data must never cost the Run
    its `topology.json`, diagram and Findings report (story 120, #143): a Check that raises on
    them is retried offline, and the offline answers also carry the Needs-attention lines.
    When Cisco was not asked there is no Cisco data to blame, so the exception is the Run's
    own and propagates.
    """
    try:
        return run_analysis.analysed(built, answers, records=records), answers
    except Exception:  # one odd Cisco reply must not lose every output
        if not lookups.ran:
            raise
        print(ANALYSIS_FAILED, file=sys.stderr)
        offline = CiscoAnswers.unavailable(LOOKUPS_FAILED)
        return run_analysis.analysed(built, offline, records=records), offline


def _ask(
    known: AnalysisInput,
    key: backup_store.CiscoKey | None,
    *,
    scan: SecretScan,
    proxy: ProxyConfig | None,
    now: datetime | None,
) -> tuple[CiscoAnswers, CiscoLookups, CiscoCallTally | None, bool]:
    """Return Analysis's answers, the lookup record, Cisco's call tally and whether stopped.

    A Ctrl+C landed on the online step is treated as lookups that did not finish: the Run
    still writes its outputs and records them, and is reported stopped (#143).
    """
    if key is None:
        return (
            CiscoAnswers.unavailable(run_analysis.LOOKUPS_DID_NOT_RUN),
            CiscoLookups(ran=False),
            None,
            False,
        )
    asked = run_analysis.lookup_questions(known)
    if not _has_questions(asked):
        return (
            CiscoAnswers.unavailable(run_analysis.LOOKUPS_DID_NOT_RUN),
            CiscoLookups(ran=False),
            None,
            False,
        )
    when = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    try:
        replies = run_analysis.answers_for(asked, key, proxy=proxy, scan=scan)
        answers = run_analysis.analysis_answers(replies, asked)
    except KeyboardInterrupt:
        _warn_lookups_did_not_finish()
        return (
            CiscoAnswers.unavailable(LOOKUPS_FAILED),
            CiscoLookups(ran=True, when=when),
            None,
            True,
        )
    except LookupInterrupted as stopped:
        _warn_lookups_did_not_finish()
        return (
            CiscoAnswers.unavailable(LOOKUPS_FAILED),
            CiscoLookups(ran=True, when=when),
            stopped.tally,
            False,
        )
    except Exception:  # noqa: BLE001 (an outage must never cost the Run its outputs)
        _warn_lookups_did_not_finish()
        return (
            CiscoAnswers.unavailable(LOOKUPS_FAILED),
            CiscoLookups(ran=True, when=when),
            None,
            False,
        )
    return answers, CiscoLookups(ran=True, when=when), replies.tally, False


def _warn_lookups_did_not_finish() -> None:
    print(
        "Warning: Cisco lookups did not finish; the Run's Backups and other outputs are "
        "unaffected.",
        file=sys.stderr,
    )


def _has_questions(asked: LookupQuestions) -> bool:
    return bool(
        asked.releases
        or asked.hardware_pids
        or asked.software_releases
        or asked.suggestion_pids
        or asked.compatible_pids
    )


def _attention(  # noqa: PLR0913 (the Run end's state, each part named)
    *,
    lookups_enabled: bool,
    key: backup_store.CiscoKey | None,
    locked_out: bool,
    answers: CiscoAnswers,
    lookups: CiscoLookups,
    stopped: bool,
) -> tuple[str, ...]:
    """One Needs-attention line per Cisco source that did not run (stories 35, 118).

    A Ctrl+C during the online step already shows as a stopped Run, so it adds no line that
    blames a Cisco source (#143).
    """
    if not lookups_enabled or stopped:
        return ()
    if key is None:
        if locked_out:
            return (backup_store.KEY_LOCKED_ELSEWHERE,)
        return (NO_KEY_ATTENTION,)
    if not lookups.ran:
        return ()  # there was nothing Cisco could be asked, so no source was down
    return attention_lines(answers)


def attention_lines(answers: CiscoAnswers) -> tuple[str, ...]:
    """One Needs-attention line per named Cisco source that did not run.

    A rejected key and an expired token each give one line, whatever they stopped, and they
    are decided first: a rejected compatible list still gives the key line when Software
    Suggestion failed for another reason, although the two calls share one name (#131, #155).
    """
    sources = tuple(getattr(answers, name) for name, _shown in _SOURCES)
    lines: list[str] = []
    if any(_rejected(source) for source in sources):
        lines.append(_REJECTED_LINE)
    if any(_is_expired(source) for source in sources):
        lines.append(_EXPIRED_LINE)
    named: set[str] = set()
    for (_name, shown), source in zip(_SOURCES, sources, strict=True):
        if not isinstance(source, SourceUnavailable) or shown in named:
            continue
        if source.reason in (_REJECTED, TOKEN_EXPIRED):
            continue  # its one line is already above
        named.add(shown)
        lines.append(_source_line(shown, source.reason))
    return tuple(lines)


def _rejected(source: object) -> bool:
    """Whether a source says Cisco refused the API key."""
    return isinstance(source, SourceUnavailable) and source.reason == _REJECTED


def _is_expired(source: object) -> bool:
    """Whether a source says the token expired: whole, or for some of its chassis PIDs."""
    if isinstance(source, SourceUnavailable):
        return source.reason == TOKEN_EXPIRED
    if isinstance(source, tuple):
        return any(getattr(item, "unanswered", None) == TOKEN_EXPIRED for item in source)
    return False


def _source_line(shown: str, reason: str) -> str:
    """The Needs-attention line for one source that did not run; a shared name shares a line."""
    return f"{shown} did not run: {reason}."


def analysis_event(
    results: AnalysisResults,
    lookups: CiscoLookups,
    tally: CiscoCallTally | None,
) -> AnalysisRan:
    """Return the Audit log's one `analysis` event: counts only, no device or Cisco value.

    It says which Checks ran or were skipped and why, the Finding count per level and per
    Check (story 114), and how many calls and values went to each Cisco endpoint with the
    token result (story 22). Never a device name, a per-device Finding, a Cisco value, the
    client ID or the token.
    """
    levels = Counter(finding.level for finding in results.findings)
    by_check = Counter(finding.check.id for finding in results.findings)
    check_ids = list(dict.fromkeys(run.check.id for run in results.checks))
    check_ids.extend(check for check in by_check if check not in check_ids)
    token = tally.token if tally is not None else None
    return AnalysisRan(
        cisco_lookups_ran=lookups.ran,
        cisco_lookups_when=lookups.when,
        checks=tuple((run.check.id, run.ran, run.reason) for run in results.checks),
        findings_by_level=tuple((level.value, levels.get(level, 0)) for level in FindingLevel),
        findings_by_check=tuple((check, by_check.get(check, 0)) for check in check_ids),
        token_outcome=(token.outcome if token is not None else TokenOutcome.NOT_REQUESTED).value,
        token_status=None if token is None else token.status,
        token_error=None if token is None else token.error_code,
        endpoints=()
        if tally is None
        else tuple(
            (use.endpoint.value, use.calls, use.values, use.retries, use.pages)
            for use in tally.endpoints
        ),
    )
