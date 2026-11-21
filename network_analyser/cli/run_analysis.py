"""Analysis at the Run's end, and the bridge to the one online step (#94, #104, #102).

The Run's end order (ADR 0007) is:

    sessions closed -> Backups locked -> key unlocked -> passwords and passphrase wiped
    -> lookup questions -> ask Cisco -> Checks run -> outputs written

This module holds the "lookup questions -> ask Cisco" bridge. `lookup_questions` turns the
Run's records into the de-duplicated, pattern-valid values `advisories` may send, with no
device record in them. `answers_for` asks Cisco through `advisories` with the unlocked key.
`analysis_answers` adapts Cisco's replies (`records.cisco`) into the plain answers Analysis's
Checks take (`records.analysis`), keeping "source unavailable: reason" as a source with no
answers, so an outage never reads as "Cisco said none".

`collected_from` is the show-output half of the input (#102): the Run's device records hold
each Visited Device's `Collected`, and Analysis cannot ask a device for it later.

`analysed` runs every Check on the built Topology. It takes Cisco's answers when the Run had
them, the records' secret-free config facts (#96) and their collected show output (#102);
without answers it is the offline form for a stopped Run, a Run with lookups off, or a Run
with no key: every source is unavailable, so the configuration, consistency and v1 Topology
Checks still run.
"""

import re
from collections.abc import Iterable
from typing import Final

from network_analyser import advisories, analysis
from network_analyser.advisories import ProxyConfig, Transport
from network_analyser.analysis.releases import normalise_release, train_of
from network_analyser.backup_store import CiscoKey
from network_analyser.credentials import SecretScan
from network_analyser.records.analysis import (
    AdvisoryAnswer,
    AnalysisInput,
    CiscoAnswers,
    ConfigFacts,
    DeviceCollected,
    EoxAnswers,
    FixedRelease,
    HardwareEox,
    OsType,
    ReleaseAdvisories,
    SoftwareEox,
    SourceUnavailable,
    SuggestedReleases,
)
from network_analyser.records.cisco import (
    AdvisoriesAnswer,
    CiscoAdvisory,
    CiscoOsType,
    EoxAnswer,
    EoxRecord,
    SuggestionsAnswer,
)
from network_analyser.records.cisco import (
    CiscoAnswers as CiscoReplies,
)
from network_analyser.records.cisco import (
    LookupQuestions as CiscoQuestions,
)
from network_analyser.records.cisco import (
    ReleaseQuestion as CiscoReleaseQuestion,
)
from network_analyser.records.cisco import (
    SourceUnavailable as CiscoSourceUnavailable,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import (
    ADVISORY_STATUS,
    AdvisoryDetail,
    AnalysisResults,
    CiscoDetailKind,
    EoxItem,
    EoxKind,
    FindingLevel,
    Topology,
)
from network_analyser.topology.devices import known_devices

LOOKUPS_DID_NOT_RUN: Final = "Cisco lookups did not run"
"""The reason every Cisco source gives when the online step was not asked (#104)."""

_TRAIN: Final = re.compile(r"^\d{1,3}\.\d{1,3}(?:[.(]|$)")
_CISCO_OS: Final = {
    OsType.IOS: CiscoOsType.IOS,
    OsType.IOS_XE: CiscoOsType.IOS_XE,
    OsType.NX_OS: CiscoOsType.NX_OS,
}
_ANALYSIS_OS: Final = {value: key for key, value in _CISCO_OS.items()}
_SIR: Final = {level.value.lower(): level for level in FindingLevel}


def lookup_questions(data: AnalysisInput) -> CiscoQuestions:
    """Return the exact values `advisories` may send: PIDs and OS type + release strings.

    Every value comes from `analysis.lookup_questions`, so it is already pattern-checked,
    de-duplicated and sorted, and holds no hostname, address, serial, count or config line.
    A PID is used for both EoX and Software Suggestion. An NX-OS release is sent only with the
    Nexus hardware family `analysis` worked out (#78, story 46): `advisories` refuses an NX-OS
    question without one, so leaving it out is what keeps the rest of the batch askable.
    """
    asked = analysis.lookup_questions(data)
    releases = tuple(
        CiscoReleaseQuestion(
            _CISCO_OS[question.os_type], question.release, question.hardware_family
        )
        for question in asked.releases
        if question.os_type is not OsType.NX_OS or question.hardware_family is not None
    )
    return CiscoQuestions(
        releases=releases,
        hardware_pids=asked.pids,
        software_releases=tuple(question.release for question in asked.releases),
        suggestion_pids=asked.pids,
    )


def collected_from(records: Iterable[DeviceRecord]) -> tuple[DeviceCollected, ...]:
    """Return each device's collected show output, keyed by the address logged into.

    A record with no collection (a device the visit never reached, or an Unvisited Device) is
    left out; Analysis then reads its show output as `Unknown`, never as a pass (#102).
    """
    return tuple(
        DeviceCollected(record.ip, record.collected)
        for record in records
        if record.collected is not None
    )


def analysed(
    built: Topology,
    answers: CiscoAnswers | None = None,
    *,
    records: tuple[DeviceRecord, ...] = (),
) -> AnalysisResults:
    """Run every Check on `built`, with Cisco's answers, config facts and show output.

    Without `answers`, every source is unavailable, so the offline Checks still run and no
    per-device Finding is raised from Cisco (story 10). `records` are the same device records
    `built` was made from; their secret-free config facts ride into `AnalysisInput.config_facts`
    (#96) and their collected show output into `AnalysisInput.collected` (#102). With none,
    every fact and show command reads as `Unknown`, so a Check says it could not decide rather
    than passing.
    """
    without_cisco = CiscoAnswers.unavailable(LOOKUPS_DID_NOT_RUN)
    return analysis.analyse(
        AnalysisInput(
            topology=built,
            answers=answers if answers is not None else without_cisco,
            config_facts=_config_facts(records),
            collected=collected_from(records),
        )
    )


def answers_for(
    questions: CiscoQuestions,
    key: CiscoKey,
    *,
    proxy: ProxyConfig | None = None,
    scan: SecretScan | None = None,
    transport: Transport | None = None,
) -> CiscoReplies:
    """Ask Cisco `questions` with the unlocked `key`; the one online step of a Run (#104).

    It hands `advisories` only the plain questions and the key's two `Secret`s, never a device
    record. A source it could not ask comes back `SourceUnavailable(reason)`, never empty.
    """
    return advisories.ask_cisco(
        questions,
        key.client_id,
        key.client_secret,
        proxy=proxy,
        scan=scan,
        transport=transport,
    )


def analysis_answers(replies: CiscoReplies, asked: CiscoQuestions) -> CiscoAnswers:
    """Adapt Cisco's replies into the plain answers Analysis's Checks take (#104).

    Each source stays whole: a `SourceUnavailable` makes the whole source unavailable, so no
    per-device Finding can be raised from an outage (stories 118-120). `asked` is what was
    sent, so every PID and release asked about gets an answer record, empty when Cisco named
    nothing. Cisco's Advisory text is kept as data; whatever shows it escapes it (story 117).
    """
    return CiscoAnswers(
        advisories=_advisories(replies.advisories),
        eox=_eox(replies.hardware_eox, replies.software_eox, asked),
        suggestions=_suggestions(replies.suggestions, asked),
    )


# -- Cisco's replies, adapted ----------------------------------------------------------------


def _advisories(
    source: tuple[AdvisoriesAnswer | CiscoSourceUnavailable, ...],
) -> tuple[ReleaseAdvisories, ...] | SourceUnavailable:
    unavailable = next((item for item in source if isinstance(item, CiscoSourceUnavailable)), None)
    if unavailable is not None:
        return SourceUnavailable(unavailable.reason)
    return tuple(_release_answer(item) for item in source if isinstance(item, AdvisoriesAnswer))


def _release_answer(answer: AdvisoriesAnswer) -> ReleaseAdvisories:
    question = answer.question
    os_type = _ANALYSIS_OS[question.os_type]
    train = _train(question.release, os_type)
    return ReleaseAdvisories(
        os_type=os_type,
        release=question.release,
        advisories=tuple(_advisory(item, train, os_type) for item in answer.advisories),
        hardware_family=question.platform_alias,
    )


def _advisory(advisory: CiscoAdvisory, train: str | None, os_type: OsType) -> AdvisoryAnswer:
    first_fixed = tuple(
        FixedRelease(trains, release)
        for release in advisory.first_fixed
        if (trains := _train(release, os_type)) is not None
    )
    in_train = next(
        (
            release
            for release in advisory.first_fixed
            if train is not None and _train(release, os_type) == train
        ),
        None,
    )
    return AdvisoryAnswer(
        detail=AdvisoryDetail(
            kind=CiscoDetailKind.ADVISORY,
            id=advisory.advisory_id,
            title=advisory.title,
            sir=_SIR.get(advisory.sir.strip().lower(), FindingLevel.LOW),
            cvss="" if advisory.cvss_base_score is None else f"{advisory.cvss_base_score:g}",
            cves=advisory.cves,
            published=advisory.first_published,
            updated=advisory.last_updated,
            first_fixed=in_train,
            status=ADVISORY_STATUS,
        ),
        first_fixed=first_fixed,
    )


def _eox(
    hardware: EoxAnswer | CiscoSourceUnavailable,
    software: EoxAnswer | CiscoSourceUnavailable,
    asked: CiscoQuestions,
) -> tuple[EoxAnswers, ...] | SourceUnavailable:
    if isinstance(hardware, CiscoSourceUnavailable):
        return SourceUnavailable(hardware.reason)
    if isinstance(software, CiscoSourceUnavailable):
        return SourceUnavailable(software.reason)
    hardware_records = _eox_by_input(hardware)
    software_records = _eox_by_input(software)
    return (
        EoxAnswers(
            hardware=tuple(
                HardwareEox(pid, items=_items(EoxKind.HARDWARE, hardware_records.get(pid, ())))
                for pid in asked.hardware_pids
            ),
            software=tuple(
                SoftwareEox(
                    release, items=_items(EoxKind.SOFTWARE, software_records.get(release, ()))
                )
                for release in asked.software_releases
            ),
        ),
    )


def _eox_by_input(answer: EoxAnswer) -> dict[str, tuple[EoxRecord, ...]]:
    grouped: dict[str, list[EoxRecord]] = {}
    for record in answer.records:
        grouped.setdefault(record.input_value, []).append(record)
    return {value: tuple(records) for value, records in grouped.items()}


def _items(kind: EoxKind, records: tuple[EoxRecord, ...]) -> tuple[EoxItem, ...]:
    return tuple(
        EoxItem(
            kind=kind,
            name=record.product_id or record.description,
            last_date_of_support=record.last_date_of_support,
            end_of_security_support=record.end_of_security_vul_support,
            end_of_sw_maintenance=record.end_of_sw_maintenance,
            end_of_sale=record.end_of_sale,
            replacement=record.migration_product_id,
        )
        for record in records
    )


def _suggestions(
    source: SuggestionsAnswer | CiscoSourceUnavailable, asked: CiscoQuestions
) -> tuple[SuggestedReleases, ...] | SourceUnavailable:
    if isinstance(source, CiscoSourceUnavailable):
        return SourceUnavailable(source.reason)
    by_pid = {answer.product_id: answer for answer in source.answers}
    return tuple(
        SuggestedReleases(
            pid,
            releases=tuple(item.release for item in by_pid[pid].releases if item.suggested),
        )
        if pid in by_pid
        else SuggestedReleases(pid)
        for pid in asked.suggestion_pids
    )


def _train(release: str, os_type: OsType) -> str | None:
    """The Train a release belongs to, such as `17.9` or `7.0(3)I7`; None if unreadable."""
    normalised = normalise_release(release)
    if _TRAIN.match(normalised) is None:
        return None
    return train_of(normalised, os_type)


def _config_facts(records: tuple[DeviceRecord, ...]) -> tuple[ConfigFacts, ...]:
    """Each Visited Device's facts, under the same id `topology.build` gave it."""
    return tuple(
        ConfigFacts(known.id, known.record.config_facts) for known in known_devices(records)
    )
