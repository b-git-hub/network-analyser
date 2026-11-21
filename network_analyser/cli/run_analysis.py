"""Analysis at the Run's end, and the slot where the online step will go (#94, #104, #102).

The Run's end order (ADR 0007) is:

    sessions closed -> Backups locked -> key unlocked -> passwords and passphrase wiped
    -> lookup questions -> ask Cisco -> Checks run -> outputs written

This module sits at "lookup questions -> ask Cisco -> Checks run". `answers_for` is the
"ask Cisco" seam: today it is offline and every source is unavailable, so the Run adds no
outbound connection. #104 replaces its body with the `advisories` call; the `analysis` API
does not change.

`collected_from` is the show-output half of the input (#102): the Run's device records hold
each Visited Device's `Collected`, and Analysis cannot ask a device for it later.
"""

import dataclasses
from collections.abc import Iterable
from typing import Final

from network_analyser import analysis
from network_analyser.records.analysis import (
    AnalysisInput,
    CiscoAnswers,
    ConfigFacts,
    DeviceCollected,
    LookupQuestions,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import AnalysisResults, Topology
from network_analyser.topology.devices import known_devices

LOOKUPS_DID_NOT_RUN: Final = "Cisco lookups did not run in this version"
"""The reason every Cisco source gives while the online step is a placeholder (#104)."""


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


def answers_for(_questions: LookupQuestions) -> CiscoAnswers:
    """Ask Cisco the lookup questions. Offline placeholder; #104 fills in the body."""
    return CiscoAnswers.unavailable(LOOKUPS_DID_NOT_RUN)


def analysed(built: Topology, records: tuple[DeviceRecord, ...] = ()) -> AnalysisResults:
    """Run the Run-end sequence on `built`: facts, questions, answers, then every Check.

    `records` are the same device records `built` was made from; their secret-free config
    facts ride into `AnalysisInput.config_facts` (#96) and their collected show output into
    `AnalysisInput.collected` (#102). With none, every fact and show command reads as
    `Unknown`, so a Check says it could not decide rather than passing.
    """
    data = AnalysisInput(
        topology=built,
        config_facts=_config_facts(records),
        collected=collected_from(records),
    )
    questions = analysis.lookup_questions(data)
    answers = answers_for(questions)
    return analysis.analyse(dataclasses.replace(data, answers=answers))


def _config_facts(records: tuple[DeviceRecord, ...]) -> tuple[ConfigFacts, ...]:
    """Each Visited Device's facts, under the same id `topology.build` gave it."""
    return tuple(
        ConfigFacts(known.id, known.record.config_facts) for known in known_devices(records)
    )
