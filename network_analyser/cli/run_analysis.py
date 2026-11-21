"""Analysis at the Run's end, and the slot where the online step will go (#94, #104).

The Run's end order (ADR 0007) is:

    sessions closed -> Backups locked -> key unlocked -> passwords and passphrase wiped
    -> lookup questions -> ask Cisco -> Checks run -> outputs written

This module sits at "lookup questions -> ask Cisco -> Checks run". `answers_for` is the
"ask Cisco" seam: today it is offline and every source is unavailable, so the Run adds no
outbound connection. #104 replaces its body with the `advisories` call; the `analysis` API
does not change.
"""

import dataclasses
from typing import Final

from network_analyser import analysis
from network_analyser.records.analysis import (
    AnalysisInput,
    CiscoAnswers,
    ConfigFacts,
    LookupQuestions,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import AnalysisResults, Topology
from network_analyser.topology.devices import known_devices

LOOKUPS_DID_NOT_RUN: Final = "Cisco lookups did not run in this version"
"""The reason every Cisco source gives while the online step is a placeholder (#104)."""


def answers_for(_questions: LookupQuestions) -> CiscoAnswers:
    """Ask Cisco the lookup questions. Offline placeholder; #104 fills in the body."""
    return CiscoAnswers.unavailable(LOOKUPS_DID_NOT_RUN)


def analysed(built: Topology, records: tuple[DeviceRecord, ...] = ()) -> AnalysisResults:
    """Run the Run-end sequence on `built`: facts, questions, answers, then every Check.

    `records` are the same device records `built` was made from; their secret-free config
    facts ride into `AnalysisInput.config_facts` (#96). With none, every fact reads as
    `Unknown`, so a Check says it could not decide rather than passing.
    """
    data = AnalysisInput(topology=built, config_facts=_config_facts(records))
    questions = analysis.lookup_questions(data)
    answers = answers_for(questions)
    return analysis.analyse(dataclasses.replace(data, answers=answers))


def _config_facts(records: tuple[DeviceRecord, ...]) -> tuple[ConfigFacts, ...]:
    """Each Visited Device's facts, under the same id `topology.build` gave it."""
    return tuple(
        ConfigFacts(known.id, known.record.config_facts) for known in known_devices(records)
    )
