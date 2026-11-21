"""Analysis at the Run's end, and the slot where the online step will go (#94, #104).

The Run's end order (ADR 0007) is:

    sessions closed -> Backups locked -> key unlocked -> passwords and passphrase wiped
    -> lookup questions -> ask Cisco -> Checks run -> outputs written

This module sits at "lookup questions -> ask Cisco -> Checks run". `answers_for` is the
"ask Cisco" seam: today it is offline and every source is unavailable, so the Run adds no
outbound connection. #104 replaces its body with the `advisories` call; the `analysis` API
does not change.
"""

from typing import Final

from network_analyser import analysis
from network_analyser.records.analysis import AnalysisInput, CiscoAnswers, LookupQuestions
from network_analyser.records.topology import AnalysisResults, Topology

LOOKUPS_DID_NOT_RUN: Final = "Cisco lookups did not run in this version"
"""The reason every Cisco source gives while the online step is a placeholder (#104)."""


def answers_for(_questions: LookupQuestions) -> CiscoAnswers:
    """Ask Cisco the lookup questions. Offline placeholder; #104 fills in the body."""
    return CiscoAnswers.unavailable(LOOKUPS_DID_NOT_RUN)


def analysed(built: Topology) -> AnalysisResults:
    """Run the Run-end sequence on `built`: questions, then answers, then every Check."""
    questions = analysis.lookup_questions(AnalysisInput(topology=built))
    answers = answers_for(questions)
    return analysis.analyse(AnalysisInput(topology=built, answers=answers))
