"""One odd PID in an estate: the rest are checked, its device reads "could not check" (#130).

Seam 1 (`analysis`) and Seam 2 (`advisories` against the fake Cisco) end to end through the
Run's bridge. Every model, release and address is synthetic.
"""

from dataclasses import replace
from typing import Any

from network_analyser import topology
from network_analyser.advisories import Pacer, ask_cisco
from network_analyser.cli import run_analysis
from network_analyser.credentials import Secret
from network_analyser.records import Platform
from network_analyser.records.analysis import AnalysisInput
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import AnalysisResults, Finding
from tests.support.fake_cisco import CLIENT_ID, CLIENT_SECRET, FakeCisco
from tests.support.topology_records import visited

SWITCH = "C9300-48P"
ROUTER = "ISR4451-X/K9"
ODD = "ISR 4451;X"


def device(address: str, serial: str, hostname: str, model: str) -> DeviceRecord:
    record = visited(address, serial, hostname, platform=Platform.IOS_XE)
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, model=model, software_version="17.9.4a"))


def suggestion() -> list[dict[str, Any]]:
    return [
        {
            "relDispName": "17.9.5",
            "isSuggested": "Y",
            "releaseDate": "2026-03-01",
            "trainDispName": "17.9",
        }
    ]


def run(*models: str) -> tuple[FakeCisco, AnalysisResults]:
    records = tuple(
        device(f"192.0.2.{index + 1}", f"S{index + 1}", f"sw-{'abc'[index]}", model)
        for index, model in enumerate(models)
    )
    built = topology.build(records)
    asked = run_analysis.lookup_questions(AnalysisInput(topology=built))
    cisco = FakeCisco(
        suggestions={SWITCH: suggestion(), ROUTER: suggestion()},
        compatible={},
    )
    now = [0.0]

    def wait(seconds: float) -> None:
        now[0] += seconds

    replies = ask_cisco(
        asked,
        Secret(CLIENT_ID),
        Secret(CLIENT_SECRET),
        transport=cisco,
        pacer=Pacer(clock=lambda: now[0], wait=wait),
    )
    answers = run_analysis.analysis_answers(replies, asked)
    return cisco, run_analysis.analysed(built, answers, records=records)


def suggested_findings(results: AnalysisResults) -> list[Finding]:
    return [item for item in results.findings if item.check.id == "lifecycle-suggested-release"]


def test_an_isr_router_with_a_licence_suffix_is_asked_about() -> None:
    cisco, results = run(SWITCH, ROUTER)

    assert (
        "/software/suggestion/v2/suggestions/releases/productIds/C9300-48P,ISR4451-X%2FK9"
        in cisco.paths()
    )
    assert any("compatible/productId/ISR4451-X%2FK9" in path for path in cisco.paths())
    assert [item.what_was_found for item in suggested_findings(results)] == [
        "Release 17.9.4a is not one of Cisco's Suggested Releases for PID C9300-48P: 17.9.5.",
        "Release 17.9.4a is not one of Cisco's Suggested Releases for PID ISR4451-X/K9: 17.9.5.",
    ]


def test_one_odd_pid_is_not_sent_and_its_device_reads_could_not_check() -> None:
    cisco, results = run(SWITCH, ROUTER, ODD)

    paths = "\n".join(cisco.paths())
    assert "ISR4451-X%2FK9" in paths
    assert "C9300-48P" in paths
    assert "4451;X" not in paths
    assert " " not in paths
    findings = [item.what_was_found for item in suggested_findings(results)]
    assert (
        "Could not check the release against Cisco's Suggested Releases: the PID was not sent "
        "to Cisco because it does not match the safe pattern."
    ) in findings
    assert len(findings) == 3
    assert all(ODD not in text for text in findings)
