"""Synthetic Analysis inputs for the show-output Checks (#102).

The seam is `analysis.analyse`: plain records in, plain results out. These helpers only
assemble the Run's inputs the way `cli.run_analysis` does, so a test never reaches inside a
Check: it builds a Visited Device with hand-written show output, then reads the Findings and
Check results the operator would see.
"""

from collections.abc import Iterable

from network_analyser import analysis, topology
from network_analyser.records.analysis import (
    AnalysisInput,
    ConfigFact,
    ConfigFacts,
    DeviceCollected,
    FactValue,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import AnalysisResults, CheckRun, Finding


def collected_of(*records: DeviceRecord) -> tuple[DeviceCollected, ...]:
    """Each record's collected show output, keyed by its address, as the Run hands it over."""
    return tuple(
        DeviceCollected(record.ip, record.collected)
        for record in records
        if record.collected is not None
    )


def analysed(
    *records: DeviceRecord, facts: ConfigFacts | Iterable[ConfigFacts] = ()
) -> AnalysisResults:
    """Run Analysis on `records`, handing it their collected show output and `facts`."""
    built = topology.build(records)
    collected = collected_of(*records)
    given = (facts,) if isinstance(facts, ConfigFacts) else tuple(facts)
    return analysis.analyse(AnalysisInput(topology=built, collected=collected, config_facts=given))


def facts(device: str, **values: FactValue) -> ConfigFacts:
    """A device's config facts, from name and value pairs."""
    return ConfigFacts(
        device,
        tuple(ConfigFact(name=name, value=value) for name, value in values.items()),
    )


def found(results: AnalysisResults, check_id: str) -> list[Finding]:
    """Every Finding one Check raised, worst first as Analysis sorts them."""
    return [finding for finding in results.findings if finding.check.id == check_id]


def run_of(results: AnalysisResults, check_id: str) -> CheckRun:
    """One Check's `CheckRun`."""
    return next(run for run in results.checks if run.check.id == check_id)
