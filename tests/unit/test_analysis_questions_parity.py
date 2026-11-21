"""Every value `analysis` asks for is a value `advisories` will send (#130).

Both modules read one set of patterns, so a PID or release one accepts cannot be refused by
the other. These tests drive `analysis.lookup_questions` with the estates the review named
(ISR G2 and ISR 4000 routers, a Catalyst 9000v and the NX-OS 9000v) and put every value it
emits through `advisories`' own checks.
"""

from dataclasses import replace

import pytest

from network_analyser import analysis, topology
from network_analyser.advisories import is_safe_pid, is_safe_platform_alias, is_safe_release
from network_analyser.cli import run_analysis
from network_analyser.records import Platform
from network_analyser.records.analysis import AnalysisInput, OsType
from network_analyser.records.device import DeviceRecord
from tests.support.topology_records import visited

SWITCH = "C9300-48P"
ISR_4K = "ISR4451-X/K9"
ISR_G2 = "CISCO2911/K9"
VIRTUAL = "C9300v"
NEXUS_VIRTUAL = "N9K-C9300v"


def device(
    address: str,
    hostname: str,
    *,
    model: str,
    release: str,
    platform: Platform = Platform.IOS_XE,
) -> DeviceRecord:
    record = visited(address, f"SN-{hostname}", hostname, platform=platform)
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, model=model, software_version=release))


def estate() -> AnalysisInput:
    return AnalysisInput(
        topology=topology.build(
            [
                device("192.0.2.1", "sw-a", model=SWITCH, release="17.9.4a"),
                device("192.0.2.2", "rtr-a", model=ISR_4K, release="16.9.3"),
                device("192.0.2.3", "rtr-b", model=ISR_G2, release="15.7(3)M9"),
                device("192.0.2.4", "sw-b", model=VIRTUAL, release="17.12.1"),
                device(
                    "192.0.2.5",
                    "nx-a",
                    model=NEXUS_VIRTUAL,
                    release="9.3(10)",
                    platform=Platform.NX_OS,
                ),
                device(
                    "192.0.2.6",
                    "nx-b",
                    model="N9K-C93180YC-FX",
                    release="7.0(3)I7(9)",
                    platform=Platform.NX_OS,
                ),
            ]
        )
    )


def test_every_pid_analysis_asks_for_passes_the_advisories_pattern() -> None:
    asked = analysis.lookup_questions(estate())

    assert {SWITCH, ISR_4K, ISR_G2, VIRTUAL, NEXUS_VIRTUAL} <= set(asked.pids)
    assert {SWITCH, ISR_4K, ISR_G2, VIRTUAL, NEXUS_VIRTUAL} <= set(asked.compatible_pids)
    assert all(is_safe_pid(pid) for pid in (*asked.pids, *asked.compatible_pids))


def test_every_release_and_family_analysis_asks_for_passes_the_advisories_pattern() -> None:
    asked = analysis.lookup_questions(estate())

    assert {OsType.IOS, OsType.IOS_XE, OsType.NX_OS} == {item.os_type for item in asked.releases}
    assert all(is_safe_release(item.release) for item in asked.releases)
    families = [item.hardware_family for item in asked.releases if item.hardware_family]
    assert families
    assert all(is_safe_platform_alias(family) for family in families)


def test_the_bridge_hands_every_value_analysis_asked_for_to_advisories() -> None:
    asked = run_analysis.lookup_questions(estate())

    assert all(is_safe_pid(pid) for pid in asked.hardware_pids)
    assert all(is_safe_pid(pid) for pid in asked.suggestion_pids)
    assert all(is_safe_pid(pid) for pid in asked.compatible_pids)
    assert all(is_safe_release(release) for release in asked.software_releases)
    assert ISR_4K in asked.hardware_pids
    assert ISR_4K in asked.compatible_pids


@pytest.mark.parametrize(
    "model",
    [
        "C9300-48P\r\n",
        "../C9300-48P",
        "C9300%2e48P",
        "C9300-48P;DROP",
        "C9300-\u096a\u096eP",
        "C9300-48P/K9/K9",
        "ISR4451-X/",
        "<script>",
    ],
)
def test_a_hostile_model_is_not_asked_for_and_the_rest_still_is(model: str) -> None:
    odd = AnalysisInput(
        topology=topology.build(
            [
                device("192.0.2.1", "sw-a", model=SWITCH, release="17.9.4a"),
                device("192.0.2.2", "rtr-a", model=model, release="17.9.4a"),
            ]
        )
    )

    asked = analysis.lookup_questions(odd)

    assert asked.pids == (SWITCH,)
    assert asked.compatible_pids == (SWITCH,)
    assert [(item.os_type, item.release) for item in asked.releases] == [(OsType.IOS_XE, "17.9.4a")]
