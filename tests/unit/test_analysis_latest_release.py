"""The Latest Release from Cisco's compatible list at Seam 1 (#127).

Driven through `analysis.analyse` and `analysis.lookup_questions` only. Every answer is
hand-written synthetic data: catalogue-style PIDs and public Cisco release strings only. The
tests read what the operator sees in the advice record: both values, their lifecycle codes, the
"running release is newer" text, and `not available` when Cisco gave no usable list (stories
1-13 of #122).
"""

from dataclasses import replace

from network_analyser import analysis, topology
from network_analyser.records.analysis import (
    AnalysisInput,
    CiscoAnswers,
    CompatibleRelease,
    CompatibleReleases,
    DeviceInventory,
    HardwareItem,
    HardwareKind,
    SourceUnavailable,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.platform import Platform
from network_analyser.records.topology import NOT_AVAILABLE, AnalysisResults
from tests.support.topology_records import visited

A = "192.0.2.1"
B = "192.0.2.2"
C = "192.0.2.3"
MODEL = "C9300-48P"
OTHER_MODEL = "C9300-24T"
LINE_CARD = "C9300-NM-8X"
NEXUS_MODEL = "N9K-C93180YC-FX"
NEWER = "running release is newer than Cisco's list"


def _device(  # noqa: PLR0913 (every device field the tests read, by name)
    address: str,
    serial: str,
    hostname: str,
    *,
    platform: Platform = Platform.IOS_XE,
    model: str = MODEL,
    release: str = "17.12.4",
) -> DeviceRecord:
    record = visited(address, serial, hostname, platform=platform)
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, model=model, software_version=release))


def _listed(*releases: tuple[str, str | None]) -> tuple[CompatibleRelease, ...]:
    return tuple(CompatibleRelease(release, lifecycle) for release, lifecycle in releases)


def _compatible(
    pid: str = MODEL,
    *releases: tuple[str, str | None],
    unanswered: str | None = None,
) -> CompatibleReleases:
    return CompatibleReleases(pid, releases=_listed(*releases), unanswered=unanswered)


def _results(
    *records: DeviceRecord,
    compatible: tuple[CompatibleReleases, ...] | SourceUnavailable = (),
) -> AnalysisResults:
    return analysis.analyse(
        AnalysisInput(
            topology=topology.build(records),
            answers=CiscoAnswers(compatible=compatible),
        )
    )


def test_the_highest_overall_and_in_train_come_from_the_compatible_list() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.12.4"),
        compatible=(
            _compatible(
                MODEL,
                ("17.12.8", "MD"),
                ("17.12.7b", "MD"),
                ("26.2.1", "ED"),
                ("17.18.4", "MD"),
            ),
        ),
    )

    (advice,) = results.advice
    assert advice.latest_release_in_train == "17.12.8"
    assert advice.latest_in_train_lifecycle == "MD"
    assert advice.latest_release == "26.2.1"
    assert advice.latest_release_lifecycle == "ED"


def test_the_highest_is_the_new_release_order_not_the_reply_order() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.12.4"),
        compatible=(
            _compatible(
                MODEL,
                ("26.1.3", "MD"),
                ("17.12.7b", "MD"),
                ("17.12.8", "GA"),
                ("26.1.2s1", "ED"),
                ("17.12.7", "MD"),
            ),
        ),
    )

    (advice,) = results.advice
    assert advice.latest_release_in_train == "17.12.8"
    assert advice.latest_release == "26.1.3"


def test_an_old_nxos_train_is_the_devices_own_train() -> None:
    results = _results(
        _device(
            A,
            "N1",
            "nx-a",
            platform=Platform.NX_OS,
            model=NEXUS_MODEL,
            release="7.0(3)I7(9)",
        ),
        compatible=(
            _compatible(
                NEXUS_MODEL,
                ("7.0(3)I7(10)", "MD"),
                ("10.4(8)", "ED"),
            ),
        ),
    )

    (advice,) = results.advice
    assert advice.latest_release_in_train == "7.0(3)I7(10)"
    assert advice.latest_release == "10.4(8)"


def test_a_lifecycle_code_that_fails_the_pattern_is_dropped() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.12.4"),
        compatible=(
            _compatible(
                MODEL,
                ("17.12.8", "md"),
                ("17.18.4", "ED<script>"),
                ("26.2.1", "ED"),
            ),
        ),
    )

    (advice,) = results.advice
    # 17.18.4 still wins its own Train, and 26.2.1 is overall; neither code survives.
    assert advice.latest_release_in_train == "17.12.8"
    assert advice.latest_in_train_lifecycle is None
    assert advice.latest_release == "26.2.1"
    assert advice.latest_release_lifecycle == "ED"


def test_a_device_running_above_the_list_says_so_for_both_values() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.18.5"),
        compatible=(_compatible(MODEL, ("17.12.8", "MD"), ("17.18.4", "MD")),),
    )

    (advice,) = results.advice
    assert advice.latest_release_in_train == NEWER
    assert advice.latest_in_train_lifecycle is None
    assert advice.latest_release == NEWER
    assert advice.latest_release_lifecycle is None


def test_running_above_only_the_train_value_keeps_the_overall_value() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.12.9"),
        compatible=(_compatible(MODEL, ("17.12.8", "MD"), ("26.2.1", "ED")),),
    )

    (advice,) = results.advice
    assert advice.latest_release_in_train == NEWER
    assert advice.latest_in_train_lifecycle is None
    assert advice.latest_release == "26.2.1"
    assert advice.latest_release_lifecycle == "ED"


def test_an_unanswered_pid_the_page_cap_and_a_source_outage_are_not_available() -> None:
    cases: tuple[tuple[str, tuple[CompatibleReleases, ...]], ...] = (
        ("unanswered", (_compatible(MODEL, unanswered="S3_INV_BASEPID"),)),
        ("page cap", (_compatible(MODEL, unanswered="page cap"),)),
        ("empty list", (_compatible(MODEL),)),
    )
    for label, compatible in cases:
        results = _results(_device(A, "S1", "sw-a"), compatible=compatible)
        (advice,) = results.advice
        assert advice.latest_release_in_train == NOT_AVAILABLE, label
        assert advice.latest_release == NOT_AVAILABLE, label
        assert advice.latest_in_train_lifecycle is None, label
        assert advice.latest_release_lifecycle is None, label

    down = _results(
        _device(B, "S2", "sw-b"),
        compatible=SourceUnavailable("Cisco did not answer"),
    )
    (advice,) = down.advice
    assert (advice.latest_release_in_train, advice.latest_release) == (
        NOT_AVAILABLE,
        NOT_AVAILABLE,
    )


def test_a_pid_with_no_answer_in_the_record_is_not_available() -> None:
    results = _results(
        _device(A, "S1", "sw-a"),
        compatible=(_compatible(OTHER_MODEL, ("17.12.8", "MD")),),
    )

    (advice,) = results.advice
    assert advice.latest_release_in_train == NOT_AVAILABLE
    assert advice.latest_release == NOT_AVAILABLE


def test_the_lookup_questions_ask_for_chassis_models_only_and_once_each() -> None:
    data = AnalysisInput(
        topology=topology.build(
            (
                _device(A, "S1", "sw-a", model=MODEL),
                _device(B, "S2", "sw-b", model=MODEL),
                _device(C, "S3", "sw-c", model=OTHER_MODEL),
            )
        ),
        inventory=(DeviceInventory(A, (HardwareItem(LINE_CARD, HardwareKind.LINE_CARD),)),),
    )

    questions = analysis.lookup_questions(data)

    assert questions.compatible_pids == (OTHER_MODEL, MODEL)
    assert LINE_CARD not in questions.compatible_pids
    assert "sw-a" not in questions.compatible_pids
