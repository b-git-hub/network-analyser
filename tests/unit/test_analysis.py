"""Analysis at the Run's end, at Seam 1: synthetic records in, plain results out (#94).

Driven through `analysis.analyse` and `analysis.lookup_questions` only. The first real Check
is the network-wide model-drift Check (story 70); the advice and Cisco-answer shapes are
already final, so later tickets fill them without changing this seam.
"""

from dataclasses import replace
from typing import Any

from network_analyser import analysis, topology
from network_analyser.records.analysis import (
    AdvisoryAnswer,
    AnalysisInput,
    CiscoAnswers,
    ConfigFact,
    ConfigFacts,
    DeviceInventory,
    HardwareItem,
    HardwareKind,
    OsType,
    SourceUnavailable,
)
from network_analyser.records.collected import Reading, StackMember
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.topology import (
    AdvisoryDetail,
    AnalysisResults,
    CheckType,
    CiscoDetailKind,
    Finding,
    FindingKind,
    FindingLevel,
)
from network_analyser.records.unknown import Unknown
from tests.support.topology_records import neighbour, port, unvisited, visited

A = "192.0.2.1"
B = "192.0.2.2"
C = "192.0.2.3"
D = "192.0.2.4"
MODEL = "C9300-48P"
HARDENING_CHECKS = (
    "hardening-aaa-central",
    "hardening-aaa-fallback",
    "hardening-brute-force",
    "hardening-enable-secret",
    "hardening-exec-timeout",
    "hardening-fhrp-authentication",
    "hardening-http-server",
    "hardening-icmp",
    "hardening-insecure-mode",
    "hardening-legacy-services",
    "hardening-ntp",
    "hardening-remote-syslog",
    "hardening-routing-authentication",
    "hardening-snmp-v1-v2c",
    "hardening-snmp-v3-priv",
    "hardening-ssh-v2",
    "hardening-strength-check",
    "hardening-telnet",
    "hardening-type-6",
    "hardening-vty-access-class",
    "hardening-weak-secret-types",
)


def _device(
    address: str,
    serial: str,
    hostname: str,
    *,
    model: str | Unknown = MODEL,
    release: str | Unknown = "17.9.4a",
) -> DeviceRecord:
    record = visited(address, serial, hostname)
    version = record.version
    assert version is not None
    return replace(record, version=replace(version, model=model, software_version=release))


def _results(
    *records: DeviceRecord, inventory: tuple[DeviceInventory, ...] = ()
) -> AnalysisResults:
    built = topology.build(records)
    return analysis.analyse(AnalysisInput(topology=built, inventory=inventory))


def _model_drift(results: AnalysisResults) -> list[Finding]:
    return [
        finding for finding in results.findings if finding.check.id == "consistency-model-drift"
    ]


def test_one_low_finding_per_model_running_more_than_one_release() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.9.4a"),
        _device(B, "S2", "sw-b", release="17.9.5"),
        _device(C, "S3", "sw-c", release="17.9.4a"),
        _device(D, "S4", "sw-d", model="C9500-48Y4C", release="17.12.1"),
    )

    (finding,) = _model_drift(results)

    assert finding.level is FindingLevel.LOW
    assert finding.check.name == "Same model on different releases"
    assert finding.check.type is CheckType.CONSISTENCY
    assert finding.check.soft is False
    assert finding.source == "tool policy, not a Cisco rule"
    assert finding.kind is None
    assert finding.devices == ("dev-S1", "dev-S2", "dev-S3")
    assert "sw-a" in finding.what_was_found
    assert "sw-b" in finding.what_was_found
    assert "17.9.4a" in finding.what_was_found
    assert "17.9.5" in finding.what_was_found
    assert "tool policy, not a Cisco rule" in finding.what_was_found
    assert finding.what_was_found == finding.summary
    assert finding.what_to_do == "Bring every device of this model onto one release."
    assert finding.evidence == ()
    assert finding.items == ()


def test_a_model_on_one_release_raises_nothing() -> None:
    results = _results(_device(A, "S1", "sw-a"), _device(B, "S2", "sw-b"))

    assert _model_drift(results) == []


def test_different_models_on_their_own_releases_raise_nothing() -> None:
    results = _results(
        _device(A, "S1", "sw-a", model="C9300-48P", release="17.9.4a"),
        _device(B, "S2", "sw-b", model="C9500-48Y4C", release="17.12.1"),
    )

    assert _model_drift(results) == []


def test_an_unknown_model_or_release_is_never_guessed() -> None:
    results = _results(
        _device(A, "S1", "sw-a", model=Unknown("show version not understood")),
        _device(B, "S2", "sw-b", release=Unknown("show version not read")),
        _device(C, "S3", "sw-c", release="17.9.5"),
    )

    assert _model_drift(results) == []


def test_the_model_drift_id_is_stable_and_does_not_depend_on_device_order() -> None:
    first = _results(
        _device(A, "S1", "sw-a", release="17.9.4a"),
        _device(B, "S2", "sw-b", release="17.9.5"),
    )
    again = _results(
        _device(B, "S2", "sw-b", release="17.9.5"),
        _device(A, "S1", "sw-a", release="17.9.4a"),
    )

    assert _model_drift(first)[0].id == _model_drift(again)[0].id
    assert _model_drift(first)[0].id.startswith("finding-")


def test_unvisited_devices_get_no_analysis() -> None:
    missed = unvisited("192.0.2.9", UnvisitedReason.UNREACHABLE)
    results = _results(
        _device(A, "S1", "sw-a", release="17.9.4a"),
        _device(B, "S2", "sw-b", release="17.9.5"),
        missed,
    )

    assert {advice.device for advice in results.advice} == {"dev-S1", "dev-S2"}
    assert _model_drift(results)[0].devices == ("dev-S1", "dev-S2")


def test_every_shipped_check_runs_and_one_advice_record_exists_per_visited_device() -> None:
    results = _results(
        _device(A, "S1", "sw-a", release="17.12.4"),
        _device(B, "S2", "sw-b", release="17.12.4"),
    )

    assert [run.check.id for run in results.checks] == [
        "advisory-could-not-check",
        "advisory-openvuln",
        "config-cisco-insecure-list",
        "config-copp-applied",
        "config-device-role-out-of-date",
        "config-guest-shell",
        "config-ntp-synchronised",
        "config-snmpv3-user-crypto",
        "config-ssh-key-size",
        "consistency-bundle-mode",
        "consistency-model-drift",
        "consistency-stack-mismatch",
        "consistency-standard-support-train",
        "consistency-vpc-mismatch",
        "hardening-aaa-central",
        "hardening-aaa-fallback",
        "hardening-brute-force",
        "hardening-enable-secret",
        "hardening-exec-timeout",
        "hardening-fhrp-authentication",
        "hardening-http-server",
        "hardening-icmp",
        "hardening-insecure-mode",
        "hardening-legacy-services",
        "hardening-ntp",
        "hardening-remote-syslog",
        "hardening-routing-authentication",
        "hardening-snmp-v1-v2c",
        "hardening-snmp-v3-priv",
        "hardening-ssh-v2",
        "hardening-strength-check",
        "hardening-telnet",
        "hardening-type-6",
        "hardening-vty-access-class",
        "hardening-weak-secret-types",
        "lifecycle-hardware-eox",
        "lifecycle-software-eox",
        "lifecycle-suggested-release",
    ]
    assert all(run.reason is None for run in results.checks if run.ran)
    assert {run.check.id for run in results.checks if not run.ran} == {
        "config-cisco-insecure-list",
        "config-copp-applied",
        "config-ntp-synchronised",
        "config-snmpv3-user-crypto",
        "config-ssh-key-size",
    }
    assert [advice.device for advice in results.advice] == ["dev-S1", "dev-S2"]


def test_a_source_unavailable_says_why_and_raises_no_per_device_findings() -> None:
    built = topology.build((_device(A, "S1", "sw-a"),))
    reason = "Cisco openVuln could not be reached"
    results = analysis.analyse(
        AnalysisInput(topology=built, answers=CiscoAnswers.unavailable(reason))
    )

    (advice,) = results.advice
    assert advice.advisory_outcome.text == f"could not check: {reason}"
    assert advice.upgrade_target == "not available"
    assert advice.latest_release_in_train == "not available"
    assert advice.latest_release == "not available"
    assert advice.upcoming_eox == ()
    # A Cisco outage raises no Advisory or Consistency Finding; the hardening Checks still
    # run, and with no config facts each says it could not decide rather than passing.
    assert all(finding.check.type is CheckType.CONFIGURATION for finding in results.findings)
    assert all("Could not decide" in finding.what_was_found for finding in results.findings)


def test_cisco_answers_are_either_an_answer_or_unavailable() -> None:
    answer = CiscoAnswers(eox=SourceUnavailable("EoX could not be reached"))

    assert answer.advisories == ()
    assert isinstance(answer.eox, SourceUnavailable)
    assert answer.suggestions == ()
    assert answer.compatible == ()
    assert isinstance(CiscoAnswers().advisories, tuple)


def test_results_carry_v1_topology_findings_beside_analysis_findings() -> None:
    a = visited(
        A,
        "S1",
        "sw-a",
        cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
        interfaces=[port("Gi1/0/1", bundle="Po10")],
    )
    b = visited(
        B,
        "S2",
        "sw-b",
        cdp=[neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
        interfaces=[port("Gi1/0/1")],
    )
    built = topology.build([a, b, _device(C, "S3", "sw-c", model="C9500-48Y4C")])
    results = analysis.analyse(AnalysisInput(topology=built))

    assert any(finding.kind is FindingKind.BUNDLE_MEMBER_MISMATCH for finding in results.findings)
    assert _model_drift(results) == []  # S1/S2 are one model on one release; S3 is another


def test_the_lookup_questions_are_deduplicated_and_pattern_valid() -> None:
    base = _device(A, "S1", "sw-a", release="17.9.5")
    collected = base.collected
    assert collected is not None
    with_stack = replace(
        base,
        collected=replace(
            collected,
            stack_members=Reading(
                ("show version",),
                (StackMember(1, "S1", MODEL), StackMember(2, "S1-B", MODEL)),
            ),
        ),
    )
    results_input = AnalysisInput(
        topology=topology.build(
            (
                with_stack,
                _device(B, "S2", "sw-b", model="<script>", release="17.9.5"),
                unvisited("192.0.2.9", UnvisitedReason.UNREACHABLE),
            )
        ),
        inventory=(DeviceInventory(A, (HardwareItem("C9300-NM-8X", HardwareKind.LINE_CARD),)),),
    )

    questions = analysis.lookup_questions(results_input)

    assert questions.pids == (MODEL, "C9300-NM-8X")
    assert questions.compatible_pids == (MODEL,)
    assert [(q.os_type, q.release) for q in questions.releases] == [
        (OsType.IOS_XE, "17.9.5"),
    ]
    assert "sw-a" not in questions.pids
    assert "S1" not in questions.pids


def test_a_release_the_family_table_does_not_hold_is_not_sent() -> None:
    results_input = AnalysisInput(
        topology=topology.build((_device(A, "S1", "sw-a", release="17.9.4a;drop tables"),))
    )

    assert analysis.lookup_questions(results_input).releases == ()


def test_a_missing_config_fact_reads_as_unknown_never_absent() -> None:
    facts = ConfigFacts("dev-S1", (ConfigFact(name="telnet", value=False),))

    assert facts.fact("telnet") is False
    missing = facts.fact("snmp_v3")
    assert isinstance(missing, Unknown)
    assert missing.reason == "config fact not collected: snmp_v3"


def test_the_results_fit_topology_json_as_optional_fields() -> None:
    built = topology.build(
        (
            _device(A, "S1", "sw-a", release="17.9.4a"),
            _device(B, "S2", "sw-b", release="17.9.5"),
        )
    )
    results = analysis.analyse(AnalysisInput(topology=built))
    document: Any = topology.to_document(
        replace(built, findings=results.findings, analysis=results.summary)
    )

    assert document["format_version"] == topology.FORMAT_VERSION
    findings = document["findings"]
    assert isinstance(findings, list)
    assert any(item["check"]["id"] == "consistency-model-drift" for item in findings)
    analysis_record = document["analysis"]
    assert isinstance(analysis_record, dict)
    advice = analysis_record["advice"]
    assert isinstance(advice, list)
    assert [item["device"] for item in advice] == ["dev-S1", "dev-S2"]
    assert advice[0]["advisory_outcome"]["kind"] == "could not check"
    assert advice[0]["upgrade_target"] == "not available"
    checks = analysis_record["checks"]
    assert isinstance(checks, list)
    assert [item["check"]["id"] for item in checks] == [
        "advisory-could-not-check",
        "advisory-openvuln",
        "config-cisco-insecure-list",
        "config-copp-applied",
        "config-device-role-out-of-date",
        "config-guest-shell",
        "config-ntp-synchronised",
        "config-snmpv3-user-crypto",
        "config-ssh-key-size",
        "consistency-bundle-mode",
        "consistency-model-drift",
        "consistency-stack-mismatch",
        "consistency-standard-support-train",
        "consistency-vpc-mismatch",
        "hardening-aaa-central",
        "hardening-aaa-fallback",
        "hardening-brute-force",
        "hardening-enable-secret",
        "hardening-exec-timeout",
        "hardening-fhrp-authentication",
        "hardening-http-server",
        "hardening-icmp",
        "hardening-insecure-mode",
        "hardening-legacy-services",
        "hardening-ntp",
        "hardening-remote-syslog",
        "hardening-routing-authentication",
        "hardening-snmp-v1-v2c",
        "hardening-snmp-v3-priv",
        "hardening-ssh-v2",
        "hardening-strength-check",
        "hardening-telnet",
        "hardening-type-6",
        "hardening-vty-access-class",
        "hardening-weak-secret-types",
        "lifecycle-hardware-eox",
        "lifecycle-software-eox",
        "lifecycle-suggested-release",
    ]
    drift = next(item for item in checks if item["check"]["id"] == "consistency-model-drift")
    assert drift["ran"] is True
    train = next(
        item for item in checks if item["check"]["id"] == "consistency-standard-support-train"
    )
    assert train["ran"] is False
    assert "17.9" in train["reason"]


def test_the_advice_shape_accepts_an_advisory_answer() -> None:
    answer = AdvisoryAnswer(detail=_advisory_detail())

    assert answer.detail.id == "cisco-sa-example-abc123"
    assert answer.first_fixed == ()


def _advisory_detail() -> AdvisoryDetail:
    return AdvisoryDetail(
        kind=CiscoDetailKind.ADVISORY,
        id="cisco-sa-example-abc123",
        title="Example Advisory",
        sir=FindingLevel.HIGH,
        cvss="8.1",
        cves=("CVE-2026-0001",),
        published="2026-11-01",
        updated="2026-11-02",
        first_fixed="17.9.5",
    )
