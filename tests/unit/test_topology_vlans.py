"""VLAN Mismatches on Links and Bundles (#61; stories 134-135).

Synthetic records in, Topology out, with no device. A mismatch needs both ends known.
Missing data is a skipped check, never a finding.
"""

import json
from dataclasses import replace

from network_analyser import topology
from network_analyser.records import Platform
from network_analyser.records.collected import (
    Interface,
    Neighbour,
    Reading,
    SwitchportMode,
    Vlan,
    VpcState,
)
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import (
    EvidenceSource,
    Finding,
    FindingKind,
    SkippedCheck,
    Topology,
)
from network_analyser.records.unknown import Unknown
from tests.support.topology_records import (
    INTERFACES,
    neighbour,
    port,
    visited,
    vpc,
)

A = "192.0.2.1"
B = "192.0.2.2"
N1 = "192.0.2.11"
N2 = "192.0.2.12"
SWITCHPORT = "show interfaces switchport"
VLAN_BRIEF = "show vlan brief"

_KINDS = {
    FindingKind.VLAN_ON_ONE_END,
    FindingKind.DIFFERING_NATIVE_VLAN,
    FindingKind.TRUNK_FACING_ACCESS,
    FindingKind.DIFFERING_ACCESS_VLANS,
}


def _db(*numbers: int, inactive: frozenset[int] = frozenset()) -> tuple[Vlan, ...]:
    return tuple(Vlan(number, f"vlan{number}", number not in inactive) for number in numbers)


def _trunk(
    name: str,
    allowed: frozenset[int] | Unknown | None,
    native: int | Unknown | None,
    bundle: str | None = None,
) -> Interface:
    return replace(
        port(name, bundle=bundle),
        native_vlan=native,
        allowed_vlans=allowed,
    )


def _access(name: str, vlan: int | Unknown | None) -> Interface:
    return replace(port(name, mode=SwitchportMode.ACCESS), access_vlan=vlan)


def _device(  # noqa: PLR0913, PLR0917 (a device's VLAN inputs, by name)
    address: str,
    serial: str,
    hostname: str,
    interfaces: list[Interface],
    vlans: tuple[Vlan, ...],
    heard: list[Neighbour],
    *,
    gaps: tuple[Unknown, ...] = (),
    platform: Platform = Platform.IOS_XE,
    vpc_state: VpcState | None = None,
) -> DeviceRecord:
    record = visited(
        address,
        serial,
        hostname,
        platform=platform,
        cdp=heard,
        interfaces=interfaces,
        vpc_state=vpc_state,
    )
    collected = record.collected
    assert collected is not None
    reading = collected.interfaces
    assert isinstance(reading, Reading)
    return replace(
        record,
        collected=replace(
            collected,
            interfaces=Reading((INTERFACES, SWITCHPORT), reading.value),
            vlans=Reading((VLAN_BRIEF,), vlans, gaps),
        ),
    )


def _vlan(built: Topology) -> list[Finding]:
    return [finding for finding in built.findings if finding.kind in _KINDS]


def _skips(built: Topology) -> list[SkippedCheck]:
    return [check for check in built.skipped if check.data == "vlan_mismatch"]


def _link(built: Topology, port_name: str) -> str:
    for link in built.links:
        shorts = {
            end.interface.short for end in link.ends if not isinstance(end.interface, Unknown)
        }
        if port_name in shorts:
            return link.id
    msg = "no link"
    raise AssertionError(msg)


def test_effective_vlans_are_allowed_and_present_and_both_kinds_are_reported() -> None:
    """Lab shape: native 1 against 99, and VLANs 30 and 99 on one end only."""
    present = _db(1, 10, 20, 30, 99)
    a = _device(
        A,
        "S1",
        "sw-a",
        [_trunk("Gi1/0/1", frozenset({10, 20, 30}), 1)],
        present,
        [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
    )
    b = _device(
        B,
        "S2",
        "sw-b",
        [_trunk("Gi1/0/1", frozenset({10, 20, 99}), 99)],
        present,
        [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
    )

    built = topology.build([a, b])
    again = topology.build([b, a])

    assert built == again
    kinds = {finding.kind for finding in _vlan(built)}
    assert kinds == {FindingKind.VLAN_ON_ONE_END, FindingKind.DIFFERING_NATIVE_VLAN}
    one_end = next(f for f in built.findings if f.kind is FindingKind.VLAN_ON_ONE_END)
    native = next(f for f in built.findings if f.kind is FindingKind.DIFFERING_NATIVE_VLAN)
    assert "30" in one_end.summary
    assert "99" in one_end.summary
    assert "10" not in one_end.summary
    assert "20" not in one_end.summary
    assert one_end.items == native.items == (built.links[0].id,)
    assert one_end.id.startswith("finding-")
    assert native.id.startswith("finding-")
    assert {e.source for e in one_end.evidence} == {EvidenceSource.VLAN}
    assert any(VLAN_BRIEF in e.command for e in one_end.evidence)
    assert any(SWITCHPORT in e.command for e in native.evidence)
    document = json.loads(json.dumps(topology.to_document(built)))
    assert document["format_version"] == 2
    assert {item["kind"] for item in document["findings"]} >= {
        "VLAN on one end only",
        "differing native VLAN",
    }


def test_a_vlan_allowed_but_absent_from_the_database_is_not_effective() -> None:
    a = _device(
        A,
        "S1",
        "sw-a",
        [_trunk("Gi1/0/1", frozenset({10, 30}), 1)],
        _db(1, 10),
        [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
    )
    b = _device(
        B,
        "S2",
        "sw-b",
        [_trunk("Gi1/0/1", frozenset({10}), 1)],
        _db(1, 10),
        [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
    )

    assert _vlan(topology.build([a, b])) == []


def test_an_inactive_vlan_still_counts_as_present() -> None:
    a = _device(
        A,
        "S1",
        "sw-a",
        [_trunk("Gi1/0/1", frozenset({10}), 1)],
        _db(1, 10, inactive=frozenset({10})),
        [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
    )
    b = _device(
        B,
        "S2",
        "sw-b",
        [_trunk("Gi1/0/1", frozenset({10}), 1)],
        _db(1, 10),
        [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
    )
    only_on_a = _device(
        B,
        "S2",
        "sw-b",
        [_trunk("Gi1/0/1", frozenset({10}), 1)],
        _db(1),
        [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
    )

    assert _vlan(topology.build([a, b])) == []
    (finding,) = _vlan(topology.build([a, only_on_a]))
    assert finding.kind is FindingKind.VLAN_ON_ONE_END
    assert "10" in finding.summary


def test_unknown_allowed_vlans_are_skipped_and_not_a_mismatch() -> None:
    a = _device(
        A,
        "S1",
        "sw-a",
        [_trunk("Gi1/0/1", Unknown("show interfaces switchport: denied"), 1)],
        _db(1, 10, 30),
        [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
    )
    b = _device(
        B,
        "S2",
        "sw-b",
        [_trunk("Gi1/0/1", frozenset({10}), 1)],
        _db(1, 10),
        [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
    )

    built = topology.build([a, b])

    assert _vlan(built) == []
    assert any(
        "denied" in check.reason and built.links[0].id in check.reason for check in _skips(built)
    )


def test_a_vlan_database_with_gaps_skips_effective_vlans_but_not_native() -> None:
    gap = (Unknown("show vlan brief: denied"),)
    a = _device(
        A,
        "S1",
        "sw-a",
        [_trunk("Gi1/0/1", frozenset({10, 30}), 1)],
        _db(1, 10, 30),
        [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
        gaps=gap,
    )
    b = _device(
        B,
        "S2",
        "sw-b",
        [_trunk("Gi1/0/1", frozenset({10}), 99)],
        _db(1, 10),
        [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
    )

    built = topology.build([a, b])

    assert {f.kind for f in _vlan(built)} == {FindingKind.DIFFERING_NATIVE_VLAN}
    assert any("VLAN database" in check.reason for check in _skips(built))


def test_trunk_facing_access_is_its_own_kind() -> None:
    a = _device(
        A,
        "S1",
        "sw-a",
        [_trunk("Gi1/0/1", frozenset({10, 20}), 1)],
        _db(1, 10, 20),
        [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
    )
    b = _device(
        B,
        "S2",
        "sw-b",
        [_access("Gi1/0/1", 10)],
        _db(1, 10),
        [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
    )

    (finding,) = _vlan(topology.build([a, b]))

    assert finding.kind is FindingKind.TRUNK_FACING_ACCESS
    assert finding.items == (topology.build([a, b]).links[0].id,)


def test_differing_access_vlans_and_not_when_they_agree() -> None:
    same = _device(
        B,
        "S2",
        "sw-b",
        [_access("Gi1/0/1", 10)],
        _db(10),
        [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
    )
    other = _device(
        B,
        "S2",
        "sw-b",
        [_access("Gi1/0/1", 20)],
        _db(10, 20),
        [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
    )
    unknown = _device(
        B,
        "S2",
        "sw-b",
        [_access("Gi1/0/1", Unknown("access VLAN not assigned"))],
        _db(10),
        [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
    )
    a = _device(
        A,
        "S1",
        "sw-a",
        [_access("Gi1/0/1", 10)],
        _db(10, 20),
        [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
    )

    assert _vlan(topology.build([a, same])) == []
    (finding,) = _vlan(topology.build([a, other]))
    assert finding.kind is FindingKind.DIFFERING_ACCESS_VLANS
    assert "10" in finding.summary
    assert "20" in finding.summary
    assert _vlan(topology.build([a, unknown])) == []
    assert _skips(topology.build([a, unknown]))


def test_routed_and_other_modes_are_not_vlan_mismatches() -> None:
    routed = port("Gi1/0/1", mode=SwitchportMode.ROUTED)
    other = port("Gi1/0/1", mode=SwitchportMode.OTHER)
    a = _device(A, "S1", "sw-a", [routed], (), [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)])
    b = _device(B, "S2", "sw-b", [routed], (), [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)])
    c = _device(B, "S2", "sw-b", [other], (), [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)])
    trunk = _device(
        A,
        "S1",
        "sw-a",
        [_trunk("Gi1/0/1", frozenset({10}), 1)],
        _db(1, 10),
        [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
    )

    assert _vlan(topology.build([a, b])) == []
    assert _skips(topology.build([a, b])) == []
    assert _vlan(topology.build([trunk, c])) == []
    assert _skips(topology.build([trunk, c])) == []


def test_cdp_native_vlan_counts_from_an_unvisited_device_and_only_native() -> None:
    mismatch = replace(neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B), native_vlan=99)
    quiet = replace(neighbour("Gi1/0/2", "sw-c", "Gi1/0/2", "192.0.2.3"), native_vlan=1)
    a = _device(
        A,
        "S1",
        "sw-a",
        [
            _trunk("Gi1/0/1", frozenset({10, 30}), 1),
            _trunk("Gi1/0/2", frozenset({10}), 1),
        ],
        _db(1, 10, 30),
        [mismatch, quiet],
    )

    built = topology.build([a])
    (finding,) = _vlan(built)

    assert finding.kind is FindingKind.DIFFERING_NATIVE_VLAN
    assert finding.items == (_link(built, "Gi1/0/1"),)
    assert {e.source for e in finding.evidence} == {EvidenceSource.CDP, EvidenceSource.VLAN}
    assert any(check.data == "vlan_mismatch" for check in built.skipped)


def test_a_matching_cdp_native_vlan_is_not_a_mismatch() -> None:
    heard = replace(neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B), native_vlan=1)
    a = _device(
        A,
        "S1",
        "sw-a",
        [_trunk("Gi1/0/1", frozenset({10}), 1)],
        _db(1, 10),
        [heard],
    )

    assert _vlan(topology.build([a])) == []


def test_unvisited_without_a_cdp_native_vlan_is_skipped() -> None:
    a = _device(
        A,
        "S1",
        "sw-a",
        [_trunk("Gi1/0/1", frozenset({10}), 1)],
        _db(1, 10),
        [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
    )

    built = topology.build([a])

    assert _vlan(built) == []
    assert any("native VLAN" in check.reason for check in _skips(built))


def test_a_bundle_is_checked_on_the_port_channel_not_on_each_member() -> None:
    db = _db(1, 10, 20, 30, 99)
    members_a = [
        _trunk("Gi1/0/1", frozenset({10, 30}), 1, "Po10"),
        _trunk("Gi1/0/2", frozenset({10, 30}), 1, "Po10"),
    ]
    members_b = [
        _trunk("Gi1/0/1", frozenset({10, 99}), 1, "Po20"),
        _trunk("Gi1/0/2", frozenset({10, 99}), 1, "Po20"),
    ]
    agreed = topology.build(
        [
            _device(
                A,
                "S1",
                "sw-a",
                [*members_a, _trunk("Po10", frozenset({10, 20}), 1)],
                db,
                [
                    neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B),
                    neighbour("Gi1/0/2", "sw-b", "Gi1/0/2", B),
                ],
            ),
            _device(
                B,
                "S2",
                "sw-b",
                [*members_b, _trunk("Po20", frozenset({10, 20}), 1)],
                db,
                [
                    neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A),
                    neighbour("Gi1/0/2", "sw-a", "Gi1/0/2", A),
                ],
            ),
        ]
    )
    disagreed = topology.build(
        [
            _device(
                A,
                "S1",
                "sw-a",
                [*members_a, _trunk("Po10", frozenset({10, 30}), 1)],
                db,
                [
                    neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B),
                    neighbour("Gi1/0/2", "sw-b", "Gi1/0/2", B),
                ],
            ),
            _device(
                B,
                "S2",
                "sw-b",
                [*members_b, _trunk("Po20", frozenset({10, 99}), 1)],
                db,
                [
                    neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A),
                    neighbour("Gi1/0/2", "sw-a", "Gi1/0/2", A),
                ],
            ),
        ]
    )

    assert _vlan(agreed) == []
    (finding,) = _vlan(disagreed)
    (bundle,) = disagreed.bundles
    assert finding.kind is FindingKind.VLAN_ON_ONE_END
    assert finding.items == (bundle.id,)
    assert "30" in finding.summary
    assert "99" in finding.summary
    assert not any(link.id in finding.items for link in disagreed.links)


def test_a_bundle_whose_port_channel_was_not_collected_is_skipped() -> None:
    db = _db(1, 10, 30, 99)
    built = topology.build(
        [
            _device(
                A,
                "S1",
                "sw-a",
                [_trunk("Gi1/0/1", frozenset({10, 30}), 1, "Po10")],
                db,
                [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
            ),
            _device(
                B,
                "S2",
                "sw-b",
                [_trunk("Gi1/0/1", frozenset({10, 99}), 1, "Po20")],
                db,
                [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
            ),
        ]
    )

    assert _vlan(built) == []
    assert _skips(built)
    assert any("port-channel" in check.reason for check in _skips(built))


def test_a_vpc_bundle_is_one_finding_not_one_per_member() -> None:
    db = _db(1, 10, 30)
    n1 = _device(
        N1,
        "N1",
        "nx-1",
        [
            _trunk("Ethernet1/1", frozenset({10, 30}), 1, "Po11"),
            port("mgmt0", ips=["198.51.100.11/24"], vrf="management", mode=SwitchportMode.ROUTED),
            _trunk("Po11", frozenset({10, 30}), 1),
        ],
        db,
        [neighbour("Ethernet1/1", "sw-a", "Gi1/0/1", A)],
        platform=Platform.NX_OS,
        vpc_state=vpc(7, "Po1", ("198.51.100.11", "198.51.100.12"), (11, "Po11")),
    )
    n2 = _device(
        N2,
        "N2",
        "nx-2",
        [
            _trunk("Ethernet1/1", frozenset({10, 30}), 1, "Po11"),
            port("mgmt0", ips=["198.51.100.12/24"], vrf="management", mode=SwitchportMode.ROUTED),
            _trunk("Po11", frozenset({10, 30}), 1),
        ],
        db,
        [neighbour("Ethernet1/1", "sw-a", "Gi1/0/2", A)],
        platform=Platform.NX_OS,
        vpc_state=vpc(7, "Po1", ("198.51.100.12", "198.51.100.11"), (11, "Po11")),
    )
    access = _device(
        A,
        "S1",
        "sw-a",
        [
            _trunk("Gi1/0/1", frozenset({10}), 1, "Po5"),
            _trunk("Gi1/0/2", frozenset({10}), 1, "Po5"),
            _trunk("Po5", frozenset({10}), 1),
        ],
        db,
        [
            neighbour("Gi1/0/1", "nx-1", "Ethernet1/1", N1),
            neighbour("Gi1/0/2", "nx-2", "Ethernet1/1", N2),
        ],
    )

    built = topology.build([n1, n2, access])
    facing = next(bundle for bundle in built.bundles if bundle.role is None)
    (finding,) = _vlan(built)

    assert finding.kind is FindingKind.VLAN_ON_ONE_END
    assert finding.items == (facing.id,)
    assert "30" in finding.summary
    assert set(finding.devices) >= {"dev-S1", "dev-N1", "dev-N2"}


def test_device_text_in_a_summary_is_escaped() -> None:
    a = _device(
        A,
        "S1",
        "sw-a\x1b",
        [_trunk("Gi1/0/1", frozenset({10}), 1)],
        _db(1, 10),
        [neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
    )
    b = _device(
        B,
        "S2",
        "sw-b",
        [_trunk("Gi1/0/1", frozenset({10}), 99)],
        _db(1, 10),
        [neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)],
    )

    (finding,) = _vlan(topology.build([a, b]))

    assert "\x1b" not in finding.summary
    assert "\\u001b" in finding.summary
