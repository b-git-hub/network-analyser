"""Links and Shared Segments from CDP and LLDP, with their evidence (#52; stories 124-129).

Synthetic records in, Topology out, with no device.
"""

from network_analyser import topology
from network_analyser.records.topology import (
    Evidence,
    EvidenceSource,
    FindingKind,
    Link,
    LinkStatus,
    Topology,
)
from network_analyser.records.unknown import Unknown
from tests.support.topology_records import CDP, LLDP, neighbour, visited

A = "192.0.2.1"
B = "192.0.2.2"
C = "192.0.2.3"


def _ports(link: Link) -> set[tuple[str, str]]:
    return {
        (end.device, end.interface.short if not isinstance(end.interface, Unknown) else "?")
        for end in link.ends
    }


def _only_link(built: Topology) -> Link:
    (link,) = built.links
    return link


def test_one_ends_cdp_report_makes_a_one_sided_link_with_its_evidence() -> None:
    a = visited(A, "S1", cdp=[neighbour("GigabitEthernet1/0/1", "sw-b", "Gi1/0/2", B)])
    b = visited(B, "S2", "sw-b")

    link = _only_link(topology.build([a, b]))

    assert link.id.startswith("link-")
    assert _ports(link) == {("dev-S1", "Gi1/0/1"), ("dev-S2", "Gi1/0/2")}
    assert link.status is LinkStatus.ONE_SIDED
    assert link.evidence == (Evidence("dev-S1", CDP, EvidenceSource.CDP),)
    assert link.conflicts == ()


def test_both_ends_reporting_each_other_make_a_confirmed_link() -> None:
    a = visited(A, "S1", cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/2", B)])
    b = visited(B, "S2", "sw-b", lldp=[neighbour("Gi1/0/2", "sw-a", "Gi1/0/1", A)])

    link = _only_link(topology.build([a, b]))

    assert link.status is LinkStatus.CONFIRMED
    assert set(link.evidence) == {
        Evidence("dev-S1", CDP, EvidenceSource.CDP),
        Evidence("dev-S2", LLDP, EvidenceSource.LLDP),
    }


def test_cdp_and_lldp_for_the_same_port_pair_are_one_link() -> None:
    a = visited(
        A,
        "S1",
        cdp=[neighbour("Gi1/0/1", "sw-b", "GigabitEthernet1/0/2", B)],
        lldp=[neighbour("Gi1/0/1", "sw-b.example", "Gi1/0/2", B)],
    )
    b = visited(B, "S2", "sw-b")

    link = _only_link(topology.build([a, b]))

    assert link.status is LinkStatus.ONE_SIDED
    assert {e.source for e in link.evidence} == {EvidenceSource.CDP, EvidenceSource.LLDP}


def test_a_far_end_that_did_not_advertise_its_port_still_confirms_from_its_own_report() -> None:
    a = visited(A, "S1", cdp=[neighbour("Gi1/0/1", "sw-b", None, B)])
    b = visited(B, "S2", "sw-b", cdp=[neighbour("Gi1/0/2", "sw-a", "Gi1/0/1", A)])

    link = _only_link(topology.build([a, b]))

    assert _ports(link) == {("dev-S1", "Gi1/0/1"), ("dev-S2", "Gi1/0/2")}
    assert link.status is LinkStatus.CONFIRMED


def test_ends_that_disagree_keep_both_claims_and_flag_the_conflict() -> None:
    a = visited(A, "S1", cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/2", B)])
    b = visited(B, "S2", "sw-b", cdp=[neighbour("Gi1/0/2", "sw-a", "Gi1/0/5", A)])

    built = topology.build([a, b])

    assert len(built.links) == 2
    assert {frozenset(_ports(link)) for link in built.links} == {
        frozenset({("dev-S1", "Gi1/0/1"), ("dev-S2", "Gi1/0/2")}),
        frozenset({("dev-S1", "Gi1/0/5"), ("dev-S2", "Gi1/0/2")}),
    }
    (finding,) = built.findings
    assert finding.kind is FindingKind.CONFLICTING_EVIDENCE
    assert finding.id.startswith("finding-")
    assert set(finding.items) == {link.id for link in built.links}
    assert set(finding.devices) == {"dev-S1", "dev-S2"}
    assert "Gi1/0/2" in finding.summary
    assert all(link.conflicts == (finding.id,) for link in built.links)
    assert all(link.status is LinkStatus.ONE_SIDED for link in built.links)


def test_cdp_and_lldp_disagreeing_on_one_port_is_a_conflict() -> None:
    a = visited(
        A,
        "S1",
        cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/2", B)],
        lldp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/3", B)],
    )
    b = visited(B, "S2", "sw-b")

    built = topology.build([a, b])

    assert len(built.links) == 2
    assert [f.kind for f in built.findings] == [FindingKind.CONFLICTING_EVIDENCE]


def test_a_link_to_an_unvisited_device_is_one_sided() -> None:
    a = visited(A, "S1", cdp=[neighbour("Gi1/0/1", "fw-a", "ethernet1/1", "192.0.2.9")])

    built = topology.build([a])

    link = _only_link(built)
    assert _ports(link) == {("dev-S1", "Gi1/0/1"), (built.unvisited[0].id, "Eth1/1")}
    assert link.status is LinkStatus.ONE_SIDED


def test_a_port_hearing_two_neighbours_connects_to_a_shared_segment() -> None:
    a = visited(
        A,
        "S1",
        cdp=[
            neighbour("Gi1/0/48", "ap-1", "Gi0", "192.0.2.21"),
            neighbour("Gi1/0/48", "ap-2", "Gi0", "192.0.2.22"),
        ],
    )

    built = topology.build([a])

    assert built.links == ()
    (segment,) = built.segments
    assert segment.id.startswith("seg-")
    attached = {
        (p.device, p.interface.short) for p in segment.ports if not isinstance(p.interface, Unknown)
    }
    unvisited = {d.id for d in built.unvisited}
    assert ("dev-S1", "Gi1/0/48") in attached
    assert {p.device for p in segment.ports} == {"dev-S1", *unvisited}
    assert len(unvisited) == 2
    assert segment.evidence == (Evidence("dev-S1", CDP, EvidenceSource.CDP),)


def test_overlapping_views_of_one_segment_merge_into_one() -> None:
    a = visited(
        A,
        "S1",
        cdp=[
            neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B),
            neighbour("Gi1/0/1", "sw-c", "Gi1/0/1", C),
        ],
    )
    b = visited(
        B,
        "S2",
        "sw-b",
        cdp=[
            neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A),
            neighbour("Gi1/0/1", "sw-c", "Gi1/0/1", C),
        ],
    )
    c = visited(C, "S3", "sw-c", cdp=[neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A)])

    built = topology.build([a, b, c])

    assert built.links == ()
    (segment,) = built.segments
    assert {(p.device, p.interface.short) for p in segment.ports} == {  # type: ignore[union-attr]  # all ports known here
        ("dev-S1", "Gi1/0/1"),
        ("dev-S2", "Gi1/0/1"),
        ("dev-S3", "Gi1/0/1"),
    }
    assert {e.device for e in segment.evidence} == {"dev-S1", "dev-S2", "dev-S3"}


def test_a_loop_cable_between_two_ports_of_one_device_is_a_link() -> None:
    a = visited(
        A,
        "S1",
        cdp=[
            neighbour("Gi1/0/1", "sw-a", "Gi1/0/2", A),
            neighbour("Gi1/0/2", "sw-a", "Gi1/0/1", A),
        ],
    )

    link = _only_link(topology.build([a]))

    assert _ports(link) == {("dev-S1", "Gi1/0/1"), ("dev-S1", "Gi1/0/2")}
    assert link.status is LinkStatus.CONFIRMED
