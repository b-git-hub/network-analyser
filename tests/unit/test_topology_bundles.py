"""Bundles, vPC and stacks (#52; stories 131-133). Synthetic records in, Topology out."""

from network_analyser import topology
from network_analyser.records import Platform
from network_analyser.records.device import DeviceRecord
from network_analyser.records.topology import (
    Bundle,
    BundleEnd,
    FindingKind,
    LinkRole,
    Topology,
)
from network_analyser.records.unknown import Unknown
from tests.support.topology_records import (
    neighbour,
    port,
    port_channel,
    visited,
    vpc,
)

A = "192.0.2.1"
B = "192.0.2.2"
N1 = "192.0.2.11"
N2 = "192.0.2.12"


def _ends(bundle: Bundle) -> set[tuple[str, str | None]]:
    return {
        (end.device, end.port_channel if not isinstance(end.port_channel, Unknown) else "?")
        for side in bundle.sides
        for end in side.ends
    }


def _only_bundle(built: Topology) -> Bundle:
    (bundle,) = built.bundles
    return bundle


def _pair(a_bundle: str | None, b_bundle: str | None) -> Topology:
    """Two switches joined by Gi1/0/1-2 on both sides, each side in the given port-channel."""
    a = visited(
        A,
        "S1",
        cdp=[
            neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B),
            neighbour("Gi1/0/2", "sw-b", "Gi1/0/2", B),
        ],
        interfaces=[port("Gi1/0/1", bundle=a_bundle), port("Gi1/0/2", bundle=a_bundle)],
    )
    b = visited(
        B,
        "S2",
        "sw-b",
        cdp=[
            neighbour("Gi1/0/1", "sw-a", "Gi1/0/1", A),
            neighbour("Gi1/0/2", "sw-a", "Gi1/0/2", A),
        ],
        interfaces=[port("Gi1/0/1", bundle=b_bundle), port("Gi1/0/2", bundle=b_bundle)],
    )
    return topology.build([a, b])


def test_links_in_a_port_channel_at_each_end_are_one_bundle_named_at_each_end() -> None:
    built = _pair("Po10", "Po20")

    bundle = _only_bundle(built)
    assert bundle.id.startswith("bundle-")
    assert _ends(bundle) == {("dev-S1", "Po10"), ("dev-S2", "Po20")}
    assert set(bundle.links) == {link.id for link in built.links}
    assert len(bundle.links) == 2
    assert bundle.flagged == ()
    assert all(link.bundle == bundle.id for link in built.links)
    assert built.findings == ()


def test_members_whose_far_end_is_in_no_bundle_are_flagged() -> None:
    built = _pair("Po10", None)

    bundle = _only_bundle(built)
    assert _ends(bundle) == {("dev-S1", "Po10"), ("dev-S2", None)}
    assert set(bundle.flagged) == set(bundle.links)
    (finding,) = built.findings
    assert finding.kind is FindingKind.BUNDLE_MEMBER_MISMATCH
    assert set(finding.items) == {bundle.id, *bundle.links}
    assert "Po10" in finding.summary


def test_a_member_whose_far_end_is_in_another_bundle_is_flagged() -> None:
    a = visited(
        A,
        "S1",
        cdp=[
            neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B),
            neighbour("Gi1/0/2", "sw-b", "Gi1/0/2", B),
        ],
        interfaces=[port("Gi1/0/1", bundle="Po10"), port("Gi1/0/2", bundle="Po10")],
    )
    b = visited(
        B,
        "S2",
        "sw-b",
        interfaces=[port("Gi1/0/1", bundle="Po20"), port("Gi1/0/2", bundle="Po21")],
    )

    built = topology.build([a, b])

    assert len(built.bundles) == 2
    assert all(len(b.flagged) == 1 for b in built.bundles)
    assert len(built.findings) == 1


def test_membership_from_the_port_channel_summary_counts_too() -> None:
    a = visited(
        A,
        "S1",
        cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
        port_channels=[port_channel("Port-channel10", "GigabitEthernet1/0/1")],
    )
    b = visited(B, "S2", "sw-b", port_channels=[port_channel("Po20", "Gi1/0/1")])

    assert _ends(_only_bundle(topology.build([a, b]))) == {("dev-S1", "Po10"), ("dev-S2", "Po20")}


def test_a_bundle_to_a_device_whose_membership_is_unknown_is_not_flagged() -> None:
    a = visited(
        A,
        "S1",
        cdp=[neighbour("Gi1/0/1", "srv-a", "eth0", "192.0.2.50")],
        interfaces=[port("Gi1/0/1", bundle="Po30")],
    )

    built = topology.build([a])

    bundle = _only_bundle(built)
    assert bundle.flagged == ()
    far = next(end for side in bundle.sides for end in side.ends if end.device != "dev-S1")
    assert isinstance(far.port_channel, Unknown)


def _vpc_pair() -> list[DeviceRecord]:
    """Two Nexus vPC peers (Po1 peer-link, keepalive on mgmt0) and a switch dual-homed to them."""
    n1 = visited(
        N1,
        "N1",
        "nx-1",
        platform=Platform.NX_OS,
        cdp=[
            neighbour("Ethernet1/49", "nx-2", "Ethernet1/49", N2),
            neighbour("Ethernet1/50", "nx-2", "Ethernet1/50", N2),
            neighbour("mgmt0", "nx-2", "mgmt0", N2),
            neighbour("Ethernet1/1", "sw-a", "Gi1/0/1", A),
        ],
        interfaces=[
            port("Ethernet1/49", bundle="Po1"),
            port("Ethernet1/50", bundle="Po1"),
            port("Ethernet1/1", bundle="Po11"),
            port("mgmt0", ips=["198.51.100.11/24"], vrf="management"),
        ],
        vpc_state=vpc(7, "port-channel1", ("198.51.100.11", "198.51.100.12"), (11, "Po11")),
    )
    n2 = visited(
        N2,
        "N2",
        "nx-2",
        platform=Platform.NX_OS,
        cdp=[
            neighbour("Ethernet1/49", "nx-1", "Ethernet1/49", N1),
            neighbour("Ethernet1/50", "nx-1", "Ethernet1/50", N1),
            neighbour("mgmt0", "nx-1", "mgmt0", N1),
            neighbour("Ethernet1/1", "sw-a", "Gi1/0/2", A),
        ],
        interfaces=[
            port("Ethernet1/49", bundle="Po1"),
            port("Ethernet1/50", bundle="Po1"),
            port("Ethernet1/1", bundle="Po11"),
            port("mgmt0", ips=["198.51.100.12/24"], vrf="management"),
        ],
        vpc_state=vpc(7, "Po1", ("198.51.100.12", "198.51.100.11"), (11, "port-channel11")),
    )
    access = visited(
        A,
        "S1",
        cdp=[
            neighbour("Gi1/0/1", "nx-1", "Ethernet1/1", N1),
            neighbour("Gi1/0/2", "nx-2", "Ethernet1/1", N2),
        ],
        interfaces=[port("Gi1/0/1", bundle="Po5"), port("Gi1/0/2", bundle="Po5")],
    )
    return [n1, n2, access]


def test_a_port_channel_facing_a_vpc_pair_is_one_bundle_with_far_ends_on_both_peers() -> None:
    built = topology.build(_vpc_pair())

    facing = next(b for b in built.bundles if b.role is None)
    assert _ends(facing) == {("dev-S1", "Po5"), ("dev-N1", "Po11"), ("dev-N2", "Po11")}
    vpc_side = next(side for side in facing.sides if len(side.ends) == 2)
    assert vpc_side.vpc == 11
    assert len(facing.links) == 2
    assert facing.flagged == ()


def test_the_vpc_peer_link_and_keepalive_are_labelled() -> None:
    built = topology.build(_vpc_pair())

    peer_link = next(b for b in built.bundles if b.role is LinkRole.VPC_PEER_LINK)
    assert _ends(peer_link) == {("dev-N1", "Po1"), ("dev-N2", "Po1")}
    roles = {link.id: link.role for link in built.links}
    assert all(roles[link] is LinkRole.VPC_PEER_LINK for link in peer_link.links)
    (keepalive,) = [link for link in built.links if link.role is LinkRole.VPC_PEER_KEEPALIVE]
    assert {e.interface.short for e in keepalive.ends} == {"mgmt0"}  # type: ignore[union-attr]  # known ports
    assert built.findings == ()


def test_a_bundle_end_on_a_vpc_peer_is_kept_with_its_device() -> None:
    built = topology.build(_vpc_pair())

    ends = {e for b in built.bundles for side in b.sides for e in side.ends}
    assert BundleEnd("dev-N1", "Po11") in ends
    assert BundleEnd("dev-N2", "Po11") in ends
