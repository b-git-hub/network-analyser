"""L3 Adjacency, Subnets and MAC/ARP inference (#62; stories 130, 136, 137, 139).

Synthetic records in, Topology out, with no device. ARP and MAC are evidence only: they
never become a device or a Link on their own, and nothing here is a scan target.
"""

import json
import re
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network

from network_analyser import scope, topology
from network_analyser.records import ScopeRecord
from network_analyser.records.collected import (
    ArpEntry,
    FhrpGroup,
    FhrpProtocol,
    MacEntry,
    Neighbour,
    RoutingNeighbour,
    RoutingProtocol,
    StaticRoute,
    SwitchportMode,
)
from network_analyser.records.device import DeviceRecord, UnvisitedReason
from network_analyser.records.interface_names import interface_name
from network_analyser.records.topology import (
    AdjacencyKind,
    EvidenceSource,
    FindingKind,
    LinkStatus,
    Subnet,
)
from network_analyser.records.unknown import Unknown
from tests.support.topology_records import (
    ARP,
    INTERFACES,
    MAC,
    ROUTING,
    STATIC,
    neighbour,
    port,
    unvisited,
    visited,
)

A = "192.0.2.1"
B = "192.0.2.2"
C = "192.0.2.3"
D = "192.0.2.4"
GW = "198.51.100.9"
MAC_A = "00005e005300"
MAC_B = "00005e005301"
_ID = re.compile(r"^[a-z]+-[0-9a-f]{12}$")


def _scope(*entries: str) -> ScopeRecord:
    fence = scope.parse(list(entries), [])
    assert isinstance(fence, ScopeRecord)
    return fence


LAN = _scope("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")


def _device(  # noqa: PLR0913 (one device's collected parts, each named)
    address: str,
    serial: str,
    hostname: str,
    *ips: str,
    vrf: str = "default",
    unnumbered: bool = False,
    admin_up: bool | Unknown = True,
    line_up: bool | Unknown = True,
    routing: Iterable[RoutingNeighbour] | None = None,
    static: Iterable[StaticRoute] | None = None,
    arp: Iterable[ArpEntry] | None = None,
    mac: Iterable[MacEntry] | None = None,
    fhrp: Iterable[FhrpGroup] | None = None,
    cdp: Iterable[Neighbour] | None = None,
) -> DeviceRecord:
    """A Visited router or switch, with only the collected parts this test names."""
    return visited(
        address,
        serial,
        hostname,
        interfaces=[
            port(
                "Gi0/0",
                mode=SwitchportMode.ROUTED,
                ips=ips,
                vrf=vrf,
                unnumbered=unnumbered,
                admin_up=admin_up,
                line_up=line_up,
            )
        ],
        routing=routing,
        static=static,
        arp=arp,
        mac=mac,
        fhrp=fhrp,
        cdp=() if cdp is None else cdp,
    )


def _ospf(
    ip: str, state: str = "FULL/DR", vrf: str = "default", interface: str = "Gi0/0"
) -> RoutingNeighbour:
    return RoutingNeighbour(
        RoutingProtocol.OSPF, vrf, IPv4Address(ip), interface_name(interface), state
    )


def _bgp(ip: str, state: str = "Established", vrf: str = "default") -> RoutingNeighbour:
    return RoutingNeighbour(RoutingProtocol.BGP, vrf, IPv4Address(ip), None, state)


def _eigrp(ip: str, state: str | Unknown = "up", vrf: str = "default") -> RoutingNeighbour:
    return RoutingNeighbour(
        RoutingProtocol.EIGRP, vrf, IPv4Address(ip), interface_name("Gi0/0"), state
    )


def _static(hop: str, prefix: str = "0.0.0.0/0", vrf: str = "default") -> StaticRoute:
    return StaticRoute(vrf, IPv4Network(prefix), IPv4Address(hop), interface_name("Vlan10"))


def _arp(ip: str, mac: str, vrf: str = "default", interface: str = "Vlan10") -> ArpEntry:
    return ArpEntry(vrf, IPv4Address(ip), mac, interface_name(interface))


def _learned(mac: str, where: str, *, dynamic: bool = True) -> MacEntry:
    return MacEntry(10, mac, interface_name(where), dynamic)


def test_two_devices_on_one_prefix_and_vrf_are_one_shared_subnet_adjacency() -> None:
    built = topology.build(
        [
            _device(B, "S2", "rtr-b", "192.0.2.2/24"),
            _device(A, "S1", "rtr-a", "192.0.2.1/24", "198.51.100.1/24"),
        ]
    )
    (adjacency,) = built.adjacencies

    assert built.subnets == ()
    assert adjacency.kind is AdjacencyKind.SHARED_SUBNET
    assert adjacency.vrf == "default"
    assert adjacency.prefix == IPv4Network("192.0.2.0/24")
    assert _ID.fullmatch(adjacency.id)
    assert {end.device for end in adjacency.ends} == {"dev-S1", "dev-S2"}
    assert {e.device for e in adjacency.evidence} == {"dev-S1", "dev-S2"}
    assert {e.source for e in adjacency.evidence} == {EvidenceSource.INTERFACE}
    assert {e.command for e in adjacency.evidence} == {INTERFACES}
    assert adjacency.conflicts == ()
    again = topology.build(
        [
            _device(A, "S1", "rtr-a", "192.0.2.1/24", "198.51.100.1/24"),
            _device(B, "S2", "rtr-b", "192.0.2.2/24"),
        ]
    )
    assert again.adjacencies == built.adjacencies


def test_a_secondary_address_counts_and_a_different_mask_does_not() -> None:
    built = topology.build(
        [
            _device(A, "S1", "rtr-a", "203.0.113.1/24", "198.51.100.1/24"),
            _device(B, "S2", "rtr-b", "198.51.100.2/24"),
            _device(C, "S3", "rtr-c", "198.51.100.3/25"),
        ]
    )

    (adjacency,) = built.adjacencies
    assert adjacency.prefix == IPv4Network("198.51.100.0/24")
    assert {end.device for end in adjacency.ends} == {"dev-S1", "dev-S2"}
    assert built.subnets == ()


def test_host_routes_virtual_ips_unnumbered_and_management_vrfs_make_no_adjacency() -> None:
    vip = FhrpGroup(FhrpProtocol.HSRP, interface_name("Gi0/0"), 1, IPv4Address("192.0.2.1"))
    built = topology.build(
        [
            _device(A, "S1", "rtr-a", "192.0.2.1/32"),
            _device(B, "S2", "rtr-b", "192.0.2.1/32"),
            _device(C, "S3", "rtr-c", "192.0.2.1/24", fhrp=(vip,)),
            _device(D, "S4", "rtr-d", "192.0.2.1/24", fhrp=(vip,)),
            visited(
                "203.0.113.1",
                "S5",
                "rtr-e",
                interfaces=[
                    port(
                        "Gi0/0",
                        mode=SwitchportMode.ROUTED,
                        ips=("203.0.113.1/24",),
                        unnumbered=True,
                    )
                ],
            ),
            visited(
                "203.0.113.2",
                "S6",
                "rtr-f",
                interfaces=[port("Gi0/0", mode=SwitchportMode.ROUTED, ips=("203.0.113.2/24",))],
            ),
            visited(
                "203.0.113.3",
                "S7",
                "rtr-g",
                interfaces=[
                    port(
                        "Gi0/0",
                        mode=SwitchportMode.ROUTED,
                        ips=("192.0.2.10/24",),
                        vrf="management",
                    )
                ],
            ),
            visited(
                "203.0.113.4",
                "S8",
                "rtr-h",
                interfaces=[
                    port(
                        "Gi0/0", mode=SwitchportMode.ROUTED, ips=("192.0.2.11/24",), vrf="Mgmt-intf"
                    )
                ],
            ),
            visited(
                "203.0.113.5",
                "S9",
                "rtr-i",
                interfaces=[
                    port(
                        "Gi0/0",
                        mode=SwitchportMode.ROUTED,
                        ips=("192.0.2.12/24",),
                        vrf="management",
                    )
                ],
            ),
        ]
    )

    assert built.adjacencies == ()
    assert built.subnets == ()


def test_a_down_or_unknown_interface_and_an_unknown_table_create_nothing() -> None:
    down = _device(A, "S1", "rtr-a", "192.0.2.1/24", line_up=False)
    unknown_line = _device(
        B, "S2", "rtr-b", "192.0.2.2/24", line_up=Unknown("show interfaces: denied")
    )
    no_table = visited("192.0.2.3", "S3", "rtr-c")

    assert topology.build([down, _device(C, "S4", "rtr-d", "192.0.2.4/24")]).adjacencies == ()
    assert (
        topology.build([unknown_line, _device(D, "S5", "rtr-e", "192.0.2.5/24")]).adjacencies == ()
    )
    assert topology.build([no_table, _device(A, "S1", "rtr-a", "192.0.2.1/24")]).adjacencies == ()


def test_three_or_more_devices_on_a_prefix_are_one_subnet_not_pairs() -> None:
    built = topology.build(
        [
            _device(C, "S3", "rtr-c", "192.0.2.3/24"),
            _device(A, "S1", "rtr-a", "192.0.2.1/24"),
            _device(B, "S2", "rtr-b", "192.0.2.2/24"),
        ]
    )
    (subnet,) = built.subnets

    assert built.adjacencies == ()
    assert isinstance(subnet, Subnet)
    assert subnet.prefix == IPv4Network("192.0.2.0/24")
    assert subnet.vrf == "default"
    assert _ID.fullmatch(subnet.id)
    assert [item.device for item in subnet.attachments] == ["dev-S1", "dev-S2", "dev-S3"]
    assert {item.address.ip for item in subnet.attachments} == {
        IPv4Address(A),
        IPv4Address(B),
        IPv4Address(C),
    }
    assert {e.source for e in subnet.evidence} == {EvidenceSource.INTERFACE}
    assert subnet.conflicts == ()


def test_a_real_subnet_stays_when_its_virtual_ip_is_known() -> None:
    vip = FhrpGroup(FhrpProtocol.HSRP, interface_name("Gi0/0"), 1, IPv4Address("192.0.2.1"))
    built = topology.build(
        [
            _device(A, "S1", "rtr-a", "192.0.2.2/24", fhrp=(vip,)),
            _device(B, "S2", "rtr-b", "192.0.2.3/24", fhrp=(vip,)),
        ]
    )

    (adjacency,) = built.adjacencies
    assert adjacency.prefix == IPv4Network("192.0.2.0/24")
    assert built.unvisited == ()


def test_ospf_eigrp_and_bgp_neighbours_are_labelled_adjacencies() -> None:
    ospf = topology.build(
        [
            _device(A, "S1", "rtr-a", "192.0.2.1/24", routing=(_ospf(B),)),
            _device(B, "S2", "rtr-b", "192.0.2.2/24", routing=(_ospf(A, "FULL/BDR"),)),
        ]
    )
    eigrp = topology.build(
        [
            _device(
                A,
                "S1",
                "rtr-a",
                routing=(_eigrp(B, Unknown("EIGRP shows no neighbour state")),),
            ),
            _device(B, "S2", "rtr-b"),
        ],
        scope=LAN,
    )
    bgp = topology.build(
        [_device(A, "S1", "rtr-a", routing=(_bgp("203.0.113.9"),))],
        scope=LAN,
    )

    ospf_adjacency = next(item for item in ospf.adjacencies if item.kind is AdjacencyKind.OSPF)
    assert ospf_adjacency.prefix is None
    assert ospf_adjacency.vrf == "default"
    assert {end.device for end in ospf_adjacency.ends} == {"dev-S1", "dev-S2"}
    assert {e.device for e in ospf_adjacency.evidence} == {"dev-S1", "dev-S2"}
    assert {e.source for e in ospf_adjacency.evidence} == {EvidenceSource.ROUTING}
    assert {e.command for e in ospf_adjacency.evidence} == {ROUTING}
    assert ospf.subnets == ()
    assert any(item.kind is AdjacencyKind.SHARED_SUBNET for item in ospf.adjacencies)
    eigrp_adjacency = next(item for item in eigrp.adjacencies if item.kind is AdjacencyKind.EIGRP)
    assert eigrp.unvisited == ()
    assert {end.device for end in eigrp_adjacency.ends} == {"dev-S1", "dev-S2"}
    (bgp_adjacency,) = bgp.adjacencies
    assert bgp_adjacency.kind is AdjacencyKind.BGP
    assert bgp.unvisited[0].reason is UnvisitedReason.ROUTING_OR_ARP_ONLY


def test_a_session_that_is_not_up_is_not_an_adjacency() -> None:
    records = [
        _device(
            A,
            "S1",
            "rtr-a",
            routing=(_ospf(B, "2WAY/DROTHER"), _bgp(C, "Idle"), _eigrp(D, "down")),
        ),
        _device(B, "S2", "rtr-b", "192.0.2.2/32"),
    ]

    assert topology.build(records, scope=LAN).adjacencies == ()


def test_a_next_hop_with_no_arp_is_listed_as_having_no_link() -> None:
    built = topology.build(
        [_device(A, "S1", "rtr-a", routing=(_ospf(GW),))],
        scope=LAN,
    )

    (hop,) = built.unplaced_next_hops
    assert hop.ip == IPv4Address(GW)
    assert hop.reporter == "dev-S1"
    assert hop.reason == "ARP was not collected"
    assert built.links == ()


def test_an_in_scope_next_hop_cdp_never_advertised_is_unvisited_and_not_a_target() -> None:
    built = topology.build(
        [_device(A, "S1", "rtr-a", routing=(_ospf(GW),), static=(_static(GW),))],
        scope=LAN,
    )
    (device,) = built.unvisited

    assert device.reason is UnvisitedReason.ROUTING_OR_ARP_ONLY
    assert device.advertised_ips == (IPv4Address(GW),)
    assert _ID.fullmatch(device.id)
    assert {report.evidence.source for report in device.reported_by} == {EvidenceSource.ROUTING}
    assert {report.evidence.command for report in device.reported_by} == {ROUTING, STATIC}
    assert device.reported_by[0].device == "dev-S1"


def test_a_next_hop_outside_scope_or_with_no_scope_is_not_invented() -> None:
    records = [_device(A, "S1", "rtr-a", routing=(_ospf(GW),))]

    assert topology.build(records, scope=_scope("192.0.2.0/24")).unvisited == ()
    assert topology.build(records).unvisited == ()
    assert topology.build(records).adjacencies == ()


def test_a_neighbour_already_known_keeps_its_device_and_its_reason() -> None:
    routed = _device(A, "S1", "rtr-a", "192.0.2.1/24", routing=(_ospf(B),))
    other = _device(B, "S2", "rtr-b", "192.0.2.2/24")
    heard = visited(
        A,
        "S1",
        "rtr-a",
        cdp=[neighbour("Gi0/1", "fw", "Gi0/1", GW)],
        routing=(_ospf(GW),),
    )
    skipped = unvisited(GW, UnvisitedReason.UNREACHABLE)
    built = topology.build([heard, skipped], scope=LAN)

    (device,) = built.unvisited
    assert device.reason is UnvisitedReason.UNREACHABLE
    assert device.advertised_ips == (IPv4Address(GW),)
    paired = topology.build([routed, other])
    assert paired.unvisited == ()
    assert any(item.kind is AdjacencyKind.OSPF for item in paired.adjacencies)


def test_arp_and_mac_place_one_inferred_link_on_the_single_edge_port() -> None:
    built = topology.build(
        [
            visited(
                A,
                "S1",
                "sw-a",
                interfaces=[port("Gi1/0/24", mode=SwitchportMode.ACCESS)],
                static=(_static(GW),),
                arp=(_arp(GW, MAC_A),),
                mac=(_learned(MAC_A, "Gi1/0/24"),),
                cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
            ),
            _device(B, "S2", "sw-b", "192.0.2.2/32"),
        ],
        scope=LAN,
    )
    inferred = [link for link in built.links if link.status is LinkStatus.INFERRED]

    (link,) = inferred
    assert _ID.fullmatch(link.id)
    ends = {
        (end.device, end.interface.short if not isinstance(end.interface, Unknown) else "?")
        for end in link.ends
    }
    assert ("dev-S1", "Gi1/0/24") in ends
    assert link.conflicts == ()
    assert {e.source for e in link.evidence} >= {EvidenceSource.ARP, EvidenceSource.MAC}
    assert {e.command for e in link.evidence} >= {ARP, MAC, STATIC}
    assert built.unvisited[0].reason is UnvisitedReason.ROUTING_OR_ARP_ONLY
    assert {e.device for e in link.evidence} == {"dev-S1"}


def test_inference_does_not_guess_when_the_port_is_not_a_single_edge() -> None:
    two_ports = visited(
        A,
        "S1",
        "sw-a",
        static=(_static(GW),),
        arp=(_arp(GW, MAC_A),),
        mac=(_learned(MAC_A, "Gi1/0/24"), _learned(MAC_A, "Gi1/0/25")),
    )
    on_uplink = visited(
        A,
        "S1",
        "sw-a",
        static=(_static(GW),),
        arp=(_arp(GW, MAC_A),),
        mac=(_learned(MAC_A, "Gi1/0/1"),),
        cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
    )
    already = visited(
        A,
        "S1",
        "sw-a",
        static=(_static(B),),
        arp=(_arp(B, MAC_A),),
        mac=(_learned(MAC_A, "Gi1/0/24"),),
        cdp=[neighbour("Gi1/0/1", "sw-b", "Gi1/0/1", B)],
    )
    on_svi = visited(
        A,
        "S1",
        "sw-a",
        static=(_static(GW),),
        arp=(_arp(GW, MAC_A),),
        mac=(_learned(MAC_A, "Vlan10"),),
    )
    no_mac = visited(A, "S1", "sw-a", static=(_static(GW),), arp=(_arp(GW, MAC_A),))
    no_arp = visited(A, "S1", "sw-a", static=(_static(GW),), mac=(_learned(MAC_A, "Gi1/0/24"),))

    split = topology.build([two_ports], scope=LAN)
    assert [link for link in split.links if link.status is LinkStatus.INFERRED] == []
    assert split.findings[0].kind is FindingKind.CONFLICTING_EVIDENCE
    assert split.findings[0].evidence
    cases = (
        [on_uplink, _device(B, "S2", "sw-b")],
        [already, _device(B, "S2", "sw-b")],
        [on_svi],
        [no_mac],
        [no_arp],
    )
    for records in cases:
        built = topology.build(records, scope=LAN)
        assert [link for link in built.links if link.status is LinkStatus.INFERRED] == []


def test_two_next_hops_on_one_edge_port_are_a_shared_segment() -> None:
    other = "198.51.100.10"
    built = topology.build(
        [
            visited(
                A,
                "S1",
                "sw-a",
                static=(_static(GW), _static(other, "203.0.113.0/24")),
                arp=(_arp(GW, MAC_A), _arp(other, MAC_B)),
                mac=(_learned(MAC_A, "Gi1/0/24"), _learned(MAC_B, "Gi1/0/24")),
            )
        ],
        scope=LAN,
    )

    assert built.links == ()
    (segment,) = built.segments
    assert _ID.fullmatch(segment.id)
    assert {port.device for port in segment.ports} == {
        "dev-S1",
        *(device.id for device in built.unvisited),
    }
    assert len(built.unvisited) == 2
    assert {e.source for e in segment.evidence} >= {EvidenceSource.ARP, EvidenceSource.MAC}


def test_an_arp_entry_that_is_not_a_next_hop_creates_no_device_and_no_link() -> None:
    built = topology.build(
        [
            visited(
                A,
                "S1",
                "sw-a",
                arp=(_arp("192.0.2.50", MAC_A),),
                mac=(_learned(MAC_A, "Gi1/0/24"),),
            )
        ],
        scope=LAN,
    )

    assert built.unvisited == ()
    assert built.links == ()
    assert built.adjacencies == ()
    assert built.subnets == ()


def test_the_document_carries_adjacencies_and_subnets() -> None:
    built = topology.build(
        [
            _device(A, "S1", "rtr-a", "192.0.2.1/24", routing=(_ospf(B),)),
            _device(B, "S2", "rtr-b", "192.0.2.2/24"),
            _device(C, "S3", "rtr-c", "198.51.100.1/24"),
            _device(D, "S4", "rtr-d", "198.51.100.2/24"),
            _device("192.0.2.5", "S5", "rtr-e", "198.51.100.3/24"),
        ]
    )
    document = json.loads(json.dumps(topology.to_document(built)))

    assert document["format_version"] == 2
    kinds = {item["kind"] for item in document["adjacencies"]}
    assert kinds == {"OSPF", "shared subnet"}
    shared = next(item for item in document["adjacencies"] if item["kind"] == "shared subnet")
    assert shared["prefix"] == "192.0.2.0/24"
    assert document["subnets"][0]["prefix"] == "198.51.100.0/24"
    assert len(document["subnets"][0]["attachments"]) == 3
    assert "netops-ro" not in json.dumps(document)
