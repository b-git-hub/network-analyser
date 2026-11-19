"""Where each device sits on the Map (#63, stories 143, 144, 149; decided on #13).

Tiered rows by hop distance from the most central device and its vPC peer, wrapping at 24
per row; Unvisited Devices in their own area below, grouped by reason.
"""

from network_analyser import diagram
from tests.support.topology_documents import (
    bundle,
    device,
    document,
    link,
    read,
    unvisited_device,
)

CORE = "dev-core"


def _star(count: int) -> object:
    """A core with `count` access switches, one Link each."""
    leaves = [device(f"dev-acc{i:02d}", f"acc-{i:02d}") for i in range(count)]
    links = [link(f"link-{i:02d}", CORE, f"Gi1/0/{i}", f"dev-acc{i:02d}", "Gi1/1/1") for i in range(count)]
    return document([device(CORE, "core"), *leaves], links)


def _rows(layout: diagram.Layout, ids: list[str]) -> list[float]:
    return sorted({layout.positions[i].y for i in ids})


def test_the_most_central_device_sits_alone_in_the_top_row() -> None:
    layout = diagram.place(read(_star(3)))

    core = layout.positions[CORE]
    leaves = [layout.positions[f"dev-acc{i:02d}"] for i in range(3)]
    assert core.x == 0
    assert all(leaf.y > core.y for leaf in leaves)
    assert len({leaf.y for leaf in leaves}) == 1


def test_a_chain_puts_each_hop_one_row_further_down() -> None:
    devices = [device(f"dev-{n}", n) for n in ("a", "b", "c", "d", "e")]
    links = [
        link("link-1", "dev-a", "Gi1", "dev-b", "Gi1"),
        link("link-2", "dev-b", "Gi2", "dev-c", "Gi1"),
        link("link-3", "dev-c", "Gi2", "dev-d", "Gi1"),
        link("link-4", "dev-d", "Gi2", "dev-e", "Gi1"),
    ]

    layout = diagram.place(read(document(devices, links)))

    y = {n: layout.positions[f"dev-{n}"].y for n in "abcde"}
    assert y["c"] < y["b"] == y["d"] < y["a"] == y["e"]


def test_the_vpc_peer_shares_the_top_row() -> None:
    devices = [
        device("dev-n1", "nx-1"),
        device("dev-n2", "nx-2"),
        device("dev-d", "dist"),
        device("dev-e", "dist-2"),
    ]
    links = [
        link("link-p1", "dev-n1", "Eth1/53", "dev-n2", "Eth1/53", role="vPC peer-link", bundle="bundle-p"),
        link("link-p2", "dev-n1", "Eth1/54", "dev-n2", "Eth1/54", role="vPC peer-link", bundle="bundle-p"),
        link("link-u1", "dev-d", "Te1/1/1", "dev-n1", "Eth1/1", bundle="bundle-u"),
        link("link-u2", "dev-d", "Te1/1/2", "dev-n2", "Eth1/1", bundle="bundle-u"),
        link("link-v1", "dev-e", "Te1/1/1", "dev-n1", "Eth1/2"),
        link("link-v2", "dev-e", "Te1/1/2", "dev-n2", "Eth1/2"),
    ]
    bundles = [
        bundle("bundle-p", [("dev-n1", "Po1")], [("dev-n2", "Po1")], ["link-p1", "link-p2"], role="vPC peer-link"),
        bundle("bundle-u", [("dev-d", "Po10")], [("dev-n1", "Po10"), ("dev-n2", "Po10")], ["link-u1", "link-u2"], vpc=10),
    ]

    layout = diagram.place(read(document(devices, links, bundles=bundles)))

    pos = layout.positions
    assert pos["dev-n1"].y == pos["dev-n2"].y < pos["dev-d"].y == pos["dev-e"].y


def test_a_tier_wraps_at_24_devices_per_row() -> None:
    layout = diagram.place(read(_star(30)))

    leaves = [f"dev-acc{i:02d}" for i in range(30)]
    first, second = _rows(layout, leaves)
    assert sum(layout.positions[i].y == first for i in leaves) == 24
    assert sum(layout.positions[i].y == second for i in leaves) == 6


def test_positions_are_the_same_every_time_whatever_the_order() -> None:
    data = _star(5)
    shuffled = dict(data)  # type: ignore[call-overload]  # a JSON object
    shuffled["devices"] = list(reversed(shuffled["devices"]))
    shuffled["links"] = list(reversed(shuffled["links"]))

    assert diagram.place(read(data)) == diagram.place(read(data))
    assert diagram.place(read(shuffled)).positions == diagram.place(read(data)).positions


def test_no_two_devices_share_a_place() -> None:
    data = _star(30)
    data["unvisited"] = [  # type: ignore[index]  # a JSON object
        unvisited_device(f"unv-{i:012x}", f"ap-{i}", "outside Scope", "dev-acc01") for i in range(9)
    ]

    layout = diagram.place(read(data))

    places = [(p.x, p.y) for p in layout.positions.values()]
    assert len(places) == len(set(places)) == 1 + 30 + 9


def test_a_device_with_no_link_sits_below_the_connected_ones() -> None:
    data = _star(2)
    data["devices"].append(device("dev-lone", "lone"))  # type: ignore[index]  # a JSON object

    layout = diagram.place(read(data))

    assert layout.positions["dev-lone"].y > layout.positions["dev-acc00"].y


def test_a_shared_segment_takes_a_place_in_the_tiers() -> None:
    data = _star(1)
    data["segments"] = [  # type: ignore[index]  # a JSON object
        {
            "id": "seg-1",
            "ports": [{"device": "dev-acc00", "interface": {"short": "Gi1/0/48"}}],
            "evidence": [],
        }
    ]

    layout = diagram.place(read(data))

    assert layout.positions["seg-1"].y > layout.positions["dev-acc00"].y


def test_unvisited_devices_sit_in_their_own_area_below_grouped_by_reason() -> None:
    data = _star(2)
    data["unvisited"] = [  # type: ignore[index]  # a JSON object
        unvisited_device("unv-000000000001", "ap-1", "outside Scope", "dev-acc00"),
        unvisited_device("unv-000000000002", "ap-2", "unreachable", "dev-acc00"),
        unvisited_device("unv-000000000003", "ap-3", "outside Scope", "dev-acc01"),
        {"id": "unv-000000000004", "reason": {"unknown": "no reason recorded"}},
    ]

    layout = diagram.place(read(data))

    lowest_visited = max(layout.positions[f"dev-acc{i:02d}"].y for i in range(2))
    unvisited = [f"unv-00000000000{i}" for i in range(1, 5)]
    assert all(layout.positions[u].y > lowest_visited for u in unvisited)
    groups = [label.text for label in layout.labels if not label.heading]
    assert groups == ["outside Scope (2)", "reason not recorded (1)", "unreachable (1)"]
    assert [label.heading for label in layout.labels].count(True) == 1
