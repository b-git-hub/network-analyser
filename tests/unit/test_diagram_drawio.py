"""`diagram.drawio`: a draw.io file with a Physical and a Routing page (#65, story 154).

The file is read back as XML, so these tests check what draw.io will open, not how it looks
(that is a lab check). Every name and address is synthetic.
"""

import re
import xml.etree.ElementTree as ET
from collections.abc import Callable
from typing import Any

import pytest

from network_analyser import diagram
from tests.support.topology_documents import (
    adjacency,
    bundle,
    device,
    document,
    link,
    name,
    read,
    subnet,
    unvisited_device,
)

HOSTILE = "<img src=x onerror=alert(1)>&amp;\"'</mxCell><!-- x -->\x00\x01\x1b\u2028\ud800"


def _file(data: object, redact: Callable[[str], str] = lambda text: text) -> str:
    return diagram.draw_drawio(read(data), redact)


def _root(text: str) -> ET.Element:
    return ET.fromstring(text)  # noqa: S314 (the file the tool itself just wrote)


def _page(root: ET.Element, title: str) -> ET.Element:
    (found,) = (d for d in root.findall("diagram") if d.get("name") == title)
    model = found.find("mxGraphModel")
    assert model is not None  # uncompressed: draw.io Desktop needs no inflate
    cells = model.find("root")
    assert cells is not None
    return cells


def _cells(page: ET.Element) -> dict[str, ET.Element]:
    """Every cell by id; a shape with data is an `object` holding the `mxCell`."""
    found: dict[str, ET.Element] = {}
    for element in page.iter():
        if element.tag == "object" or (element.tag == "mxCell" and element.get("id")):
            ident = element.get("id")
            assert ident is not None
            assert ident not in found, f"cell id {ident} is used twice"
            found[ident] = element
    return found


def _cell(element: ET.Element) -> ET.Element:
    return element.find("mxCell") if element.tag == "object" else element  # type: ignore[return-value]


def _style(element: ET.Element) -> dict[str, str]:
    style = _cell(element).get("style", "")
    pairs = [part.partition("=") for part in style.split(";") if part]
    return {key: value for key, _, value in pairs}


def _centre(element: ET.Element) -> tuple[float, float]:
    geometry = _cell(element).find("mxGeometry")
    assert geometry is not None
    return (
        float(geometry.get("x", "0")) + float(geometry.get("width", "0")) / 2,
        float(geometry.get("y", "0")) + float(geometry.get("height", "0")) / 2,
    )


def _edges(page: ET.Element) -> list[ET.Element]:
    return [e for e in _cells(page).values() if _cell(e).get("edge") == "1"]


def _three_switches() -> Any:  # noqa: ANN401 (JSON data)
    devices = [
        device("dev-S1", "sw-a", serials=["SYN1"], software_version="17.9.4"),
        device("dev-S2", "sw-b", "192.0.2.2", platform="NX-OS", serials=["SYN2"]),
        device("dev-S3", "sw-c", "192.0.2.3", serials=["SYN3"]),
    ]
    links = [
        link("link-1", "dev-S1", "Gi1/0/1", "dev-S2", "Eth1/1"),
        link("link-2", "dev-S2", "Eth1/2", "dev-S3", "Gi1/0/2", status="one-sided"),
        link("link-3", "dev-S1", "Gi1/0/3", "dev-S3", "Gi1/0/3", status="inferred"),
        link("link-4", "dev-S1", "Gi1/0/9", "dev-S2", "Eth1/9", role="vPC peer-keepalive"),
        link("link-5", "dev-S1", "Gi1/0/5", "dev-S3", "Gi1/0/5", bundle="bundle-1"),
        link("link-6", "dev-S1", "Gi1/0/6", "dev-S3", "Gi1/0/6", bundle="bundle-1"),
    ]
    bundles = [bundle("bundle-1", [("dev-S1", "Po1")], [("dev-S3", "Po1")], ["link-5", "link-6"])]
    return document(
        devices,
        links,
        unvisited=[unvisited_device("unv-0123456789ab", "ap-1", "outside Scope", "dev-S1")],
        segments=[
            {
                "id": "seg-0123456789ab",
                "ports": [
                    {"device": "dev-S1", "interface": name("Gi1/0/7")},
                    {"device": "dev-S2", "interface": name("Eth1/7")},
                ],
                "evidence": [],
            }
        ],
        bundles=bundles,
    )


def test_the_file_is_one_xml_document_with_a_physical_and_a_routing_page() -> None:
    root = _root(_file(_three_switches()))

    assert root.tag == "mxfile"
    assert [d.get("name") for d in root.findall("diagram")] == ["Physical", "Routing"]


def test_both_pages_put_every_device_where_diagram_html_does() -> None:
    topology = read(_three_switches())
    layout = diagram.place(topology)
    root = _root(diagram.draw_drawio(topology, lambda text: text))

    for title, expected in (
        ("Physical", {"dev-S1", "dev-S2", "dev-S3", "unv-0123456789ab", "seg-0123456789ab"}),
        ("Routing", {"dev-S1", "dev-S2", "dev-S3"}),
    ):
        cells = _cells(_page(root, title))
        shapes = {i[2:]: e for i, e in cells.items() if i.startswith("n-")}
        assert set(shapes) == expected
        for ident, shape in shapes.items():
            point = layout.positions[ident]
            assert _centre(shape) == pytest.approx((point.x, point.y), abs=0.1), (title, ident)


def test_the_unvisited_area_keeps_its_headings() -> None:
    topology = read(_three_switches())
    layout = diagram.place(topology)
    cells = _cells(_page(_root(diagram.draw_drawio(topology, lambda text: text)), "Physical"))

    labels = [_cell(e) for i, e in cells.items() if i.startswith("area-")]
    assert len(labels) == len(layout.labels)
    assert any(c.get("value", "").startswith("outside Scope") for c in labels)
    assert any("Unvisited Devices" in c.get("value", "") for c in labels)


def test_line_styles_match_the_html_confirmed_solid_one_sided_dashed_inferred_dotted() -> None:
    page = _page(_root(_file(_three_switches())), "Physical")
    cells = _cells(page)

    confirmed = _style(cells["e-link-1"])
    one_sided = _style(cells["e-link-2"])
    inferred = _style(cells["e-link-3"])
    assert confirmed.get("dashed", "0") == "0"
    assert one_sided["dashed"] == "1"
    assert inferred["dashed"] == "1"
    assert one_sided["dashPattern"] != inferred["dashPattern"]
    # dotted is a short dash with a long gap; dashed is a long dash
    assert float(inferred["dashPattern"].split()[0]) < float(one_sided["dashPattern"].split()[0])
    assert _style(cells["e-link-4"])["dashed"] == "1"  # the keepalive is not a data link
    assert float(_style(cells["e-link-4"])["strokeWidth"]) < float(confirmed["strokeWidth"])


def test_a_bundle_is_one_wide_labelled_line_for_its_members() -> None:
    page = _page(_root(_file(_three_switches())), "Physical")
    edges = _edges(page)
    bundles = [e for e in edges if e.get("label", "").startswith("Po1")]

    assert len(bundles) == 1  # two member Links, one line
    assert "\u00d72" in bundles[0].get("label", "")
    style = _style(bundles[0])
    assert style["shape"] == "link"  # draw.io's double line, as the HTML draws a Bundle
    assert float(style["width"]) > 0
    assert _style(_cells(page)["e-link-1"]).get("shape") != "link"
    assert "e-link-5" not in _cells(page)
    assert "e-link-6" not in _cells(page)


def test_interface_names_label_each_end_of_a_line() -> None:
    page = _page(_root(_file(_three_switches())), "Physical")
    cells = _cells(page)

    ends = [
        c.get("value") for c in (_cell(e) for e in cells.values()) if c.get("parent") == "e-link-1"
    ]
    assert sorted(v for v in ends if v) == ["Eth1/1", "Gi1/0/1"]


def test_a_line_joins_the_two_shapes_it_names() -> None:
    page = _page(_root(_file(_three_switches())), "Physical")
    edge = _cell(_cells(page)["e-link-1"])

    assert edge.get("source") == "n-dev-S1"
    assert edge.get("target") == "n-dev-S2"


def test_lines_to_unvisited_devices_sit_on_a_layer_that_starts_hidden() -> None:
    data = _three_switches()
    data["links"].append(link("link-9", "dev-S1", "Gi1/0/9", "unv-0123456789ab", None))
    page = _page(_root(_file(data)), "Physical")
    cells = _cells(page)

    layer = _cell(cells["e-link-9"]).get("parent")
    assert layer is not None
    assert _cell(cells[layer]).get("visible") == "0"
    assert _cell(cells["e-link-1"]).get("parent") != layer


def test_device_details_are_in_the_shape_data_and_there_is_no_username() -> None:
    page = _page(_root(_file(_three_switches())), "Physical")
    shape = _cells(page)["n-dev-S1"]

    assert shape.tag == "object"
    assert shape.get("hostname") == "sw-a"
    assert shape.get("platform") == "IOS/IOS-XE"
    assert shape.get("model") == "C9300-48P"
    assert shape.get("software_version") == "17.9.4"
    assert shape.get("management_ip") == "192.0.2.1"
    assert shape.get("serial") == "SYN1"
    assert "username" not in _file(_three_switches()).lower()


def test_the_routing_page_has_the_same_shape_data() -> None:
    page = _page(_root(_file(_three_switches())), "Routing")
    shape = _cells(page)["n-dev-S2"]

    assert shape.get("hostname") == "sw-b"
    assert shape.get("platform") == "NX-OS"
    assert shape.get("management_ip") == "192.0.2.2"


def test_a_device_s_addresses_are_in_its_shape_data_on_the_routing_page() -> None:
    interface = {
        "name": name("Vlan10"),
        "ip": {"vrf": "default", "addresses": ["192.0.2.1/24"], "unnumbered": None},
    }
    data = document([device("dev-S1", "sw-a", interfaces=[interface])])
    shape = _cells(_page(_root(_file(data)), "Routing"))["n-dev-S1"]

    assert "Vlan10" in shape.get("l3_interfaces", "")
    assert "192.0.2.1/24" in shape.get("l3_interfaces", "")
    assert "default" in shape.get("l3_interfaces", "")


def test_the_routing_page_says_when_the_file_holds_no_routing_lines() -> None:
    page = _page(_root(_file(_three_switches())), "Routing")

    assert _edges(page) == []
    notes = [_cell(e).get("value", "") for i, e in _cells(page).items() if i == "note"]
    assert notes
    assert "no routing" in notes[0].lower()


def _routed() -> Any:  # noqa: ANN401 (JSON data)
    data = _three_switches()
    l3 = {
        "name": name("Vlan99"),
        "ip": {"vrf": "default", "addresses": ["198.51.100.1/24"], "unnumbered": None},
    }
    data["devices"][0]["interfaces"] = [l3]
    data["devices"][1]["interfaces"] = [l3]
    data["adjacencies"] = [
        adjacency("adj-000000000001", "dev-S1", "dev-S2", prefix="192.0.2.8/30"),
        adjacency("adj-000000000002", "dev-S1", "dev-S2", "OSPF"),
    ]
    data["subnets"] = [
        subnet(
            "subnet-000000000001",
            "198.51.100.0/24",
            ("dev-S1", "Vlan99", "198.51.100.1/24"),
            ("dev-S2", "Vlan99", "198.51.100.2/24"),
            ("dev-S3", "Vlan99", "198.51.100.3/24"),
        )
    ]
    return data


def test_the_routing_page_draws_shared_subnets_labelled_with_the_prefix() -> None:
    cells = _cells(_page(_root(_file(_routed())), "Routing"))

    line = cells["e-adj-000000000001"]
    assert line.get("label") == "192.0.2.8/30"
    assert _cell(line).get("source") == "n-dev-S1"
    assert _cell(line).get("target") == "n-dev-S2"
    assert line.get("topology_id") == "adj-000000000001"
    assert _style(line).get("dashed", "0") == "0"


def test_the_routing_page_draws_protocol_neighbourships_labelled_with_the_protocol() -> None:
    cells = _cells(_page(_root(_file(_routed())), "Routing"))

    line = cells["e-adj-000000000002"]
    assert line.get("label") == "OSPF"
    assert _style(line)["dashed"] == "1"
    assert line.get("vrf") == "default"


def test_a_subnet_is_a_node_joined_to_each_device_on_it() -> None:
    topology = read(_routed())
    spot = diagram.place(topology).subnets["subnet-000000000001"]
    cells = _cells(_page(_root(diagram.draw_drawio(topology, lambda text: text)), "Routing"))

    node = cells["n-subnet-000000000001"]
    assert "198.51.100.0/24" in _cell(node).get("value", node.get("label", ""))
    assert _centre(node) == pytest.approx((spot.x, spot.y), abs=0.1)
    joined = {
        _cell(e).get("target")
        for e in _edges(_page(_root(_file(_routed())), "Routing"))
        if _cell(e).get("source") == "n-subnet-000000000001"
    }
    assert joined == {"n-dev-S1", "n-dev-S2", "n-dev-S3"}


def test_devices_with_no_l3_interface_are_faded_on_the_routing_page() -> None:
    data = _routed()
    data["subnets"] = []
    cells = _cells(_page(_root(_file(data)), "Routing"))

    assert "opacity" not in _style(cells["n-dev-S1"])
    assert float(_style(cells["n-dev-S3"])["opacity"]) < 100
    assert "opacity" not in _style(_cells(_page(_root(_file(data)), "Physical"))["n-dev-S3"])


def test_with_l3_data_the_routing_page_carries_no_missing_lines_note() -> None:
    cells = _cells(_page(_root(_file(_routed())), "Routing"))

    notes = [_cell(e).get("value", "") for i, e in cells.items() if i == "note"]
    assert all("no routing" not in note.lower() for note in notes)


def test_unknown_values_read_as_unknown_never_as_empty() -> None:
    data = document([device("dev-S1", "sw-a", model={"unknown": "not collected"}, serials=[])])
    shape = _cells(_page(_root(_file(data)), "Physical"))["n-dev-S1"]

    assert shape.get("model") == "unknown (not collected)"
    assert shape.get("serial") == "none"


def test_an_unvisited_device_carries_its_reason() -> None:
    shape = _cells(_page(_root(_file(_three_switches())), "Physical"))["n-unv-0123456789ab"]

    assert shape.get("reason") == "outside Scope"
    assert shape.get("advertised_ips") == "198.51.100.7"


def test_hostile_device_text_is_escaped_and_the_file_still_parses() -> None:
    data = document(
        [
            device("dev-S1", HOSTILE, model=HOSTILE, software_version=HOSTILE),
            device("dev-S2", "sw-b", "192.0.2.2"),
        ],
        [link("link-1", "dev-S1", HOSTILE, "dev-S2", "Gi1/0/2")],
        unvisited=[unvisited_device("unv-0123456789ab", HOSTILE, HOSTILE, "dev-S1")],
    )
    data["devices"][0]["interfaces"] = [
        {"name": name(HOSTILE), "description": HOSTILE, "ip": {"addresses": [HOSTILE]}}
    ]
    text = _file(data)

    root = _root(text)  # well-formed: nothing closed a tag or started a comment
    assert "<img" not in text
    assert "</mxCell><!--" not in text
    assert "<!--" not in text
    assert not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]", text)
    shape = _cells(_page(root, "Physical"))["n-dev-S1"]
    hostname = shape.get("hostname", "")
    assert hostname.startswith("<img src=x onerror=alert(1)>&amp;\"'</mxCell><!-- x -->")
    assert hostname.endswith("\\x00\\x01\\x1b\\u2028\\ud800")  # shown, not smuggled
    assert shape.get("label", "").startswith("<img src=x")
    assert shape.get("model", "").endswith("\\x00\\x01\\x1b\\u2028\\ud800")
    assert "\\x1b" in shape.get("l3_interfaces", "")


def test_hostile_text_cannot_become_a_url_a_tag_or_style() -> None:
    hostile = (
        "http://evil.example/x",
        "HTTPS://evil.example",
        "javascript:alert(1)",
        "a;fillColor=red;html=1",
        '<a href="//evil.example">x</a>',
        "url(//evil.example/a.png)",
    )
    data = document(
        [device(f"dev-S{i}", h, f"192.0.2.{i}") for i, h in enumerate(hostile, 1)],
    )
    text = _file(data)

    lowered = text.lower()
    for outside in ("http:", "https:", "javascript:", "//evil", "<a ", "url(", "xmlns"):
        assert outside not in lowered
    assert not re.search(r"href\s*=|src\s*=", lowered)
    root = _root(text)
    for i, h in enumerate(hostile, 1):
        shape = _cells(_page(root, "Physical"))[f"n-dev-S{i}"]
        assert shape.get("hostname") == h  # the text is kept; it is just inert
        style = _style(shape)
        assert style.get("html") == "0"  # a label is plain text, never HTML
        assert "fillColor" not in style or style["fillColor"] != "red"
        assert "link" not in shape.attrib
        assert "placeholders" not in shape.attrib


def test_nothing_in_the_file_points_outside_it() -> None:
    text = _file(_three_switches())

    for outside in (
        "http",
        "://",
        "xmlns",
        "href",
        "src=",
        "link=",
        "url(",
        "@import",
        "<!doctype",
    ):
        assert outside not in text.lower()


def test_every_value_is_scanned_before_it_is_escaped() -> None:
    seen: list[str] = []

    def redact(text: str) -> str:
        seen.append(text)
        return text.replace("CANARY-pw-7f3a", "[blocked]")

    data = _three_switches()
    data["devices"][1]["hostname"] = 'x"<CANARY-pw-7f3a&'
    data["devices"][1]["model"] = "CANARY-pw-7f3a"
    text = _file(data, redact)

    assert "CANARY" not in text
    shape = _cells(_page(_root(text), "Physical"))["n-dev-S2"]
    assert shape.get("hostname") == 'x"<[blocked]&'
    assert shape.get("model") == "[blocked]"
    assert 'x"<CANARY-pw-7f3a&' in seen  # scanned as written, not as escaped


def test_a_duplicate_id_in_the_file_does_not_make_two_cells_with_one_id() -> None:
    data = document(
        [
            device("dev-S1", "sw-a"),
            device("dev-S1", "sw-b", "192.0.2.2"),
            device("dev-S2", "sw-c", "192.0.2.3"),
            device("dev-S3", "sw-d", "192.0.2.4"),
        ],
        [
            link("link-1", "dev-S1", "Gi1/0/1", "dev-S2", "Gi1/0/2"),
            link("link-1", "dev-S1", "Gi1/0/3", "dev-S3", "Gi1/0/4"),
        ],
    )

    page = _page(_root(_file(data)), "Physical")

    assert len(_edges(page)) == 2  # _cells also asserts that no id is used twice


def test_parallel_lines_between_two_devices_do_not_lie_on_top_of_each_other() -> None:
    data = document(
        [device("dev-S1", "sw-a"), device("dev-S2", "sw-b", "192.0.2.2")],
        [
            link("link-1", "dev-S1", "Gi1/0/1", "dev-S2", "Gi1/0/1"),
            link("link-2", "dev-S1", "Gi1/0/2", "dev-S2", "Gi1/0/2"),
        ],
    )
    cells = _cells(_page(_root(_file(data)), "Physical"))

    bends = [_cell(cells[f"e-link-{i}"]).findall("mxGeometry/Array/mxPoint") for i in (1, 2)]
    assert bends[0] != bends[1]
    assert (bends[0][0].get("x"), bends[0][0].get("y")) != (
        bends[1][0].get("x"),
        bends[1][0].get("y"),
    )


def test_a_link_to_something_that_is_not_drawn_is_left_out() -> None:
    data = document(
        [device("dev-S1", "sw-a")],
        [link("link-1", "dev-S1", "Gi1/0/1", "dev-GONE", "Gi1/0/2")],
    )

    assert _edges(_page(_root(_file(data)), "Physical")) == []


def test_an_empty_topology_still_gives_two_empty_pages() -> None:
    root = _root(_file(document([])))

    assert [d.get("name") for d in root.findall("diagram")] == ["Physical", "Routing"]
    assert all(_page(root, n) is not None for n in ("Physical", "Routing"))


def test_the_same_topology_gives_the_same_file() -> None:
    assert _file(_three_switches()) == _file(_three_switches())


def test_the_file_declares_utf8_and_is_ascii_for_device_text() -> None:
    data = document([device("dev-S1", "sw-\u00e9\u4e2d\U0001f600")])
    text = _file(data)

    assert text.startswith('<?xml version="1.0" encoding="UTF-8"?>')
    shape = _cells(_page(_root(text), "Physical"))["n-dev-S1"]
    assert shape.get("hostname") == "sw-\u00e9\u4e2d\U0001f600"  # real characters survive
    assert "\u00e9" not in text
