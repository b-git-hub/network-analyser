"""Dragging a box on `diagram.html` (#73).

The page's own JavaScript moves a node with the pointer and keeps the moved positions in the
browser, per diagram file. These tests pin the contracts that would otherwise disappear in
silence; the pointer behaviour itself is checked in a real browser, because the repo has no
JavaScript test runner.
"""

import base64
import hashlib
import re

from network_analyser import diagram
from tests.support.topology_documents import device, document, link, read

DRAG_HINT = "Drag a box, Shared Segment or Subnet to move it"
RESET_BUTTON = (
    '<button data-z="reset" aria-label="Reset layout" '
    'title="Reset layout to the generated positions">\u21ba</button>'
)


def _twins() -> object:
    return document(
        [device("dev-S1", "sw-a"), device("dev-S2", "sw-b", "192.0.2.2")],
        [link("link-1", "dev-S1", "Gi1/0/1", "dev-S2", "Gi1/0/2")],
    )


def _page() -> str:
    return diagram.draw_html(read(_twins()), lambda text: text)


def _script(page: str) -> str:
    found = re.search(r"<script>(.*?)</script>", page, re.DOTALL)
    assert found is not None
    return found.group(1)


def test_the_page_keeps_dragged_positions_in_the_browser_for_this_file_only() -> None:
    script = _script(_page())

    assert "network-analyser.diagram.layout.v1:" in script
    assert "location.pathname" in script
    for call in ("localStorage.getItem", "localStorage.setItem", "localStorage.removeItem"):
        assert call in script


def test_the_page_offers_the_reset_control_and_the_physical_view_drag_hint() -> None:
    page = _page()

    assert RESET_BUTTON in page
    assert DRAG_HINT in _script(page)


def test_the_dragged_positions_still_need_no_script_from_outside() -> None:
    page = _page()
    script = _script(page)

    for call in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "import("):
        assert call not in script
    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page)
    assert policy is not None
    assert "default-src 'none'" in policy.group(1)
    assert f"script-src 'sha256-{_digest(script)}'" in policy.group(1)


def _digest(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")
