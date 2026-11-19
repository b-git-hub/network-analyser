"""`diagram.html`: one self-contained page, every device string escaped (#63, story 142).

The page's own JavaScript draws the Map from a data block. These tests read that block back
and check the page around it; how the drawing looks is checked by hand in a browser.
"""

import base64
import hashlib
import json
import re
from collections.abc import Callable
from typing import Any

from network_analyser import diagram
from tests.support.topology_documents import device, document, link, read, unvisited_device

HOSTILE = "</script><img src=x onerror=alert(1)>\"'&\u2028"
DATA_OPEN = '<script type="application/json" id="topology-data">'


def _page(data: object, redact: Callable[[str], str] = lambda text: text) -> str:
    return diagram.draw_html(read(data), redact)


def _data(page: str) -> Any:  # noqa: ANN401 (JSON data, read by key)
    start = page.index(DATA_OPEN) + len(DATA_OPEN)
    return json.loads(page[start : page.index("</script>", start)])


def _two_switches(hostname: str = "sw-b") -> object:
    return document(
        [device("dev-S1", "sw-a"), device("dev-S2", hostname, "192.0.2.2")],
        [link("link-1", "dev-S1", "Gi1/0/1", "dev-S2", "Gi1/0/2")],
        unvisited=[unvisited_device("unv-0123456789ab", "ap-1", "outside Scope", "dev-S1")],
    )


def test_the_page_carries_the_topology_and_every_device_s_place() -> None:
    data = _data(_page(_two_switches()))

    assert [d["id"] for d in data["topology"]["devices"]] == ["dev-S1", "dev-S2"]
    assert data["topology"]["links"][0]["ends"][1]["interface"]["short"] == "Gi1/0/2"
    placed = {ident for ident, _x, _y in data["layout"]["positions"]}
    assert placed == {"dev-S1", "dev-S2", "unv-0123456789ab"}
    assert any("outside Scope" in label["text"] for label in data["layout"]["labels"])


def test_device_text_never_reaches_the_page_as_markup() -> None:
    page = _page(_two_switches(HOSTILE))

    assert "<img" not in page
    assert page.count("</script>") == 2  # the data block's and the code's own
    assert "\u2028" not in page
    assert _data(page)["topology"]["devices"][1]["hostname"] == HOSTILE


def test_every_value_is_scanned_before_it_is_escaped() -> None:
    seen: list[str] = []

    def redact(text: str) -> str:
        seen.append(text)
        return text.replace("CANARY-pw-7f3a", "[blocked]")

    page = _page(_two_switches('x"CANARY-pw-7f3a<'), redact)

    assert "CANARY" not in page
    assert _data(page)["topology"]["devices"][1]["hostname"] == 'x"[blocked]<'
    assert 'x"CANARY-pw-7f3a<' in seen  # scanned as written, not as escaped


def test_the_page_runs_only_its_own_script_and_style() -> None:
    page = _page(_two_switches())

    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page)
    assert policy is not None
    rules = dict(rule.strip().split(" ", 1) for rule in policy.group(1).split(";"))
    assert rules["default-src"] == "'none'"
    script = re.search(r"<script>(.*?)</script>", page, re.DOTALL)
    style = re.search(r"<style>(.*?)</style>", page, re.DOTALL)
    assert script is not None
    assert style is not None
    assert rules["script-src"] == f"'sha256-{_digest(script.group(1))}'"
    assert rules["style-src"] == f"'sha256-{_digest(style.group(1))}'"


def test_the_page_needs_nothing_from_outside() -> None:
    page = _page(_two_switches()).lower()

    for outside in (
        "src=",
        "href=",
        "<link",
        "@import",
        "url(",
        "http:",
        "https:",
        "<iframe",
        "<object",
    ):
        assert outside not in page


def test_the_same_topology_gives_the_same_page() -> None:
    assert _page(_two_switches()) == _page(_two_switches())


def _digest(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")
