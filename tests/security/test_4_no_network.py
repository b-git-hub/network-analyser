"""Security test 4, no-network pages (spec #37, Testing Decisions; decided on #13, #30).

A static scan of a generated `diagram.html` finds no `http(s)://`, no `<script src>` and no
fetch calls, nor any other way for the page to load or send anything, even when device
text is written to look like one (#63). The same scan of a generated `diagram.drawio` finds
no URL and no namespace to fetch (#65). A generated `run-report.html` has no `http(s)://`,
no `<script>` at all, and a Content-Security-Policy `<meta>` tag (#66).
"""

import json
import re
from pathlib import Path

import pytest

from network_analyser.cli import ExitCode, main
from network_analyser.credentials import SecretScan
from network_analyser.run_output import RunFolder
from network_analyser.run_output.report import write_run_report
from tests.support.topology_documents import (
    adjacency,
    device,
    document,
    link,
    subnet,
    unvisited_device,
)
from tests.unit.test_run_report import _report

pytestmark = pytest.mark.security

# What would let a page reach the network: URLs, loaded scripts, styles, frames or
# media, and every script call that sends or fetches. Checked over the whole page.
NETWORK = {
    "a URL": re.compile(r"https?:|wss?:|//[a-z0-9-]+\.[a-z0-9.-]+", re.IGNORECASE),
    "a loaded script": re.compile(r"<script\b[^>]*\bsrc\s*=", re.IGNORECASE),
    "a fetch call": re.compile(r"\bfetch\s*\(", re.IGNORECASE),
    "a request object": re.compile(
        r"\b(?:XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|import)\s*\(",
        re.IGNORECASE,
    ),
    "a loaded resource": re.compile(
        r"<[a-z][^>]*\s(?:src|href|srcset|action|formaction|data|poster)\s*="
        r"|<link\b|<iframe\b|<object\b|<embed\b|@import|url\s*\(",
        re.IGNORECASE,
    ),
}
# The page's own code may not even name a network API. Device text may (a description
# saying "fetch"), but only inside the data block, whose strings hold no `(`, `:`, `/`, `=`
# or `<`, so it can never form a call, a URL or a tag.
NETWORK_NAMES = re.compile(
    r"\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts)\b",
    re.IGNORECASE,
)
DATA_BLOCK = re.compile(r'(<script type="application/json" id="topology-data">)[^<]*(</script>)')


HOSTILE = (
    "http://evil.example/x",
    "HTTPS://evil.example",
    "fetch('//evil.example')",
    "<script src=//evil.example/x.js></script>",
    "<img src=x onerror=fetch(1)>",
    "url(//evil.example/a.png)",
    "@import 'evil.example'",
    "new WebSocket('wss://evil.example')",
)


def offences(page: str) -> list[str]:
    """Name each way `page` could reach the network."""
    found = [what for what, pattern in NETWORK.items() if pattern.search(page)]
    code = DATA_BLOCK.sub(r"\1\2", page)
    if NETWORK_NAMES.search(code):
        found.append("a network API in the page's code")
    return found


@pytest.mark.parametrize(
    ("planted", "what"),
    [
        ('<a href="http://192.0.2.1/">', "a URL"),
        ("<script src=x.js></script>", "a loaded script"),
        ("fetch('/x')", "a fetch call"),
        ("new XMLHttpRequest()", "a request object"),
        ("<link rel=stylesheet href=x.css>", "a loaded resource"),
        ("background:url(x.png)", "a loaded resource"),
        ("<script>const send = navigator.sendBeacon;</script>", "a network API in the page's code"),
    ],
)
def test_the_scan_finds_a_planted_network_call(planted: str, what: str) -> None:
    assert what in offences(f"<html><body>{planted}</body></html>")


def test_a_rendered_diagram_cannot_reach_the_network(tmp_path: Path) -> None:
    devices = [
        device("dev-S1", HOSTILE[0], model=HOSTILE[1], platform=HOSTILE[2]),
        device("dev-S2", HOSTILE[3], "192.0.2.2", software_version=HOSTILE[4]),
    ]
    links = [link("link-1", "dev-S1", "Gi1/0/1", "dev-S2", "Gi1/0/2")]
    unvisited = [unvisited_device("unv-0123456789ab", HOSTILE[5], HOSTILE[6], "dev-S1")]
    data = document(devices, links, unvisited=unvisited)
    data["findings"] = [
        {
            "id": "finding-0123456789ab",
            "kind": HOSTILE[7],
            "summary": HOSTILE[0],
            "devices": ["dev-S1"],
        }
    ]
    data["adjacencies"] = [adjacency("adj-0123456789ab", "dev-S1", "dev-S2", vrf=HOSTILE[2])]
    data["subnets"] = [
        subnet("subnet-0123456789ab", HOSTILE[3], ("dev-S1", "Vlan9", HOSTILE[5]), vrf=HOSTILE[7])
    ]
    data["skipped"] = [{"device": "dev-S1", "data": "vlan_mismatch", "reason": HOSTILE[4]}]
    (tmp_path / "topology.json").write_text(json.dumps(data), encoding="utf-8")

    assert main(["render", str(tmp_path)], elevated=lambda: False) == ExitCode.CLEAN

    page = (tmp_path / "diagram.html").read_text(encoding="utf-8")
    assert offences(page) == []
    assert "dev-S2" in page  # the hostile Topology was drawn, not dropped

    drawio = (tmp_path / "diagram.drawio").read_text(encoding="utf-8")
    assert drawio_offences(drawio) == []
    assert "dev-S2" in drawio


# A draw.io shape that carries data is an `<object>`, so that tag is not a loaded resource here.
DRAWIO_RESOURCE = re.compile(
    r"<[a-z][^>]*\s(?:src|href|srcset|action|formaction|data|poster)\s*="
    r"|<link\b|<iframe\b|<embed\b|@import|url\s*\(",
    re.IGNORECASE,
)


def drawio_offences(text: str) -> list[str]:
    """Name each way a draw.io file could point outside itself.

    A draw.io file has no code, so a device description that merely says "fetch" is only
    text; what matters is a URL, a namespace, a link property or a loaded resource.
    """
    found = [
        what
        for what, pattern in NETWORK.items()
        if what != "a loaded resource" and pattern.search(text)
    ]
    if DRAWIO_RESOURCE.search(text):
        found.append("a loaded resource")
    if re.search(r"xmlns|\blink\s*=|<!doctype|<!entity", text, re.IGNORECASE):
        found.append("a namespace, link or entity")
    return found


@pytest.mark.parametrize(
    "planted",
    [
        '<mxfile xmlns="http://www.w3.org/1999/xhtml">',
        '<object label="x" link="https://evil.example/x">',
        '<mxCell value="//evil.example/x"/>',
        '<mxCell style="shape=image;image=x" src="x.png"/>',
        "<iframe>",
        '<!DOCTYPE mxfile [<!ENTITY x SYSTEM "file:///etc/passwd">]>',
    ],
)
def test_the_scan_finds_a_planted_reference_in_a_drawio_file(planted: str) -> None:
    assert drawio_offences(planted)


def report_offences(page: str) -> list[str]:
    """Name a URL or a script tag in a Run report. Relative diagram links are allowed."""
    found: list[str] = []
    if re.search(r"https?://", page, re.IGNORECASE):
        found.append("a URL")
    if re.search(r"<script", page, re.IGNORECASE):
        found.append("a script")
    return found


@pytest.mark.parametrize(
    ("planted", "what"),
    [
        ("http://evil.example/x", "a URL"),
        ("HTTPS://evil.example/x", "a URL"),
        ("<script>alert(1)</script>", "a script"),
        ("<SCRIPT src=x>", "a script"),
    ],
)
def test_the_report_scan_finds_a_planted_url_or_script(planted: str, what: str) -> None:
    assert what in report_offences(planted)


def test_a_run_report_cannot_reach_the_network(tmp_path: Path) -> None:
    folder = RunFolder(path=tmp_path, io_path=tmp_path)
    write_run_report(folder, _report(), SecretScan())

    page = (tmp_path / "run-report.html").read_text(encoding="utf-8")
    assert report_offences(page) == []
    assert 'http-equiv="Content-Security-Policy"' in page
    assert "script-src 'none'" in page
    assert "dev-S1" in page
