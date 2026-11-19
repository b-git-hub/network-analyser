"""`render RUN_FOLDER` redraws `diagram.html` in place from `topology.json` alone (#63, story 155).

No device is contacted (the suite refuses every connection), and the Run report is never
touched.
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from network_analyser.cli import ExitCode, main
from tests.support.topology_documents import device, document, link

DIAGRAM = "diagram.html"
DRAWIO = "diagram.drawio"


def _render(*argv: str) -> int:
    return main(["render", *argv], elevated=lambda: False)


@pytest.fixture
def run_folder(tmp_path: Path) -> Path:
    folder = tmp_path / "20261118T101530Z_dc1"
    folder.mkdir()
    data = document(
        [device("dev-S1", "sw-a"), device("dev-S2", "sw-b", "192.0.2.2")],
        [link("link-1", "dev-S1", "Gi1/0/1", "dev-S2", "Gi1/0/2")],
    )
    (folder / "topology.json").write_text(json.dumps(data), encoding="utf-8")
    return folder


def test_render_draws_diagram_html_beside_topology_json(
    run_folder: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _render(str(run_folder))

    assert code == ExitCode.CLEAN
    page = (run_folder / DIAGRAM).read_text(encoding="utf-8")
    assert "dev-S2" in page
    assert DIAGRAM in capsys.readouterr().out
    assert sorted(p.name for p in run_folder.iterdir()) == sorted(
        [DIAGRAM, DRAWIO, "topology.json"]
    )


def test_render_draws_diagram_drawio_beside_diagram_html(
    run_folder: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _render(str(run_folder))

    assert code == ExitCode.CLEAN
    root = ET.fromstring((run_folder / DRAWIO).read_bytes())  # noqa: S314 (our own file)
    assert [d.get("name") for d in root.findall("diagram")] == ["Physical", "Routing"]
    assert DRAWIO in capsys.readouterr().out


def test_render_redraws_diagram_drawio_in_place(run_folder: Path) -> None:
    (run_folder / DRAWIO).write_text("an older drawing", encoding="utf-8")

    assert _render(str(run_folder)) == ExitCode.CLEAN

    assert "an older drawing" not in (run_folder / DRAWIO).read_text(encoding="utf-8")
    assert "sw-b" in (run_folder / DRAWIO).read_text(encoding="utf-8")


def test_render_redraws_in_place_and_never_touches_the_run_report(run_folder: Path) -> None:
    (run_folder / DIAGRAM).write_text("an older drawing", encoding="utf-8")
    (run_folder / "run-report.html").write_text("the Run's own record", encoding="utf-8")

    code = _render(str(run_folder))

    assert code == ExitCode.CLEAN
    assert "an older drawing" not in (run_folder / DIAGRAM).read_text(encoding="utf-8")
    assert (run_folder / "run-report.html").read_text(encoding="utf-8") == "the Run's own record"


def test_a_topology_from_a_newer_version_is_refused(
    run_folder: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    topology = run_folder / "topology.json"
    data = json.loads(topology.read_text(encoding="utf-8"))
    data["format_version"] = 2
    topology.write_text(json.dumps(data), encoding="utf-8")

    code = _render(str(run_folder))

    assert code == ExitCode.REFUSED
    assert "newer version" in capsys.readouterr().err
    assert not (run_folder / DIAGRAM).exists()
    assert not (run_folder / DRAWIO).exists()


@pytest.mark.parametrize("text", ["not json", '{"format_version": 1, "devices": "x"}', "\udcff"])
def test_a_file_that_is_not_a_topology_is_refused(
    run_folder: Path, text: str, capsys: pytest.CaptureFixture[str]
) -> None:
    (run_folder / "topology.json").write_bytes(text.encode("utf-8", "surrogateescape"))

    code = _render(str(run_folder))

    assert code == ExitCode.REFUSED
    assert "refused" in capsys.readouterr().err
    assert not (run_folder / DIAGRAM).exists()
    assert not (run_folder / DRAWIO).exists()


def test_a_folder_with_no_topology_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _render(str(tmp_path))

    assert code == ExitCode.REFUSED
    assert "topology.json" in capsys.readouterr().err


def test_a_folder_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    assert _render(str(tmp_path / "missing")) == ExitCode.REFUSED


def test_a_diagram_that_cannot_be_written_needs_attention(
    run_folder: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from network_analyser import run_output  # noqa: PLC0415 (patched only here)

    def disk_full(*_args: object) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(run_output, "write_scanned_text", disk_full)

    code = _render(str(run_folder))

    assert code == ExitCode.NEEDS_ATTENTION
    assert "could not be written" in capsys.readouterr().err


def test_a_drawio_that_cannot_be_written_needs_attention(
    run_folder: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from network_analyser import run_output  # noqa: PLC0415 (patched only here)

    real = run_output.write_scanned_text

    def fails_for_drawio(folder: run_output.RunFolder, name: str, *rest: object) -> int:
        if name == DRAWIO:
            raise OSError(28, "No space left on device")
        return real(folder, name, *rest)  # type: ignore[arg-type]  # the cli's own arguments

    monkeypatch.setattr(run_output, "write_scanned_text", fails_for_drawio)

    code = _render(str(run_folder))

    assert code == ExitCode.NEEDS_ATTENTION
    assert "diagram.drawio" in capsys.readouterr().err
