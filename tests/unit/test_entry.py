"""`python -m network_analyser` is how the operator (and the frozen exe) starts the tool."""

import subprocess
import sys

from tests.support.source_scan import REPO_ROOT


def test_python_m_network_analyser_prints_the_version_and_exits_0() -> None:
    result = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-m", "network_analyser", "--version"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )

    assert result.returncode == 0
    assert result.stdout.startswith("network-analyser 0.")


def test_a_command_not_built_yet_exits_4_from_the_real_entry_point() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "network_analyser", "render", "runs/x"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )

    assert result.returncode == 4
    assert "network-analyser render: not built yet" in result.stderr
