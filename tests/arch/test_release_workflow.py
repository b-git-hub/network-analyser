"""The release workflow is a tag-only, pinned, least-privilege release build (ticket #47).

It cannot run outside GitHub, so these static rules stand in for a run: what triggers it, what
it may touch, which actions it trusts, and that it builds by running build.ps1 itself.
"""

import re
from typing import Any, cast

import yaml

from tests.support.source_scan import REPO_ROOT

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
_FULL_SHA_PIN = re.compile(r"[\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+")


def _workflow() -> dict[Any, Any]:
    return cast("dict[Any, Any]", yaml.safe_load(WORKFLOW.read_text(encoding="utf-8")))


def _steps(job: str) -> list[dict[str, Any]]:
    return cast("list[dict[str, Any]]", _workflow()["jobs"][job]["steps"])


def unpinned_actions(text: str) -> list[str]:
    """Return each `uses:` not pinned to a full commit SHA with its version in a comment."""
    found = re.findall(r"^\s*(?:-\s+)?uses:\s*(.+?)\s*$", text, flags=re.MULTILINE)
    return [use for use in found if not _FULL_SHA_PIN.fullmatch(use)]


def expressions_in_scripts(steps: list[dict[str, Any]]) -> list[str]:
    """Name each step whose script expands a ${{ }} expression (script injection)."""
    return [str(step.get("name")) for step in steps if "${{" in str(step.get("run", ""))]


def test_only_a_v0_y_z_tag_push_triggers_it() -> None:
    workflow = _workflow()
    # PyYAML reads the bare key `on` as the boolean True (YAML 1.1).
    triggers = workflow[True]

    assert triggers == {"push": {"tags": ["v0.[0-9]+.[0-9]+"]}}
    assert sorted(path.name for path in WORKFLOW.parent.iterdir()) == ["release.yml"]


def test_the_token_is_read_only_except_where_the_release_is_published() -> None:
    workflow = _workflow()

    assert workflow["permissions"] == {}
    assert {name: job["permissions"] for name, job in workflow["jobs"].items()} == {
        "build": {"contents": "read"},
        "publish": {"contents": "write"},
    }


def test_both_jobs_run_on_windows_2025_and_publish_waits_for_the_build() -> None:
    jobs = _workflow()["jobs"]

    assert {name: job["runs-on"] for name, job in jobs.items()} == {
        "build": "windows-2025",
        "publish": "windows-2025",
    }
    assert jobs["publish"]["needs"] == "build"


def test_the_build_job_runs_build_ps1_under_windows_powershell_5_1() -> None:
    scripts = [str(step.get("run", "")) for step in _steps("build")]

    assert any(
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\build.ps1 -Python" in script
        for script in scripts
    )
    assert any("scripts.release_gate check --tag" in script for script in scripts)


def test_the_checkout_keeps_no_credentials_and_nothing_is_cached() -> None:
    steps = {step.get("uses", "").split("@")[0]: step.get("with", {}) for step in _steps("build")}

    assert steps["actions/checkout"]["persist-credentials"] is False
    assert steps["astral-sh/setup-uv"]["enable-cache"] is False
    assert "cache" not in steps["actions/setup-python"]
    assert steps["actions/setup-python"]["python-version-file"] == ".python-version"


def test_every_action_is_pinned_to_a_full_commit_sha() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    used = [step for job in ("build", "publish") for step in _steps(job) if "uses" in step]

    assert len(used) == len(re.findall(r"uses:", text)) == 5
    assert unpinned_actions(text) == []


def test_the_pin_rule_catches_a_planted_violation() -> None:
    planted = (
        "      - uses: actions/checkout@v7\n"
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
        "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
    )

    assert unpinned_actions(planted) == [
        "actions/checkout@v7",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    ]


def test_no_script_expands_an_expression() -> None:
    steps = _steps("build") + _steps("publish")

    assert expressions_in_scripts(steps) == []
    assert expressions_in_scripts([{"name": "bad", "run": "echo ${{ github.ref_name }}"}]) == [
        "bad"
    ]
