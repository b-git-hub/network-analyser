"""The CML lab's Device Role is `role-snippet` output, kept in step (#53, follow-up from #39)."""

import re

import yaml

from scripts.lab_roles import LAB_FILE, regenerate


def _node_configs() -> dict[str, str]:
    lab = yaml.safe_load(LAB_FILE.read_text(encoding="utf-8"))
    return {
        node["label"]: "\n".join(part["content"] for part in node["configuration"])
        for node in lab["nodes"]
        if node["label"].startswith(("xe-", "nx-"))
    }


def test_the_lab_file_holds_the_role_role_snippet_prints() -> None:
    text = LAB_FILE.read_text(encoding="utf-8")

    assert regenerate(text) == text, "run: uv run --locked python -m scripts.lab_roles"


def test_every_lab_node_gives_the_tool_account_the_generated_role() -> None:
    configs = _node_configs()

    assert len(configs) == 5
    for label, config in configs.items():
        if label.startswith("xe-"):
            assert " commands exec include show privilege\n" in config, label
            assert "username netanalyser view NA-READ algorithm-type scrypt" in config, label
            assert "show parser view" not in config, label  # not on the allow-list
        else:
            assert re.search(r"  rule \d+ permit command show user-account netanalyser\n", config)
            assert "username netanalyser password CHANGE_ME role NA-READ\n" in config, label
            assert "no username netanalyser role network-operator\n" in config, label
        assert "PROVISIONAL" not in config, label


def test_regenerating_replaces_a_hand_written_role_and_keeps_the_rest() -> None:
    stale = (
        "    hostname sw-a\n"
        "    parser view NA-READ\n"
        "     secret CHANGE_ME\n"
        "     commands exec include show parser view\n"
        "    !\n"
        "    role name NA-READ\n"
        "      description old\n"
        "      rule 1 permit command show tech-support\n"
        "    username netanalyser password CHANGE_ME role NA-READ\n"
    )

    fresh = regenerate(stale)

    assert fresh.startswith("    hostname sw-a\n    parser view NA-READ\n     secret CHANGE_ME\n")
    assert "show parser view" not in fresh
    assert "show tech-support" not in fresh
    assert "     commands exec include show version\n" in fresh
    assert "\n    !\n    role name NA-READ\n      description Network Analyser" in fresh
    assert "      rule 1 permit command terminal length 0\n" in fresh
    assert " permit command show user-account netanalyser\n" in fresh
    assert fresh.endswith("\n    username netanalyser password CHANGE_ME role NA-READ\n")
