"""The strict patterns on outbound values, for the Checks that build the questions (#95).

`analysis` uses the same checks before it builds the lookup questions (ticket #104), so a value
that would be refused here is never even offered.
"""

import pytest

from network_analyser.advisories import is_safe_pid, is_safe_platform_alias, is_safe_release


@pytest.mark.parametrize(
    "value",
    [
        "C9300-48P",
        "N9K-C93180YC-FX",
        "WS-C2960X-48FPS-L",
        "C9300-NM-8X",
        "C9300-24T",
        "ISR4451-X/K9",
        "CISCO2911/K9",
        "C9300v",
        "N9K-C9300v",
        "c9300-48p",
        "C" + "9" * 40,
    ],
)
def test_a_cisco_pid_is_accepted(value: str) -> None:
    assert is_safe_pid(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "C9300 48P",
        "C9300-48P;DROP",
        "C9300-48P\r\n",
        "=C9300-48P",
        "C9300/K9/K9",
        "ISR4451-X/",
        "/K9",
        "ISR4451-X/K9/",
        "ISR4451-X%2FK9",
        "C9300%2e48P",
        "../C9300-48P",
        "C9300-48P?x=1",
        "C9300-48P#x",
        "C9300-\u096a\u096eP",
        "C9300-48P\u00e9",
        "AB",
        "CATALYST",
        "C" + "9" * 70,
    ],
)
def test_anything_else_is_refused_as_a_pid(value: str) -> None:
    assert not is_safe_pid(value)


@pytest.mark.parametrize(
    "value", ["17.9.4a", "15.2(7)E9", "9.3(10)", "7.0(3)I7(9)", "17.12.04", "10.2(5)"]
)
def test_a_normalised_release_is_accepted(value: str) -> None:
    assert is_safe_release(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "17",
        "v17.9.4",
        "17.9.4 a",
        "17.9.4<script>",
        "17.9.4/..",
        "17.9.4\r\nHost: evil",
        "17.9.4?x=1",
    ],
)
def test_anything_else_is_refused_as_a_release(value: str) -> None:
    assert not is_safe_release(value)


@pytest.mark.parametrize("value", ["NEXUS9000", "NEXUS3000", "NEXUS1000V", "NEXUS7700"])
def test_a_nexus_family_is_accepted(value: str) -> None:
    assert is_safe_platform_alias(value)


@pytest.mark.parametrize(
    "value", ["", "NEXUS", "nexus9000", "NEXUS90001", "NEXUS9000/x", "NEXUS9000\r\n"]
)
def test_anything_else_is_refused_as_a_family(value: str) -> None:
    assert not is_safe_platform_alias(value)
