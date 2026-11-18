"""A Secret never shows its value, however it is printed, formatted or saved.

The full security test 5 ("canary no-secrets", spec #37) lands with later tickets; this
proves the type that every password and the Backup Passphrase are held in.
"""

import copy
import logging
import pickle
from collections.abc import Callable
from dataclasses import dataclass

import pytest

from network_analyser.credentials import Secret

CANARY = "CANARY-pw-93ad"


@dataclass(frozen=True)
class _LoginRecord:
    username: str
    password: Secret


@pytest.mark.parametrize(
    "render",
    [
        pytest.param(str, id="str"),
        pytest.param(repr, id="repr"),
        pytest.param(lambda s: f"{s}", id="f-string"),
        pytest.param(lambda s: f"{s!r}", id="f-string !r"),
        pytest.param(lambda s: f"{s:>40}", id="format spec"),
        pytest.param("{}".format, id="str.format"),
        pytest.param(lambda s: "%s %r" % (s, s), id="percent"),  # noqa: UP031
        pytest.param(lambda s: repr(_LoginRecord("operator", s)), id="inside a dataclass"),
        pytest.param(lambda s: str([s, {"k": s}]), id="inside containers"),
        pytest.param(ascii, id="ascii"),
    ],
)
def test_no_rendering_reveals_the_value(render: Callable[[Secret], str]) -> None:
    text = render(Secret(CANARY))

    assert CANARY not in text
    assert "held in memory" in text


def test_logging_a_secret_does_not_reveal_it(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO):
        logging.getLogger("test").info("login with %s", Secret(CANARY))

    assert CANARY not in caplog.text


@pytest.mark.parametrize(
    "save",
    [
        pytest.param(pickle.dumps, id="pickle"),
        pytest.param(copy.copy, id="copy"),
        pytest.param(copy.deepcopy, id="deepcopy"),
    ],
)
def test_a_secret_cannot_be_pickled_or_copied(save: Callable[[Secret], object]) -> None:
    with pytest.raises(TypeError, match="cannot be saved"):
        save(Secret(CANARY))


def test_reveal_is_the_one_way_to_the_value() -> None:
    assert Secret(CANARY).reveal() == CANARY


def test_same_as_catches_a_password_reused_as_the_passphrase() -> None:
    assert Secret(CANARY).same_as(Secret(CANARY))
    assert not Secret(CANARY).same_as(Secret(CANARY + "x"))


def test_equality_is_refused_so_a_slip_cannot_silently_compare_false() -> None:
    with pytest.raises(TypeError, match="same_as"):
        _ = Secret(CANARY) == CANARY


def test_a_truth_test_is_refused_and_is_empty_says_whether_anything_was_typed() -> None:
    assert Secret("").is_empty()
    assert not Secret(CANARY).is_empty()
    with pytest.raises(TypeError, match="is_empty"):
        bool(Secret(CANARY))


def test_a_secret_has_no_length() -> None:
    with pytest.raises(TypeError):
        len(Secret(CANARY))  # type: ignore[arg-type]


def test_a_secret_is_not_hashable_so_it_cannot_become_a_dict_key_by_accident() -> None:
    with pytest.raises(TypeError):
        hash(Secret(CANARY))


def test_a_secret_cannot_be_subclassed_to_undo_the_hiding() -> None:
    with pytest.raises(TypeError, match="subclassed"):
        type("Leaky", (Secret,), {})
