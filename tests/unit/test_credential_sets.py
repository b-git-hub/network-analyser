"""Credential Sets held in memory by `credentials` (spec #37 stories 23-24, 27-28; #6, #15).

A set's password is a `Secret` from the moment it is typed: nothing a set or the Run's sets
show, format or hand out as a record ever holds it.
"""

import copy
import pickle

import pytest

from network_analyser.credentials import MAX_SETS, CredentialSet, CredentialSets, Secret
from network_analyser.records import CredentialSetView, Platform

CANARY = "CANARY-pw-5b2e"


def _set(username: str = "netops-ro", platform_limit: Platform | None = None) -> CredentialSet:
    return CredentialSet(username, Secret(CANARY), platform_limit)


def test_a_set_never_shows_its_password() -> None:
    one = _set(platform_limit=Platform.NX_OS)
    sets = CredentialSets([one])

    shown = [repr(one), str(one), f"{one}", repr(sets), str(sets), f"{sets!r}"]

    assert all(CANARY not in text for text in shown)
    assert "netops-ro" in repr(one)
    assert "held in memory" in repr(one)


def test_the_sets_are_shown_as_records_in_the_order_given_without_passwords() -> None:
    sets = CredentialSets([_set("netops-ro", Platform.IOS_XE), _set("svc-nexus")])

    assert sets.views() == (
        CredentialSetView(number=1, username="netops-ro", platform_limit=Platform.IOS_XE),
        CredentialSetView(number=2, username="svc-nexus", platform_limit=None),
    )
    assert CANARY not in repr(sets.views())


def test_an_empty_password_is_refused() -> None:
    with pytest.raises(ValueError, match="needs a password"):
        CredentialSet("netops-ro", Secret(""), None)


def test_an_empty_username_is_refused() -> None:
    with pytest.raises(ValueError, match="needs a username"):
        CredentialSet("  ", Secret(CANARY), None)


def test_a_run_takes_one_to_five_sets() -> None:
    with pytest.raises(ValueError, match="1 to 5"):
        CredentialSets([])
    with pytest.raises(ValueError, match="1 to 5"):
        CredentialSets([_set(f"user{n}") for n in range(MAX_SETS + 1)])

    assert len(CredentialSets([_set(f"user{n}") for n in range(MAX_SETS)])) == MAX_SETS


def test_the_sets_say_whether_any_password_is_a_given_secret() -> None:
    sets = CredentialSets([CredentialSet("a", Secret("one"), None), _set("b")])

    assert sets.password_same_as(Secret(CANARY))
    assert not sets.password_same_as(Secret("CANARY-pp-different"))


def test_a_set_cannot_be_pickled_or_deep_copied() -> None:
    one = _set()

    with pytest.raises(TypeError):
        pickle.dumps(one)
    with pytest.raises(TypeError):
        copy.deepcopy(CredentialSets([one]))


# -- Trying sets at a login (ticket #49; the full rules of story 31-37 are #54) ------------------


def test_sets_are_tried_in_order_and_a_platform_limit_needs_a_matching_hint() -> None:
    sets = CredentialSets(
        [_set("any-a"), _set("xe-only", Platform.IOS_XE), _set("nx-only", Platform.NX_OS)]
    )

    assert [v.username for v in sets.login_order(Platform.IOS_XE)] == ["any-a", "xe-only"]
    assert [v.username for v in sets.login_order(Platform.NX_OS)] == ["any-a", "nx-only"]
    assert [v.username for v in sets.login_order(None)] == ["any-a"]


def test_the_password_is_handed_over_as_a_secret_never_as_text() -> None:
    sets = CredentialSets([_set("netops-ro")])

    password = sets.password_for_login(1)

    assert isinstance(password, Secret)
    assert password.same_as(Secret(CANARY))


def test_a_set_is_retired_once_it_spends_its_failure_budget() -> None:
    sets = CredentialSets([_set("netops-ro"), _set("svc-b")])

    spent = [sets.record_login(1, succeeded=False, failure_budget=2) for _ in range(2)]

    assert spent == [False, True]
    assert [v.username for v in sets.login_order(None)] == ["svc-b"]
    assert not sets.all_retired()
    assert sets.failures(1) == 2


def test_a_successful_login_spends_nothing() -> None:
    sets = CredentialSets([_set("netops-ro")])

    retired = sets.record_login(1, succeeded=True, failure_budget=1)

    assert not retired
    assert [v.username for v in sets.login_order(None)] == ["netops-ro"]


def test_every_set_retired_is_reported() -> None:
    sets = CredentialSets([_set("netops-ro")])

    sets.record_login(1, succeeded=False, failure_budget=1)

    assert sets.all_retired()
    assert sets.login_order(None) == ()
