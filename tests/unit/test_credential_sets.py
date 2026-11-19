"""Credential Sets held in memory by `credentials` (spec #37 stories 23-24, 27-28; #6, #15).

A set's password is a `Secret` from the moment it is typed: nothing a set or the Run's sets
show, format or hand out as a record ever holds it.
"""

import copy
import pickle
import threading

import pytest

from network_analyser.credentials import MAX_SETS, CredentialSet, CredentialSets, Secret
from network_analyser.records import CredentialSetResult, CredentialSetView, Platform

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


def test_the_password_is_handed_over_through_a_lease_as_a_secret_never_as_text() -> None:
    sets = CredentialSets([_set("netops-ro")])
    lease = sets.try_lease(1, failure_budget=3)
    assert lease is not None

    password = lease.password_for_login()

    assert isinstance(password, Secret)
    assert password.same_as(Secret(CANARY))


# -- Order, probation and the failure budget (ticket #54; stories 31-37) ---------------------


def _logs_in(sets: CredentialSets, number: int, *, succeeded: bool, budget: int = 3) -> bool:
    lease = sets.try_lease(number, failure_budget=budget)
    assert lease is not None
    return lease.finish(succeeded=succeeded)


def test_a_set_that_has_worked_moves_to_the_front() -> None:
    sets = CredentialSets([_set("first"), _set("second"), _set("third")])

    _logs_in(sets, 3, succeeded=True)

    assert [v.username for v in sets.login_order(None)] == ["third", "first", "second"]

    _logs_in(sets, 2, succeeded=True)

    assert [v.username for v in sets.login_order(None)] == ["second", "third", "first"]


def test_a_set_that_failed_keeps_its_place() -> None:
    sets = CredentialSets([_set("first"), _set("second")])

    _logs_in(sets, 1, succeeded=False)

    assert [v.username for v in sets.login_order(None)] == ["first", "second"]


def test_a_platform_limited_set_is_eligible_where_either_hint_points_to_its_platform() -> None:
    sets = CredentialSets([_set("xe-only", Platform.IOS_XE), _set("nx-only", Platform.NX_OS)])

    order = sets.login_order(Platform.IOS_XE, Platform.NX_OS)

    assert [v.username for v in order] == ["xe-only", "nx-only"]
    assert [v.username for v in sets.login_order(None, Platform.NX_OS)] == ["nx-only"]


def test_a_set_on_probation_has_one_login_in_flight_at_a_time() -> None:
    sets = CredentialSets([_set("netops-ro")])

    first = sets.try_lease(1, failure_budget=3)

    assert first is not None
    assert sets.try_lease(1, failure_budget=3) is None
    first.finish(succeeded=False)
    second = sets.try_lease(1, failure_budget=3)
    assert second is not None


def test_a_set_that_has_worked_leaves_probation() -> None:
    sets = CredentialSets([_set("netops-ro")])
    _logs_in(sets, 1, succeeded=True)

    leases = [sets.try_lease(1, failure_budget=3) for _ in range(3)]

    assert all(lease is not None for lease in leases)


def test_logins_in_flight_never_outrun_the_budget_left() -> None:
    sets = CredentialSets([_set("netops-ro")])
    _logs_in(sets, 1, succeeded=True)
    _logs_in(sets, 1, succeeded=False)

    held = [sets.try_lease(1, failure_budget=3) for _ in range(3)]

    assert [lease is not None for lease in held] == [True, True, False]


def test_a_lease_given_back_unused_spends_nothing() -> None:
    sets = CredentialSets([_set("netops-ro")])
    lease = sets.try_lease(1, failure_budget=1)
    assert lease is not None

    lease.release()

    assert sets.failures(1) == 0
    assert sets.try_lease(1, failure_budget=1) is not None


def test_a_lease_is_finished_once() -> None:
    sets = CredentialSets([_set("netops-ro")])
    lease = sets.try_lease(1, failure_budget=3)
    assert lease is not None
    lease.finish(succeeded=False)

    with pytest.raises(RuntimeError, match="once"):
        lease.finish(succeeded=False)
    lease.release()  # given back already: nothing happens

    assert sets.failures(1) == 1


def test_a_retired_set_is_never_leased() -> None:
    sets = CredentialSets([_set("netops-ro"), _set("svc-b")])

    retired = [_logs_in(sets, 1, succeeded=False, budget=2) for _ in range(2)]

    assert retired == [False, True]
    assert sets.try_lease(1, failure_budget=2) is None
    assert [v.username for v in sets.login_order(None)] == ["svc-b"]


@pytest.mark.parametrize("budget", [0, 6])
def test_a_failure_budget_outside_one_to_five_is_refused(budget: int) -> None:
    sets = CredentialSets([_set("netops-ro")])

    with pytest.raises(ValueError, match="1 to 5"):
        sets.try_lease(1, failure_budget=budget)


@pytest.mark.parametrize("number", [0, -1, 3])
def test_a_set_number_that_is_not_one_of_the_sets_is_refused(number: int) -> None:
    sets = CredentialSets([_set("netops-ro"), _set("svc-b")])

    with pytest.raises(ValueError, match="no Credential Set"):
        sets.try_lease(number, failure_budget=3)
    with pytest.raises(ValueError, match="no Credential Set"):
        sets.wait_for_turn(number, failure_budget=3)
    with pytest.raises(ValueError, match="no Credential Set"):
        sets.failures(number)


def test_waiting_for_a_turn_ends_when_the_login_in_flight_finishes() -> None:
    sets = CredentialSets([_set("netops-ro")])
    first = sets.try_lease(1, failure_budget=3)
    assert first is not None
    waited = threading.Event()

    def wait() -> None:
        sets.wait_for_turn(1, failure_budget=3)
        waited.set()

    waiter = threading.Thread(target=wait)
    waiter.start()
    assert not waited.wait(0.05)
    first.finish(succeeded=False)
    waiter.join(timeout=2)

    assert waited.is_set()


def test_waiting_for_a_turn_ends_when_the_set_is_retired() -> None:
    sets = CredentialSets([_set("netops-ro")])
    first = sets.try_lease(1, failure_budget=1)
    assert first is not None
    waiter = threading.Thread(target=sets.wait_for_turn, args=(1,), kwargs={"failure_budget": 1})
    waiter.start()

    assert first.finish(succeeded=False)
    waiter.join(timeout=2)

    assert not waiter.is_alive()
    assert sets.all_retired()


def test_the_results_of_each_set_are_kept_without_passwords() -> None:
    sets = CredentialSets([_set("netops-ro"), _set("svc-b", Platform.NX_OS)])
    _logs_in(sets, 1, succeeded=True)
    _logs_in(sets, 1, succeeded=True)
    _logs_in(sets, 2, succeeded=False, budget=1)

    assert sets.results() == (
        CredentialSetResult(CredentialSetView(1, "netops-ro", None), 2, 0, retired=False),
        CredentialSetResult(CredentialSetView(2, "svc-b", Platform.NX_OS), 0, 1, retired=True),
    )
    assert CANARY not in repr(sets.results())


def test_every_set_retired_is_reported() -> None:
    sets = CredentialSets([_set("netops-ro")])

    _logs_in(sets, 1, succeeded=False, budget=1)

    assert sets.all_retired()
    assert sets.login_order(None) == ()
