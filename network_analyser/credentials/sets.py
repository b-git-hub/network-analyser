"""The Credential Sets of one Run, held in memory only, and how they are tried (#45, #54).

Decided on #6 and #15: up to five sets, typed at Run start, each optionally limited to one
Platform. A set's password is a `Secret` and stays inside this module (and, at the login
itself, `device_gateway`); what the rest of the tool sees is a `CredentialSetView` record,
which holds no password and not even its length.

How sets are tried, so that a mistyped password can't trip AAA lockout (spec #37 stories
31-37):

- In the order given, except that a set that has worked moves to the front; the set that
  worked most recently comes first (story 31). A Platform-limited set is eligible only where
  a hint points to its Platform (story 32).
- Every login takes a `LoginLease`, the only way to the password. The lease is what makes
  probation and the failure budget hold across the pool of workers:
  - until a set has worked once, it is on probation: one login with it in flight at a time
    (story 35);
  - after that, no more logins are in flight with it than its failure budget has left, so
    logins that all fail at once can never spend more than the budget (the secure reading
    of story 34);
  - a set whose failed logins reach the budget becomes a Retired Credential Set and is
    never leased again (story 34).
- Whether a set is tried at most once per device is the visit's to keep (story 33).
"""

import functools
import threading
from collections.abc import Callable, Sequence
from types import TracebackType
from typing import Final, NoReturn, Self, final, override

from network_analyser.credentials.scan import SecretScan
from network_analyser.credentials.secret import HELD_IN_MEMORY, Secret
from network_analyser.records import CredentialSetResult, CredentialSetView, Platform

MAX_SETS: Final = 5
MAX_FAILURE_BUDGET: Final = 5
"""The failure budget is 3 by default; the operator may lower it, never raise it above 5."""


@final
class CredentialSet:
    """One username and password the operator typed for this Run, and its Platform limit."""

    __slots__ = ("__password", "platform_limit", "username")

    def __init__(self, username: str, password: Secret, platform_limit: Platform | None) -> None:
        """Hold a set typed at the prompt.

        Raises:
            ValueError: the username is blank or the password is empty (story 24).
        """
        if not username.strip():
            msg = "a Credential Set needs a username"
            raise ValueError(msg)
        if password.is_empty():
            msg = "a Credential Set needs a password"
            raise ValueError(msg)
        self.username: Final = username
        self.platform_limit: Final = platform_limit
        self.__password: Final = password

    def password_same_as(self, secret: Secret) -> bool:
        """Say, in constant time, whether this set's password is `secret` (story 27)."""
        return self.__password.same_as(secret)

    def add_to_scan(self, scan: SecretScan) -> None:
        """Have the secret scan look for this set's password in everything written."""
        scan.watch(self.__password)

    def password_for_login(self) -> Secret:
        """Hand the password to `device_gateway` for one login, still a `Secret`.

        Only `credentials` and `device_gateway` may call this (tests/arch/test_secret_rules).
        """
        return self.__password

    def wipe(self) -> None:
        """Wipe this set's password at the Run's end, before Cisco is asked (ADR 0007)."""
        self.__password.wipe()

    @property
    def wiped(self) -> bool:
        """Say whether this set's password was wiped."""
        return self.__password.wiped

    @override
    def __init_subclass__(cls) -> NoReturn:
        """Refuse subclasses: one could add a way to the password."""
        msg = "CredentialSet cannot be subclassed"
        raise TypeError(msg)

    @override
    def __repr__(self) -> str:
        limit = self.platform_limit.value if self.platform_limit else "any Platform"
        return f"CredentialSet({self.username!r}, {limit}, password {HELD_IN_MEMORY})"

    @override
    def __reduce_ex__(self, protocol: object) -> NoReturn:
        msg = "a Credential Set cannot be saved, pickled or copied"
        raise TypeError(msg)


@final
class LoginLease:
    """One login with one Credential Set, in flight: the only way to its password.

    Finish it once with what came of the login, or give it back unused with `release` (or by
    leaving its `with` block): a lease given back spends nothing.
    """

    __slots__ = ("__done", "__end", "__set", "view")

    def __init__(
        self,
        view: CredentialSetView,
        credential_set: CredentialSet,
        end: Callable[[bool | None], bool],
    ) -> None:
        """Lease `credential_set` for one login; `end` counts what came of it."""
        self.view: Final = view
        self.__set: Final = credential_set
        self.__end: Final = end
        self.__done = False

    def password_for_login(self) -> Secret:
        """Hand the set's password to `device_gateway` for this login, still a `Secret`.

        Only `credentials` and `device_gateway` may call this (tests/arch/test_read_only).

        Raises:
            RuntimeError: the lease is finished or given back.
        """
        if self.__done:
            msg = "a lease's password is handed over only while the lease is held"
            raise RuntimeError(msg)
        return self.__set.password_for_login()

    def finish(self, *, succeeded: bool) -> bool:
        """Count what came of the login; return True when this failure retired the set.

        Raises:
            RuntimeError: the lease was already finished or given back.
        """
        if self.__done:
            msg = "a lease is finished once"
            raise RuntimeError(msg)
        self.__done = True
        return self.__end(succeeded)

    def release(self) -> None:
        """Give the lease back unused, if it is still held: it spends nothing."""
        if not self.__done:
            self.__done = True
            self.__end(None)

    def __enter__(self) -> Self:
        """Hold the lease for the block."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Give the lease back if the block did not finish it."""
        self.release()

    @override
    def __init_subclass__(cls) -> NoReturn:
        """Refuse subclasses: one could add a way to the password."""
        msg = "LoginLease cannot be subclassed"
        raise TypeError(msg)

    @override
    def __repr__(self) -> str:
        return f"LoginLease(set {self.view.number}, password {HELD_IN_MEMORY})"

    @override
    def __reduce_ex__(self, protocol: object) -> NoReturn:
        msg = "a login lease cannot be saved, pickled or copied"
        raise TypeError(msg)


@final
class CredentialSets:
    """The Run's Credential Sets, one to five, and how each has fared. Safe across threads."""

    __slots__ = (
        "__failures",
        "__in_flight",
        "__retired",
        "__sets",
        "__successes",
        "__turns",
        "__worked",
        "__worked_count",
    )

    def __init__(self, sets: Sequence[CredentialSet]) -> None:
        """Hold the sets typed at Run start.

        Raises:
            ValueError: there are none, or more than MAX_SETS.
        """
        if not 1 <= len(sets) <= MAX_SETS:
            msg = f"a Run takes 1 to {MAX_SETS} Credential Sets"
            raise ValueError(msg)
        count = len(sets)
        self.__sets: Final = tuple(sets)
        self.__turns: Final = threading.Condition()
        self.__failures: Final = [0] * count
        self.__successes: Final = [0] * count
        self.__in_flight: Final = [0] * count
        self.__retired: Final = [False] * count
        self.__worked: Final = [0] * count
        """When each set last worked, as a count of logins that worked; 0 for never."""
        self.__worked_count = 0

    def views(self) -> tuple[CredentialSetView, ...]:
        """Return what may be shown of each set, in order (story 28): never a password."""
        return tuple(
            CredentialSetView(number=n, username=s.username, platform_limit=s.platform_limit)
            for n, s in enumerate(self.__sets, start=1)
        )

    def login_order(self, *hints: Platform | None) -> tuple[CredentialSetView, ...]:
        """Return the sets to try on a device, in order, leaving out Retired Credential Sets.

        Sets that have worked come first, the most recent first; the rest keep the order the
        operator gave (story 31). A set limited to one Platform is eligible only where one
        of `hints` (the SSH identification string's, the Neighbour's) is that Platform
        (story 32).
        """
        with self.__turns:
            retired = tuple(self.__retired)
            worked = tuple(self.__worked)
        eligible = [
            view
            for view, is_retired in zip(self.views(), retired, strict=True)
            if not is_retired and (view.platform_limit is None or view.platform_limit in hints)
        ]
        return tuple(sorted(eligible, key=lambda view: -worked[view.number - 1]))

    def try_lease(self, number: int, *, failure_budget: int) -> LoginLease | None:
        """Lease set `number` for one login now, or return None if it may not log in now.

        None means the set is retired, or it is on probation with a login in flight, or
        its logins in flight already match the failure budget it has left.

        Raises:
            ValueError: there is no set `number`, or `failure_budget` is not 1 to 5.
        """
        index = self.__index(number)
        _check_budget(failure_budget)
        with self.__turns:
            if not self.__has_turn(index, failure_budget):
                return None
            self.__in_flight[index] += 1
        view = self.views()[index]
        end = functools.partial(self.__end_login, index, failure_budget)
        return LoginLease(view, self.__sets[index], end)

    def wait_for_turn(self, number: int, *, failure_budget: int) -> None:
        """Wait until set `number` could be leased, or is retired.

        Another worker may take the turn first, so `try_lease` can still return None. Never
        call it while holding an SSH connection open: the wait has no end but other logins.

        Raises:
            ValueError: there is no set `number`, or `failure_budget` is not 1 to 5.
        """
        index = self.__index(number)
        _check_budget(failure_budget)
        with self.__turns:
            self.__turns.wait_for(
                lambda: self.__retired[index] or self.__has_turn(index, failure_budget)
            )

    def failures(self, number: int) -> int:
        """Return how many failed logins set `number` has spent this Run.

        Raises:
            ValueError: there is no set `number`.
        """
        index = self.__index(number)
        with self.__turns:
            return self.__failures[index]

    def all_retired(self) -> bool:
        """Say whether every set is a Retired Credential Set (story 37)."""
        with self.__turns:
            return all(self.__retired)

    def results(self) -> tuple[CredentialSetResult, ...]:
        """Return how each set has fared this Run, in order: never a password."""
        with self.__turns:
            counts = tuple(zip(self.__successes, self.__failures, self.__retired, strict=True))
        return tuple(
            CredentialSetResult(view, successes, failures, retired=retired)
            for view, (successes, failures, retired) in zip(self.views(), counts, strict=True)
        )

    def password_same_as(self, secret: Secret) -> bool:
        """Say whether any set's password is `secret`, without saying which."""
        return any(s.password_same_as(secret) for s in self.__sets)

    def add_to_scan(self, scan: SecretScan) -> None:
        """Have the secret scan look for every set's password in everything written (#30)."""
        for credential_set in self.__sets:
            credential_set.add_to_scan(scan)

    def wipe(self) -> None:
        """Wipe every set's password at the Run's end, before Cisco is asked (ADR 0007).

        A wiped password has no value left for `reveal()`; the secret scan keeps its own copy
        until `forget()`, so the Run's outputs are still redacted.
        """
        for credential_set in self.__sets:
            credential_set.wipe()

    @property
    def wiped(self) -> bool:
        """Say whether every set's password was wiped, for the Run end to prove it."""
        return all(credential_set.wiped for credential_set in self.__sets)

    def __index(self, number: int) -> int:
        """Return set `number`'s index; a number from outside (0, -1) must not wrap round."""
        if not 1 <= number <= len(self.__sets):
            msg = f"there is no Credential Set {number}"
            raise ValueError(msg)
        return number - 1

    def __has_turn(self, index: int, failure_budget: int) -> bool:
        """Say whether set `index` may start a login now. Call holding the lock."""
        if self.__retired[index]:
            return False
        if not self.__successes[index]:
            return self.__in_flight[index] == 0  # probation (story 35)
        return self.__failures[index] + self.__in_flight[index] < failure_budget

    def __end_login(self, index: int, failure_budget: int, succeeded: bool | None) -> bool:  # noqa: FBT001 (a partial's last argument)
        """Count a leased login; None gives it back unused. True when it retired the set."""
        with self.__turns:
            self.__in_flight[index] -= 1
            newly_retired = False
            if succeeded is True:
                self.__successes[index] += 1
                self.__worked_count += 1
                self.__worked[index] = self.__worked_count
            elif succeeded is False:
                self.__failures[index] += 1
                spent = self.__failures[index] >= failure_budget
                newly_retired = spent and not self.__retired[index]
                self.__retired[index] = self.__retired[index] or spent
            self.__turns.notify_all()
        return newly_retired

    def __len__(self) -> int:
        """Return how many sets there are."""
        return len(self.__sets)

    @override
    def __init_subclass__(cls) -> NoReturn:
        """Refuse subclasses: one could add a way to the passwords."""
        msg = "CredentialSets cannot be subclassed"
        raise TypeError(msg)

    @override
    def __repr__(self) -> str:
        return f"CredentialSets({len(self.__sets)} sets, passwords {HELD_IN_MEMORY})"

    @override
    def __reduce_ex__(self, protocol: object) -> NoReturn:
        msg = "Credential Sets cannot be saved, pickled or copied"
        raise TypeError(msg)


def _check_budget(failure_budget: int) -> None:
    if not 1 <= failure_budget <= MAX_FAILURE_BUDGET:
        msg = f"a failure budget is 1 to {MAX_FAILURE_BUDGET} failed logins"
        raise ValueError(msg)
