"""The Credential Sets of one Run, held in memory only (spec #37 stories 23-24, 27-28).

Decided on #6 and #15: up to five sets, typed at Run start, tried in the order given, each
optionally limited to one Platform. A set's password is a `Secret` and stays inside this
module (and, at the login itself, `device_gateway`); what the rest of the tool sees is a
`CredentialSetView` record, which holds no password and not even its length.
"""

import threading
from collections.abc import Sequence
from typing import Final, NoReturn, final, override

from network_analyser.credentials.scan import SecretScan
from network_analyser.credentials.secret import HELD_IN_MEMORY, Secret
from network_analyser.records import CredentialSetView, Platform

MAX_SETS: Final = 5


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
class CredentialSets:
    """The Run's Credential Sets, one to five, in the order the operator gave them."""

    __slots__ = ("__failures", "__lock", "__retired", "__sets")

    def __init__(self, sets: Sequence[CredentialSet]) -> None:
        """Hold the sets typed at Run start.

        Raises:
            ValueError: there are none, or more than MAX_SETS.
        """
        if not 1 <= len(sets) <= MAX_SETS:
            msg = f"a Run takes 1 to {MAX_SETS} Credential Sets"
            raise ValueError(msg)
        self.__sets: Final = tuple(sets)
        self.__lock: Final = threading.Lock()
        self.__failures: Final = [0] * len(self.__sets)
        self.__retired: Final = [False] * len(self.__sets)

    def views(self) -> tuple[CredentialSetView, ...]:
        """Return what may be shown of each set, in order (story 28): never a password."""
        return tuple(
            CredentialSetView(number=n, username=s.username, platform_limit=s.platform_limit)
            for n, s in enumerate(self.__sets, start=1)
        )

    def login_order(self, hint: Platform | None) -> tuple[CredentialSetView, ...]:
        """Return the sets to try on a device, in order, leaving out Retired Credential Sets.

        A set limited to one Platform is tried only where the SSH identification string
        points to that Platform (story 32). `hint` is that Platform, or None for no hint.
        """
        with self.__lock:
            retired = tuple(self.__retired)
        return tuple(
            view
            for view, is_retired in zip(self.views(), retired, strict=True)
            if not is_retired and view.platform_limit in {None, hint}
        )

    def password_for_login(self, number: int) -> Secret:
        """Hand set `number`'s password to `device_gateway` for one login, as a `Secret`.

        Only `credentials` and `device_gateway` may call this (tests/arch/test_secret_rules).
        """
        return self.__sets[number - 1].password_for_login()

    def record_login(self, number: int, *, succeeded: bool, failure_budget: int) -> bool:
        """Count one login by set `number`; return True when this failure retired it.

        A set that has failed `failure_budget` times this Run is retired (story 34).
        """
        if succeeded:
            return False
        with self.__lock:
            self.__failures[number - 1] += 1
            spent = self.__failures[number - 1] >= failure_budget
            newly = spent and not self.__retired[number - 1]
            self.__retired[number - 1] = self.__retired[number - 1] or spent
        return newly

    def failures(self, number: int) -> int:
        """Return how many failed logins set `number` has spent this Run."""
        with self.__lock:
            return self.__failures[number - 1]

    def all_retired(self) -> bool:
        """Say whether every set is a Retired Credential Set (story 37)."""
        with self.__lock:
            return all(self.__retired)

    def password_same_as(self, secret: Secret) -> bool:
        """Say whether any set's password is `secret`, without saying which."""
        return any(s.password_same_as(secret) for s in self.__sets)

    def add_to_scan(self, scan: SecretScan) -> None:
        """Have the secret scan look for every set's password in everything written (#30)."""
        for credential_set in self.__sets:
            credential_set.add_to_scan(scan)

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
