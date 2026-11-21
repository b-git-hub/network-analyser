"""`Secret`: how every Credential Set password and the Backup Passphrase is held.

CLAUDE.md: passwords and the Backup Passphrase never reach disk, logs, reports, Backups,
crash dumps, test fixtures, issues or commits. A `Secret` makes the safe path the easy one:
printing, formatting, logging or putting it in a record shows "held in memory"; it cannot be
pickled or copied; it has no length; and `reveal()` is the one way to the value, so every
use is easy to find (tests/arch checks where `reveal()` may be called).

Python cannot wipe a string from memory, so a `Secret` promises only that the tool never
shows or writes the value, not that the value is erased when the Run ends. `wipe()` drops the
reference the object holds and refuses every later `reveal()`; the Run calls it at its end,
before it goes online, so the tool holds no device secret while Cisco is asked (ADR 0007).
"""

import hmac
from typing import Final, NoReturn, final, override

HELD_IN_MEMORY: Final = "held in memory"


@final
class Secret:
    """A secret string that never shows its value.

    Call `reveal()` only at the last moment, where the value is handed to the library that
    needs it (Paramiko for a login, pyrage for a lock), and never keep the result.
    """

    __slots__ = ("__value", "__wiped")

    __value: str
    __wiped: bool

    def __init__(self, value: str) -> None:
        """Hold `value`, typed at a hidden prompt."""
        self.__value: str = value
        self.__wiped = False

    @override
    def __init_subclass__(cls) -> NoReturn:
        """Refuse subclasses: one could override the methods that hide the value."""
        msg = "Secret cannot be subclassed"
        raise TypeError(msg)

    def reveal(self) -> str:
        """Return the value. The only way to it.

        Raises:
            RuntimeError: the secret was wiped, so it must never be used again.
        """
        if self.__wiped:
            msg = "this secret was wiped at the end of the Run"
            raise RuntimeError(msg)
        return self.__value

    def wipe(self) -> None:
        """Drop the value and refuse every later `reveal()`, at the Run's end (ADR 0007).

        Python cannot erase the characters of a string already made, so this releases the
        reference this object holds and makes a later use a bug. The Run calls it once every
        Backup is locked and before Cisco is asked. A wiped secret still `is_empty()`.
        """
        self.__value = ""
        self.__wiped = True

    @property
    def wiped(self) -> bool:
        """Say whether `wipe()` was called, for the Run end to prove no secret is held."""
        return self.__wiped

    def same_as(self, other: Secret) -> bool:
        """Say, in constant time, whether two secrets hold the same value (story 27)."""
        return hmac.compare_digest(self.reveal().encode(), other.reveal().encode())

    def is_empty(self) -> bool:
        """Say whether nothing was typed, so an empty password can be refused (story 24)."""
        return not self.__value

    @override
    def __repr__(self) -> str:
        return f"Secret({HELD_IN_MEMORY})"

    @override
    def __str__(self) -> str:
        return HELD_IN_MEMORY

    @override
    def __format__(self, format_spec: str) -> str:
        return format(HELD_IN_MEMORY, format_spec)

    @override
    def __eq__(self, other: object) -> NoReturn:
        """Refuse `==`: a slip such as `secret == "text"` would silently be False."""
        msg = "compare secrets with same_as(), never =="
        raise TypeError(msg)

    __hash__ = None  # type: ignore[assignment]  # unhashable on purpose

    def __bool__(self) -> NoReturn:
        """Refuse truth tests, which read like a check of the value; use is_empty()."""
        msg = "use is_empty(), not a truth test, on a Secret"
        raise TypeError(msg)

    @override
    def __reduce_ex__(self, protocol: object) -> NoReturn:
        msg = "a Secret cannot be saved, pickled or copied"
        raise TypeError(msg)
