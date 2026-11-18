"""`Secret`: how every Credential Set password and the Backup Passphrase is held.

CLAUDE.md: passwords and the Backup Passphrase never reach disk, logs, reports, Backups,
crash dumps, test fixtures, issues or commits. A `Secret` makes the safe path the easy one:
printing, formatting, logging or putting it in a record shows "held in memory"; it cannot be
pickled or copied; it has no length; and `reveal()` is the one way to the value, so every
use is easy to find (tests/arch checks where `reveal()` may be called).

Python cannot wipe a string from memory, so a `Secret` promises only that the tool never
shows or writes the value, not that the value is erased when the Run ends.
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

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        """Hold `value`, typed at a hidden prompt."""
        self.__value: Final = value

    @override
    def __init_subclass__(cls) -> NoReturn:
        """Refuse subclasses: one could override the methods that hide the value."""
        msg = "Secret cannot be subclassed"
        raise TypeError(msg)

    def reveal(self) -> str:
        """Return the value. The only way to it."""
        return self.__value

    def same_as(self, other: Secret) -> bool:
        """Say, in constant time, whether two secrets hold the same value (story 27)."""
        return hmac.compare_digest(self.__value.encode(), other.__value.encode())

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
