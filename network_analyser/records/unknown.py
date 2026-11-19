"""`Unknown`: a value the tool tried to learn and could not (CODING_STANDARDS.md, "Data").

Its own file so every record file can use it without importing another (ticket #50 moved it
here from `records/device.py`, which still re-exports it).
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Unknown:
    """A value the tool tried to learn and could not. Never read it as "none".

    Attributes:
        reason: why, as fixed text, such as `show version not understood`.
    """

    reason: str
